# Copyright 2026 NeoAxios LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Build configuration loader.

Reads build.yaml from the repository root to centralize directory layout,
Docker scan paths, validation scopes, and contract globs. All build tools,
validation scripts, and Makefiles consume this config instead of hardcoding
paths.

build.yaml is required. If absent, load_build_config raises FileNotFoundError.
This is intentional — the file IS the portability mechanism. A repo that
wants to use neoaxios-build creates its own build.yaml declaring its own
directory structure.

Required sections: package_roots (with path + layout per entry).
Optional sections: docker_scan_paths, validation (omitted = all validators
scan all roots), contracts (with root, providers_pattern, consumers_pattern
— omitted when the consumer neither publishes nor consumes contracts),
contracts.consumers_exclude (omitted = no exclusions).
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


@dataclass(frozen=True)
class PackageRoot:
    """A directory containing buildable Python packages.

    Attributes:
        path: Directory path relative to repo root (e.g., "packages")
        layout: How packages are organized within this root:
            "nested" — root/category/package/ (e.g., packages/foundation/logging)
            "flat"   — root/package/          (e.g., apps/my_app)
    """
    path: str
    layout: str  # "nested" | "flat"

    def __post_init__(self):
        if self.layout not in ("nested", "flat"):
            raise ValueError(
                f"Invalid layout {self.layout!r} for {self.path!r}. "
                f"Must be 'nested' or 'flat'."
            )


@dataclass(frozen=True)
class ContractsConfig:
    """Contract discovery configuration.

    Attributes:
        root: Package root that contains contracts (e.g., "packages")
        providers_pattern: Glob pattern for provider manifests, relative to root
        consumers_pattern: Glob pattern for consumer contracts, relative to root
        consumers_exclude: Glob patterns to exclude from consumer discovery
    """
    root: str
    providers_pattern: str
    consumers_pattern: str
    consumers_exclude: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class BuildConfig:
    """Repository build configuration loaded from build.yaml.

    Attributes:
        package_roots: Directories containing buildable packages
        docker_scan_paths: Glob patterns for Dockerfile discovery. Empty
            list when the project builds no Docker images of its own.
        required_images: Base images this project consumes from the
            shared Docker image cache (published by another project's
            ``make build``).  Each entry is a full image reference
            matching the Dockerfile ``FROM`` line (e.g.
            ``neoaxios/base:latest``).  Resolved and loaded into the
            local daemon before this project's own Docker build runs.

            ``None`` means the section was omitted from build.yaml — the
            consumer is on the legacy auto-discovery path.  An empty list
            means the consumer explicitly opted into the ownership model
            and depends on zero cross-repo base images (only Docker Hub
            or repo-local FROMs).  A non-empty list is the standard
            opt-in with real dependencies.  The empty-vs-missing
            distinction is the signal ``build_docker_images`` uses to
            decide whether to suppress the deprecated built-in auto-
            discovery sweep.
        validation: Mapping of validator name to list of root paths it scans
        contracts: Contract discovery configuration.  ``None`` when the
            consumer neither publishes nor consumes contracts.
        layer1_profile: Name of the Layer-1 dependency profile this consumer
            uses for ``neo worktree init``.  Resolves to
            ``neo-packages/dev-env-setup/profiles/<name>.list``.
            Defaults to ``"default"`` (every consumer's standard profile).
            Named profiles exist for consumers that legitimately need a
            different Layer-1 set (e.g. a profile for a consumer with
            non-standard dependencies).  Set in build.yaml as
            ``layer1_profile: <name>``.
        cache_namespace: Optional cache-isolation namespace.  When set,
            this project's wheel and Docker-image caches resolve to a
            dedicated subdirectory of the shared cache hierarchy
            instead of the collision-prone shared root, so artifacts
            published from this project cannot overwrite (or be
            overwritten by) artifacts from other projects sharing the
            cache.  ``None`` (default) keeps the shared-root behavior.
            Set in build.yaml as ``cache: { namespace: <name> }``.
    """
    package_roots: List[PackageRoot]
    docker_scan_paths: List[str]
    validation: Dict[str, List[str]]
    contracts: Optional[ContractsConfig] = None
    required_images: Optional[List[str]] = None
    layer1_profile: str = "default"
    cache_namespace: Optional[str] = None

    def roots_for_validator(self, validator_name: str) -> List[PackageRoot]:
        """Get package roots a specific validator should scan.

        Args:
            validator_name: Validator key (e.g., "telemetry", "license")

        Returns:
            List of PackageRoot objects. Falls back to all roots if the
            validator is not explicitly configured.
        """
        root_paths = self.validation.get(validator_name)
        if root_paths is None:
            return list(self.package_roots)
        by_path = {r.path: r for r in self.package_roots}
        return [by_path[p] for p in root_paths if p in by_path]

    @property
    def all_root_paths(self) -> List[str]:
        """All package root paths as strings."""
        return [r.path for r in self.package_roots]


def load_build_config(repo_root: Path) -> BuildConfig:
    """Load build configuration from build.yaml.

    build.yaml is the single source of truth for directory layout.
    Every section is required — no silent defaults.

    Args:
        repo_root: Repository root directory containing build.yaml

    Returns:
        BuildConfig parsed from build.yaml

    Raises:
        FileNotFoundError: If build.yaml does not exist at repo_root
        ValueError: If build.yaml is empty or missing required sections
    """
    config_path = repo_root / "build.yaml"
    if not config_path.is_file():
        raise FileNotFoundError(
            f"build.yaml not found at {config_path}. "
            f"This file is required — it declares package roots, Docker "
            f"scan paths, validation scopes, and contract globs. "
            f"See neo-packages/neoaxios-build/README.md for the schema."
        )

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)

    if not raw:
        raise ValueError(f"build.yaml at {config_path} is empty")

    # Parse package_roots (required)
    if "package_roots" not in raw or not raw["package_roots"]:
        raise ValueError("build.yaml missing required 'package_roots' section")

    package_roots = []
    for entry in raw["package_roots"]:
        if "path" not in entry:
            raise ValueError(
                f"Each package_roots entry requires a 'path' key, got: {entry}"
            )
        if "layout" not in entry:
            raise ValueError(
                f"Each package_roots entry requires a 'layout' key "
                f"('nested' or 'flat'), got: {entry}"
            )
        package_roots.append(PackageRoot(
            path=entry["path"],
            layout=entry["layout"],
        ))

    # Parse docker_scan_paths. Optional: a consumer with no Dockerfiles of
    # its own can omit the section entirely. Base images owned by another
    # repo (e.g. this codebase's ``neoaxios/base``) are NOT discovered here — they
    # are resolved from the shared image cache via ``required_images``.
    docker_scan_paths = raw.get("docker_scan_paths") or []

    # Parse required_images. Three distinct states:
    #   * key absent from build.yaml  → None (legacy consumer, auto-discovery on)
    #   * key present with empty list → [] (opted in, no cross-repo deps)
    #   * key present with entries    → [...] (opted in, real deps)
    # The empty-vs-missing distinction is intentional — a consumer like IP
    # whose Dockerfiles only FROM Docker Hub images needs a way to opt OUT
    # of auto-discovery without having to declare a bogus image dependency.
    required_images: Optional[List[str]]
    if "required_images" in raw:
        required_images_raw = raw.get("required_images")
        # YAML `required_images:` with no value parses as None; treat that
        # as an explicit empty declaration (matches YAML convention where
        # an empty mapping/list is indistinguishable from absent value).
        if required_images_raw is None:
            required_images_raw = []
        if not isinstance(required_images_raw, list):
            raise ValueError(
                f"build.yaml 'required_images' must be a list of image references, "
                f"got: {type(required_images_raw).__name__}"
            )
        required_images = []
        for entry in required_images_raw:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(
                    f"build.yaml 'required_images' entries must be non-empty strings, "
                    f"got: {entry!r}"
                )
            required_images.append(entry.strip())
    else:
        required_images = None

    # Parse validation (optional section — when omitted, all validators scan
    # all package_roots.  This is documented behavior, not a silent default.)
    validation = raw.get("validation", {})

    # Parse contracts. Optional: consumers that neither publish nor consume
    # contracts can omit the section. When present, all three required keys
    # must be set. Consumers that opt in but have no exclusions can still
    # omit consumers_exclude.
    contracts_raw = raw.get("contracts")
    contracts: Optional[ContractsConfig] = None
    if contracts_raw is not None:
        if "root" not in contracts_raw:
            raise ValueError(
                "build.yaml contracts section missing required 'root' key"
            )
        for key in ("providers_pattern", "consumers_pattern"):
            if key not in contracts_raw:
                raise ValueError(
                    f"build.yaml contracts section missing required '{key}' key"
                )
        contracts = ContractsConfig(
            root=contracts_raw["root"],
            providers_pattern=contracts_raw["providers_pattern"],
            consumers_pattern=contracts_raw["consumers_pattern"],
            # consumers_exclude is optional — empty list means no exclusions
            consumers_exclude=contracts_raw.get("consumers_exclude", []),
        )

    # Parse layer1_profile (optional). String name selecting which
    # profiles/<name>.list worktree-init.sh installs as Layer-1.
    layer1_profile_raw = raw.get("layer1_profile", "default")
    if not isinstance(layer1_profile_raw, str) or not layer1_profile_raw.strip():
        raise ValueError(
            f"build.yaml 'layer1_profile' must be a non-empty string, "
            f"got: {layer1_profile_raw!r}"
        )
    # Disallow path separators / parent traversal — the value is plugged into
    # a filesystem path, so a malformed value could escape the profiles/ dir.
    layer1_profile = layer1_profile_raw.strip()
    if "/" in layer1_profile or "\\" in layer1_profile or layer1_profile.startswith("."):
        raise ValueError(
            f"build.yaml 'layer1_profile' must be a bare profile name "
            f"(no slashes, no leading '.'), got: {layer1_profile!r}"
        )

    # Parse cache (optional). When present, ``namespace`` is the only
    # required field — the actual filesystem layout (which directory under
    # the shared cache root corresponds to a namespace) is an
    # implementation detail of the resolver, deliberately kept out of
    # build.yaml so consumer config stays portable.
    cache_raw = raw.get("cache")
    cache_namespace: Optional[str] = None
    if cache_raw is not None:
        if not isinstance(cache_raw, dict):
            raise ValueError(
                f"build.yaml 'cache' section must be a mapping, "
                f"got: {type(cache_raw).__name__}"
            )
        ns_raw = cache_raw.get("namespace")
        if ns_raw is None:
            raise ValueError(
                "build.yaml 'cache' section requires a 'namespace' key"
            )
        if not isinstance(ns_raw, str) or not ns_raw.strip():
            raise ValueError(
                f"build.yaml 'cache.namespace' must be a non-empty string, "
                f"got: {ns_raw!r}"
            )
        cache_namespace = ns_raw.strip()
        if (
            "/" in cache_namespace
            or "\\" in cache_namespace
            or cache_namespace.startswith(".")
        ):
            raise ValueError(
                f"build.yaml 'cache.namespace' must be a bare name "
                f"(no slashes, no leading '.'), got: {cache_namespace!r}"
            )

    return BuildConfig(
        package_roots=package_roots,
        docker_scan_paths=docker_scan_paths,
        validation=validation,
        contracts=contracts,
        required_images=required_images,
        layer1_profile=layer1_profile,
        cache_namespace=cache_namespace,
    )


# ── Package directory discovery helpers ──────────────────────────────────


def discover_package_dirs(
    repo_root: Path,
    roots: List[PackageRoot],
    require_src: bool = True,
) -> List[Tuple[str, Path]]:
    """Discover package directories across multiple roots.

    Handles both nested (category/package) and flat (package) layouts.

    Args:
        repo_root: Repository root directory
        roots: Package roots to scan
        require_src: If True, only include directories with a src/ subdirectory

    Returns:
        Sorted list of (display_name, package_dir) tuples.
        display_name is "category/package" for nested, "package" for flat.
    """
    packages: List[Tuple[str, Path]] = []

    for root in roots:
        root_dir = repo_root / root.path
        if not root_dir.is_dir():
            continue

        if root.layout == "nested":
            # root/category/package/
            for category_dir in root_dir.iterdir():
                if not category_dir.is_dir() or category_dir.name.startswith("."):
                    continue
                for pkg_dir in category_dir.iterdir():
                    if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
                        continue
                    if require_src and not (pkg_dir / "src").exists():
                        continue
                    name = f"{category_dir.name}/{pkg_dir.name}"
                    packages.append((name, pkg_dir))

        elif root.layout == "flat":
            # root/package/
            for pkg_dir in root_dir.iterdir():
                if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
                    continue
                if require_src and not (pkg_dir / "src").exists():
                    continue
                packages.append((pkg_dir.name, pkg_dir))

    return sorted(packages, key=lambda t: t[0].lower())


def discover_source_dirs(
    repo_root: Path,
    roots: List[PackageRoot],
) -> List[Tuple[Path, str]]:
    """Discover src/ directories with their owning package path.

    Used by import boundary validation and module-to-package mapping.

    Args:
        repo_root: Repository root directory
        roots: Package roots to scan

    Returns:
        List of (src_dir, package_path) tuples.
    """
    result: List[Tuple[Path, str]] = []

    for root in roots:
        root_dir = repo_root / root.path
        if not root_dir.is_dir():
            continue

        if root.layout == "nested":
            # nested layout: root/category/package/src/
            for category_dir in root_dir.iterdir():
                if not category_dir.is_dir() or category_dir.name.startswith("."):
                    continue
                for pkg_dir in category_dir.iterdir():
                    if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
                        continue
                    src_candidate = pkg_dir / "src"
                    if src_candidate.is_dir():
                        pkg_path = f"{category_dir.name}/{pkg_dir.name}"
                        result.append((src_candidate, pkg_path))

        elif root.layout == "flat":
            for child in root_dir.iterdir():
                if not child.is_dir() or child.name.startswith("."):
                    continue
                src_candidate = child / "src"
                if src_candidate.is_dir():
                    result.append((src_candidate, child.name))

    return result


def determine_owning_package(
    file_path: Path,
    repo_root: Path,
    roots: List[PackageRoot],
) -> Optional[str]:
    """Determine which package owns a source file based on its path.

    Args:
        file_path: Absolute path to the source file
        repo_root: Repository root directory
        roots: Package roots to check

    Returns:
        Package path like "foundation/secure_cache" or "app_runtime",
        or None if the file is not under any known root.
    """
    for root in roots:
        root_dir = repo_root / root.path
        try:
            rel = file_path.relative_to(root_dir)
        except ValueError:
            continue

        parts = rel.parts
        if "src" not in parts:
            continue

        src_idx = parts.index("src")
        if root.layout == "nested" and src_idx >= 2:
            # e.g., foundation/logging/src/... → "foundation/logging"
            return f"{parts[0]}/{parts[1]}"
        elif root.layout == "flat" and src_idx >= 1:
            # e.g., app_runtime/src/... → "app_runtime"
            return parts[0]

    return None


def find_package_in_roots(
    target_package: str,
    repo_root: Path,
    roots: List[PackageRoot],
) -> Optional[Tuple[str, Path]]:
    """Locate a specific package by name across configured roots.

    Searches each root for a directory matching target_package.

    Args:
        target_package: Package path (e.g., "foundation/logging" or "app_runtime")
        repo_root: Repository root directory
        roots: Package roots to search

    Returns:
        (display_name, package_dir) tuple, or None if not found.
    """
    for root in roots:
        root_dir = repo_root / root.path
        pkg_path = root_dir / target_package
        if pkg_path.exists() and pkg_path.is_dir():
            return (target_package, pkg_path)
    return None
