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

"""Docker image discovery for NeoAxios projects."""

import warnings
from collections import defaultdict, deque
from pathlib import Path
from typing import List, Optional

import yaml

from neoaxios.build.docker.models import DockerImage


# Module-level guard — deprecation warning fires at most once per
# process.  Multiple DockerImageDiscovery instances in one build (e.g.
# tests) don't spam the user.
_builtin_discovery_deprecation_warned: bool = False


class DockerImageDiscovery:
    """Discovers Docker images in the repository.

    Scans for docker/Dockerfile patterns and parses docker.yaml metadata
    to build a complete picture of all Docker images in the project.

    Discovery patterns are read from build.yaml via BuildConfig.
    """

    def __init__(
        self,
        repo_root: Path,
        scan_paths: List[str],
        skip_builtins: bool = False,
    ):
        """Initialize discovery with repository root.

        Args:
            repo_root: Path to repository root
            scan_paths: Dockerfile glob patterns from BuildConfig.docker_scan_paths
            skip_builtins: When True, suppress the legacy built-in base image
                auto-discovery entirely.  Callers set this when the consumer
                has opted into the ownership model by declaring
                ``required_images`` in build.yaml — the cache resolver has
                already loaded those images into the daemon, so rebuilding
                them from source would be pure duplicated work.
        """
        self.repo_root = Path(repo_root)
        self.scan_paths = scan_paths
        self.skip_builtins = skip_builtins

    def discover_all(self) -> list[DockerImage]:
        """Find all Docker images in dependency order.

        Primary source: consumer-declared scan paths from ``build.yaml``
        (``self.scan_paths``).

        Deprecated fallback: built-in base images shipped with the
        neoaxios-build package itself (``docker/base/*/Dockerfile`` inside
        the installed package).  A DeprecationWarning fires once per
        process unless the caller IS the owning repo (detected by checking
        whether ``self.repo_root`` IS the package's source tree).  New
        consumers should declare their cross-repo base image needs in
        ``build.yaml`` under ``required_images:``, which loads pre-built
        archives from the shared image cache — see
        ``docs/design/base-image-ownership.design.md``.

        Consumer entries that match the same image name as a built-in base
        image win — consumer can override any built-in by declaring a
        Dockerfile with the same image name in a scan_paths-covered location.

        Returns:
            List of DockerImage objects in build order
        """
        images = []

        # (1) Consumer-declared scan paths — processed first so they win dedup.
        for pattern in self.scan_paths:
            # Determine if this is a base image pattern
            is_base = "docker/base/" in pattern
            for dockerfile in self.repo_root.glob(pattern):
                image = self._parse_dockerfile_dir(dockerfile.parent, is_base=is_base)
                if image:
                    images.append(image)

        # (2) Built-in base images shipped with this package — auto-discovered
        #     so projects do not have to declare them in their build.yaml.
        #
        # DEPRECATED: this implicit coupling between project builds and
        # whatever the repo checkout is on disk leaks the owning repo's
        # working state (including untracked files) into project
        # artifacts.  Projects should migrate to ``required_images`` in
        # their build.yaml.
        # See ``docs/design/base-image-ownership.design.md``.
        #
        # ``skip_builtins=True`` suppresses the fallback for consumers who
        # have opted into the ownership model — they already loaded the
        # images they need from the shared cache, so rebuilding the same
        # Dockerfiles here would be pure duplicated work.
        if not self.skip_builtins:
            builtins = self._discover_builtin_base_images()
            if builtins:
                self._warn_builtin_discovery_deprecated(builtins)
            images.extend(builtins)

        # Deduplicate by ``full_name`` (registry/name:tag).  First-seen
        # wins, so consumer-declared images from (1) take precedence
        # over built-in base images from (2) when both publish the same
        # ``registry/name:tag`` triple.  Using ``full_name`` (rather than
        # bare ``name``) lets a consumer ship multiple TAGS of the same
        # image — e.g. ``neoaxios/myservice:latest`` for production
        # plus ``neoaxios/myservice:scaletest`` for load-testing —
        # without one variant silently dropping the other.
        seen: set[str] = set()
        unique = []
        for img in images:
            if img.full_name not in seen:
                seen.add(img.full_name)
                unique.append(img)

        # Sort by dependency order
        return self._topological_sort(unique)

    def _warn_builtin_discovery_deprecated(
        self, discovered: list[DockerImage]
    ) -> None:
        """Emit a DeprecationWarning unless the caller is the owning repo.

        "Owning repo" is detected by checking whether this repo_root
        contains the neoaxios-build package source — i.e. dogfooding
        its own build system.  In that case the auto-discovery IS the
        intended behavior and warning would be noise.

        Other repos get a single stderr message pointing at the
        ``required_images`` migration path.
        """
        global _builtin_discovery_deprecation_warned
        if _builtin_discovery_deprecation_warned:
            return

        # Detect "am I the owner repo" by checking whether repo_root
        # contains the neoaxios-build package source tree.  this codebase's
        # repo_root does; every consumer's does not.
        owner_marker = (
            self.repo_root
            / "neo-packages"
            / "neoaxios-build"
            / "docker"
            / "base"
        )
        if owner_marker.is_dir():
            return

        _builtin_discovery_deprecation_warned = True
        names = ", ".join(sorted(img.full_name for img in discovered))
        warnings.warn(
            "neoaxios-build auto-discovered built-in base images from the "
            "this codebase package tree and will rebuild them in this codebase.  This "
            "behavior is DEPRECATED and will be removed once all consumer "
            "repos migrate.\n"
            f"  Discovered: {names}\n"
            "\n"
            "Migration: declare only the base images you actually consume in "
            "the build.yaml under `required_images:`.  They will be "
            "loaded from the shared image cache (populated by the owning "
            "repo's own `make build`) instead of rebuilt here.  See "
            "docs/design/base-image-ownership.design.md for the full model.",
            DeprecationWarning,
            stacklevel=3,
        )

    def _discover_builtin_base_images(self) -> list[DockerImage]:
        """Enumerate base images shipped inside the neoaxios-build package.

        These live at ``<package_root>/docker/base/*/`` relative to this
        module's filesystem location (``__file__``). Each subdirectory
        containing a ``Dockerfile`` is a base image; ``docker.yaml`` next
        to the Dockerfile provides optional metadata (name, deps, registry).

        Cross-repo containment guard
        ----------------------------
        Under the standard sibling-clone install (every consumer using
        the neoaxios-build via an editable install in the source tree),
        ``<package_root>`` resolves to ``neo-packages/
        neoaxios-build``.  When the consumer is NOT building neoaxios-build itself (the typical
        case), that directory is outside ``self.repo_root`` and a sweep
        would walk a foreign repo's tree — leaking the Dockerfiles
        (including untracked files in the working tree) into
        consumer build artifacts.  Skip the sweep in that case so a
        consumer can never auto-rebuild base images it doesn't own.
        Consumers that legitimately need a base image declare it
        in ``required_images:`` and the cache resolver loads it from the
        shared image cache without rebuilding.

        Returns empty list if:
          - Package is installed as a wheel without the docker/ tree
            (the docker/ dir lives outside src/, so sdist-only installs
            won't have it). Editable installs always see it.
          - No ``<package_root>/docker/base/`` directory exists.
          - ``<package_root>`` is not contained in ``self.repo_root``
            (cross-repo discovery — blocked unconditionally).
        """
        # discovery.py is at <package_root>/src/neoaxios/build/docker/discovery.py
        # Walk up 4 parents to reach <package_root>, then docker/base/.
        module_file = Path(__file__).resolve()
        package_root = module_file.parents[4]

        # Cross-repo containment: only sweep when package_root lives
        # INSIDE this consumer's repo_root.  See class docstring above.
        try:
            resolved_repo_root = self.repo_root.resolve()
            package_root.relative_to(resolved_repo_root)
        except ValueError:
            # package_root is not under repo_root — cross-repo install.
            return []

        base_dir = package_root / "docker" / "base"

        if not base_dir.is_dir():
            return []

        builtins: list[DockerImage] = []
        for entry in sorted(base_dir.iterdir()):
            if not entry.is_dir():
                continue
            if not (entry / "Dockerfile").exists():
                continue
            image = self._parse_dockerfile_dir(entry, is_base=True)
            if image is not None:
                builtins.append(image)
        return builtins

    def _parse_dockerfile_dir(
        self, docker_dir: Path, is_base: bool = False
    ) -> Optional[DockerImage]:
        """Parse a docker/ directory into a DockerImage.

        Args:
            docker_dir: Path to directory containing Dockerfile
            is_base: Whether this is a base image

        Returns:
            DockerImage or None if invalid
        """
        dockerfile = docker_dir / "Dockerfile"
        if not dockerfile.exists():
            return None

        # Try to load docker.yaml metadata
        metadata = self.parse_docker_yaml(docker_dir / "docker.yaml")

        # Determine image name
        if metadata and "image" in metadata:
            name = metadata["image"].get("name")
            tag = metadata["image"].get("tag", "latest")
            registry = metadata["image"].get("registry")
        else:
            # Derive from directory structure
            name = self._derive_image_name(docker_dir, is_base)
            tag = "latest"
            registry = "neoaxios" if is_base else None

        if not name:
            return None

        # Determine build context
        if metadata and "build" in metadata:
            context_rel = metadata["build"].get("context", "..")
            context = (docker_dir / context_rel).resolve()
        else:
            # Default: parent of docker/ directory
            context = docker_dir.parent

        # Extract base image from Dockerfile
        base_image = self._extract_base_image(dockerfile)

        # Get dependencies
        wheel_deps = []
        image_deps = []
        if metadata and "dependencies" in metadata:
            wheel_deps = metadata["dependencies"].get("wheels", [])
            image_deps = metadata["dependencies"].get("images", [])

        # Check for always_rebuild flag
        always_rebuild = False
        if metadata and "build" in metadata:
            always_rebuild = metadata["build"].get("always_rebuild", False)

        return DockerImage(
            name=name,
            tag=tag,
            path=docker_dir,
            dockerfile=dockerfile,
            context=context,
            base_image=base_image,
            wheel_dependencies=wheel_deps,
            image_dependencies=image_deps,
            registry=registry,
            always_rebuild=always_rebuild,
        )

    def _derive_image_name(self, docker_dir: Path, is_base: bool = False) -> str:
        """Derive image name from directory structure.

        Args:
            docker_dir: Path to docker/ directory
            is_base: Whether this is a base image

        Returns:
            Derived image name
        """
        if is_base:
            # build-tools/.../docker/base/python-slim -> python-slim
            return docker_dir.name

        # workflows/<name>/docker -> <name>-workflow
        # packages/<category>/<pkg>/docker -> <pkg>
        parent = docker_dir.parent
        name = parent.name.replace("_", "-")
        return name

    def _extract_base_image(self, dockerfile: Path) -> Optional[str]:
        """Extract FROM image from Dockerfile.

        Args:
            dockerfile: Path to Dockerfile

        Returns:
            Base image name or None
        """
        try:
            content = dockerfile.read_text()
            # Match FROM directive (first non-comment FROM)
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#"):
                    continue
                if line.upper().startswith("FROM "):
                    # FROM image:tag AS stage
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
            return None
        except OSError:
            return None

    def parse_docker_yaml(self, yaml_path: Path) -> Optional[dict]:
        """Parse docker.yaml metadata file.

        Args:
            yaml_path: Path to docker.yaml

        Returns:
            Parsed metadata dict or None if not found
        """
        if not yaml_path.exists():
            return None

        try:
            content = yaml_path.read_text()
            return yaml.safe_load(content)
        except (OSError, yaml.YAMLError):
            return None

    def _topological_sort(self, images: list[DockerImage]) -> list[DockerImage]:
        """Sort images by dependency order (base images first).

        Uses Kahn's algorithm for topological sorting.  Keys every
        graph node by ``img.full_name`` (registry/name:tag) so multiple
        TAGS of the same image — e.g. ``neoaxios/myservice:latest``
        and ``neoaxios/myservice:scaletest`` — survive the sort
        without collapsing into each other.  Dependency lookups still
        accept short names (no tag, no registry) by maintaining a
        multi-keyed lookup table.

        Args:
            images: List of DockerImage objects

        Returns:
            Images sorted so dependencies come before dependents
        """
        # Build multi-keyed lookup so dependency strings written without
        # a tag (e.g. ``neoaxios/python-base``) resolve to the same
        # DockerImage as fully qualified ones (``neoaxios/python-base:latest``).
        # Short-name collisions across variants are unavoidable here —
        # by design, ``neoaxios/myservice`` (no tag) is ambiguous
        # between ``:latest`` and ``:scaletest``.  We resolve by binding
        # short-name keys to the FIRST seen variant; downstream FROMs
        # that need a specific tag should write the tag explicitly,
        # which routes through ``full_name`` and is unambiguous.
        by_full_name: dict[str, DockerImage] = {img.full_name: img for img in images}
        by_short: dict[str, DockerImage] = {}
        for img in images:
            by_short.setdefault(img.name, img)
            by_short.setdefault(img.short_name, img)

        def _resolve(dep_str: str) -> str | None:
            """Map a dep reference to a node id (full_name) if known."""
            normalized = self._normalize_image_name(dep_str)
            # First try full-name match (preserves tag), then fall back
            # to short-name lookup (legacy callers FROM ``name`` only).
            if dep_str in by_full_name:
                return dep_str
            if normalized in by_short:
                return by_short[normalized].full_name
            return None

        # Build dependency graph keyed by full_name.
        graph: dict[str, list[str]] = defaultdict(list)
        in_degree: dict[str, int] = {img.full_name: 0 for img in images}

        for img in images:
            self_id = img.full_name

            # Check image dependencies. Guard against self-reference,
            # which can happen when an image's FROM references its own
            # short name (Kahn's algorithm cannot schedule a self-loop).
            for dep in img.image_dependencies:
                dep_id = _resolve(dep)
                if dep_id is not None and dep_id != self_id:
                    graph[dep_id].append(self_id)
                    in_degree[self_id] += 1

            # Check base image dependency (same self-reference guard).
            if img.base_image:
                base_id = _resolve(img.base_image)
                if base_id is not None and base_id != self_id:
                    graph[base_id].append(self_id)
                    in_degree[self_id] += 1

        # Kahn's algorithm with deque for O(1) popleft
        queue = deque(
            full_name for full_name, degree in in_degree.items() if degree == 0
        )
        result = []

        while queue:
            node = queue.popleft()  # O(1) vs O(n) for list.pop(0)
            if node in by_full_name:
                result.append(by_full_name[node])

            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Add any remaining images (no dependencies, or cycle remnants).
        seen = {img.full_name for img in result}
        for img in images:
            if img.full_name not in seen:
                result.append(img)

        return result

    def _normalize_image_name(self, name: str) -> str:
        """Normalize image name for comparison.

        Strips registry prefix and tag.

        Args:
            name: Full image name (e.g., "neoaxios/base:latest")

        Returns:
            Normalized name (e.g., "base")
        """
        # Remove tag
        if ":" in name:
            name = name.split(":")[0]
        # Remove registry
        if "/" in name:
            name = name.split("/")[-1]
        return name
