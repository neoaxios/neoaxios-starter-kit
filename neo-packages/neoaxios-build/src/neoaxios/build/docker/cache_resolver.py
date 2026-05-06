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

"""Resolve required base images from the shared Docker image cache.

Projects declare the base images they need in ``build.yaml`` under
``required_images:``. This module looks each one up in the shared cache
(``$NEOAXIOS_IMAGE_CACHE``), loads the archive into the local Docker
daemon if it's not already resident, and fails loudly when the archive
is missing — with a message that names the owning project so the
operator knows where to run ``make build``.

The cache layout is documented in ``docs/design/base-image-ownership.design.md``:

    <hash>.tar.gz      where hash = sha256(full_name + "\\n")[:16]
    <hash>.sha256      content sha256 of the .tar.gz

The ``full_name`` matches the Dockerfile ``FROM`` line, e.g.
``neoaxios/base:latest``. The trailing newline keeps us compatible with
the existing ``DockerBuilder._compute_output_hash`` convention and with
the standard ``echo "$ref" | sha256sum`` shell idiom used by external
build scripts.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from neoaxios.build._telemetry import auto_trace, get_telemetry
from neoaxios.build.docker.builder import _shared_image_cache_path

logger = get_telemetry(__name__)


# Relative path under ``repo_root`` to the optional owner registry.
# Advisory only — absence does not fail resolution, it just produces
# less-actionable error messages on cache miss.
_OWNER_REGISTRY_RELPATH = "docs/image-owners.yaml"


class ImageCacheMiss(RuntimeError):
    """Raised when a required image is not present in the shared cache.

    The string form is already actionable; callers typically surface it
    as-is to stderr and exit non-zero.
    """


@dataclass(frozen=True)
class ResolvedImage:
    """One row in ``resolve_required_images`` bookkeeping.

    Attributes:
        ref: The full image reference from ``required_images`` (e.g.
            ``neoaxios/base:latest``).
        archive: Path to the ``<hash>.tar.gz`` in the shared cache.
        content_sha: Content sha256 of the archive, read from the sidecar
            ``.sha256`` file. Empty string when the sidecar is absent
            (older cache entries).
    """
    ref: str
    archive: Path
    content_sha: str


def _compute_hash(image_ref: str) -> str:
    """Name-addressed cache key.

    Matches ``DockerBuilder._compute_output_hash`` and
    ``thirdparty_puller._compute_hash`` byte-for-byte.  Changing this
    breaks the contract with every publisher, so don't.
    """
    return hashlib.sha256((image_ref + "\n").encode()).hexdigest()[:16]


def _load_owner_registry(repo_root: Path) -> Dict[str, str]:
    """Read the optional ``docs/image-owners.yaml`` if present.

    Registry format is a flat mapping of *untagged* image name to owner
    project, e.g. ``neoaxios/base: this codebase``.  Returning an empty
    dict is fine — the resolver degrades to "owner: (unknown)" in error
    messages.

    We search both the caller's ``repo_root`` (a project may ship its
    own partial registry) and the repo checkout at the neoaxios-build
    package location, so cross-project ownership info is available even
    when the project hasn't copied the registry locally.
    """
    merged: Dict[str, str] = {}
    candidates: List[Path] = [repo_root / _OWNER_REGISTRY_RELPATH]

    # this codebase package location: walk up from this module file.
    # discovery.py → <package_root>/src/neoaxios/build/docker/cache_resolver.py
    # <package_root> is 4 parents up; the repo checkout root is one above that.
    package_root = Path(__file__).resolve().parents[4]
    devkit_registry = package_root.parent.parent / _OWNER_REGISTRY_RELPATH
    if devkit_registry != candidates[0]:
        candidates.append(devkit_registry)

    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            logger.warning(
                f"Cannot read image-owner registry {path}: {exc}"
            )
            continue
        if not isinstance(data, dict):
            logger.warning(
                f"Image-owner registry {path} is not a mapping; ignoring"
            )
            continue
        for key, value in data.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            # First match wins — caller-local registry overrides this codebase's.
            merged.setdefault(key.strip(), value.strip())
    return merged


def _strip_tag(image_ref: str) -> str:
    """``neoaxios/base:latest`` → ``neoaxios/base``.

    Registry keys are untagged so a repo's entry survives tag bumps.
    """
    return image_ref.split(":", 1)[0]


def _owner_for(image_ref: str, registry: Dict[str, str]) -> str:
    """Map an image ref to its owner repo string, or ``(unknown)``."""
    return registry.get(_strip_tag(image_ref), "(unknown)")


def _docker_load(archive: Path) -> None:
    """Run ``docker load -i <archive>``; raise on failure.

    We don't parse stdout — successful load just needs a zero exit.
    Failure mode is typically a corrupt archive (e.g. half-written
    during a killed owner build), in which case the caller will want
    the error surfaced, not swallowed.
    """
    try:
        result = subprocess.run(
            ["docker", "load", "-i", str(archive)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"docker load failed for {archive}: {exc}"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"docker load failed for {archive}\n"
            f"stderr: {result.stderr.strip()}"
        )


@auto_trace(logger)
def resolve_required_images(
    repo_root: Path,
    required_images: List[str],
    cache_dir: Optional[Path] = None,
) -> List[ResolvedImage]:
    """Ensure every required image is loaded in the local Docker daemon.

    For each entry in ``required_images``:

      1. Compute the name-addressed hash.
      2. Look up ``<cache>/<hash>.tar.gz``.  Raise ``ImageCacheMiss`` with
         an owner-aware message if absent.
      3. ``docker load -i <archive>``.

    ``docker load`` is idempotent and cheap when all layers are already
    resident (the daemon diffs against its layer store before importing),
    so we don't gate the call on a "do we already have it" check — the
    check would require either decompressing the archive to read its
    config digest or maintaining a separate ``.image_id`` sidecar, both
    of which cost more than the skip saves in practice.

    The local daemon state after this call is a superset of what the
    consumer's Dockerfiles need: every ``FROM`` reference resolves
    without contacting a remote registry and without rebuilding the
    upstream Dockerfile.

    Args:
        repo_root: Project root — used to locate the optional
            ``docs/image-owners.yaml`` for better error messages.
        required_images: List of image refs from ``BuildConfig``.
        cache_dir: Override for the shared cache path.  Defaults to the
            value returned by ``_shared_image_cache_path()``.

    Returns:
        One ``ResolvedImage`` per input entry, in input order.

    Raises:
        ImageCacheMiss: When one or more archives are missing. We fail
            at the first miss and include the collected-so-far info in
            the exception message so the operator sees the full picture
            instead of iterating one miss at a time.
        RuntimeError: When the shared cache is disabled
            (``IMAGE_CACHE=-`` or ``NEOAXIOS_IMAGE_CACHE=-``) yet
            ``required_images`` is non-empty.  Opt-out only makes sense
            for repos that don't consume cache entries.
    """
    if not required_images:
        return []

    effective_cache = cache_dir if cache_dir is not None else _shared_image_cache_path(repo_root)
    if effective_cache is None:
        raise RuntimeError(
            "shared image cache is explicitly disabled "
            "(IMAGE_CACHE=- or NEOAXIOS_IMAGE_CACHE=-), but this "
            "repo's build.yaml declares required_images. Either enable the "
            "cache or remove the required_images entries."
        )

    owners = _load_owner_registry(repo_root)
    results: List[ResolvedImage] = []

    for ref in required_images:
        image_hash = _compute_hash(ref)
        archive = effective_cache / f"{image_hash}.tar.gz"
        checksum = effective_cache / f"{image_hash}.sha256"

        if not archive.is_file():
            owner = _owner_for(ref, owners)
            raise ImageCacheMiss(
                f"required image {ref!r} is not in the shared image cache\n"
                f"       expected archive: {archive}\n"
                f"       owner: {owner}\n"
                f"\n"
                f"To populate, run `make build` in the owning repo."
            )

        # Sidecar is informational.  Missing .sha256 just means this
        # cache entry was produced by an older writer; the archive is
        # still loadable.
        content_sha = checksum.read_text().strip() if checksum.is_file() else ""

        _docker_load(archive)
        logger.info(
            f"Loaded {ref} from shared image cache ({archive.name})"
        )

        results.append(ResolvedImage(
            ref=ref,
            archive=archive,
            content_sha=content_sha,
        ))

    return results
