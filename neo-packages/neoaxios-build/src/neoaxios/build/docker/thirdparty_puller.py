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

"""Pull 3rd-party docker images and archive them to the shared image cache.

Companion to the Dockerfile-based builder.  1st-party images have a
``docker/base/<name>/Dockerfile`` that neoaxios-build builds; 3rd-party
images have ``docker/thirdparty/<name>/deploy.yaml`` with an ``image:``
reference, and this module pulls + saves + compresses them into the same
hash-addressed cache the builder uses.  Consumers load archives the same
way regardless of provenance — ``<hash>.tar.gz`` where
``hash = sha256(image_ref + "\n")[0:16]``.

Each consuming repo owns its own ``thirdparty/`` set and pulls what its
own deploy.yaml manifests reference.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple

import yaml

from neoaxios.build._telemetry import auto_trace, get_telemetry
from neoaxios.build.ui import BuildDisplay

logger = get_telemetry(__name__)
display = BuildDisplay()

# Minimum viable archive size — anything smaller signals a truncated export
# (typical cause: docker save hit the containerd-snapshotter path and wrote
# only OCI blob refs without the layer content).  10 KiB is a conservative
# floor below which any real image archive would be malformed.
_MIN_ARCHIVE_BYTES = 10 * 1024


class ThirdPartyImage(NamedTuple):
    """A 3rd-party image declared in ``docker/thirdparty/<name>/deploy.yaml``."""

    name: str
    image_ref: str
    manifest_path: Path
    expected_digest: Optional[str]


class ThirdPartyPullResult(NamedTuple):
    """One row in the 3rd-party pull summary table.

    Shape-compatible with ``BuildDisplay.docker_pull_summary_table`` so
    the output matches the 1st-party ``docker_summary_table`` layout
    that consumers already know how to read.
    """

    image_ref: str
    archive_path: Path
    content_sha: str
    duration: float
    cached: bool
    success: bool
    error: Optional[str] = None


EXCLUDED_DIR_NAMES = {
    ".venv", "venv", "__pycache__", "node_modules", "build", "dist",
    ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".test-cache", "logs", ".build-cache",
}


def _compute_hash(image_ref: str) -> str:
    """Same scheme as ``DockerBuilder._compute_output_hash`` and the
    ``sha256sum | cut -c1-16`` shell convention used by external build
    scripts: 16 hex chars of ``sha256(image_ref + "\\n")``.

    Guarantees that downstream provisioners find archives produced by
    this module at the same path they would compute from the image ref
    in a deploy.yaml.
    """
    return hashlib.sha256((image_ref + "\n").encode()).hexdigest()[:16]


def _split_digest(image_ref: str) -> Tuple[str, Optional[str]]:
    """``foo/bar:tag@sha256:abc…`` → (``foo/bar:tag``, ``sha256:abc…``).

    Unpinned refs return (ref, None).  A pinned digest triggers a
    verification step after pull.
    """
    if "@sha256:" in image_ref:
        tag, _, digest = image_ref.partition("@")
        return tag, digest
    return image_ref, None


def discover_thirdparty_manifests(repo_root: Path) -> List[ThirdPartyImage]:
    """Walk ``<repo>`` for ``**/docker/thirdparty/<name>/deploy.yaml``.

    Shape check: deploy.yaml must sit two dirs under ``docker/thirdparty/``
    so we don't accidentally pick up a stray deploy.yaml elsewhere.  The
    folder name becomes the logical identity; the ``image:`` field is the
    pull target.
    """
    results: List[ThirdPartyImage] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        p = Path(dirpath)
        if (
            p.parent.name == "thirdparty"
            and p.parent.parent.name == "docker"
            and "deploy.yaml" in filenames
        ):
            deploy = p / "deploy.yaml"
            data = yaml.safe_load(deploy.read_text())
            if not isinstance(data, dict) or "image" not in data:
                raise ValueError(
                    f"docker/thirdparty/{p.name}/deploy.yaml missing `image:` field "
                    f"— required for pull and archive"
                )
            image_ref = str(data["image"]).strip()
            _, expected_digest = _split_digest(image_ref)
            results.append(
                ThirdPartyImage(
                    name=p.name,
                    image_ref=image_ref,
                    manifest_path=deploy,
                    expected_digest=expected_digest,
                )
            )
    return sorted(results, key=lambda i: i.name)


def _check_no_firstparty_conflict(repo_root: Path, images: List[ThirdPartyImage]) -> None:
    """Refuse to pull if a folder name also exists under ``docker/base/``.

    A name collision between 1st- and 3rd-party means somebody is trying
    to both build AND pull the same logical image, and the build pipeline
    has no way to reconcile them.  Fail loud rather than silently picking
    one.
    """
    conflicts = []
    for img in images:
        for dirpath, dirnames, _ in os.walk(repo_root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
            p = Path(dirpath)
            if (
                p.name == img.name
                and p.parent.name == "base"
                and p.parent.parent.name == "docker"
            ):
                conflicts.append((img.name, p, img.manifest_path.parent))
    if conflicts:
        details = "\n".join(
            f"  {name}: base={base.relative_to(repo_root)}  thirdparty={tp.relative_to(repo_root)}"
            for name, base, tp in conflicts
        )
        raise RuntimeError(
            "1st-party / 3rd-party name conflict — same image name declared in both:\n"
            f"{details}\n"
            "Resolution: pick one path.  If this codebase builds it, keep docker/base/ "
            "and delete the thirdparty/ entry; otherwise keep thirdparty/ and "
            "delete the Dockerfile."
        )


def _require_tools() -> None:
    """All three tools are hard requirements — no fallback path.

    ``docker`` to pull and inspect, ``docker buildx`` to export
    fully-bundled archives (plain ``docker save`` produces blob-ref-only
    OCI archives on containerd-snapshotter-backed daemons), and ``pigz``
    for compression — same tool the 1st-party builder uses.
    """
    if shutil.which("docker") is None:
        raise RuntimeError(
            "docker not found on PATH. Install: https://docs.docker.com/engine/install/"
        )
    if shutil.which("pigz") is None:
        raise RuntimeError("pigz not found on PATH. Install: apt install pigz")
    result = subprocess.run(
        ["docker", "buildx", "version"], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            "docker buildx not available — required for bundled image export. "
            "Install: https://docs.docker.com/build/install-buildx/"
        )


def _verify_digest(tag_ref: str, expected_digest: str) -> None:
    """Assert the pulled image matches a pinned ``@sha256:…`` digest.

    Without this, ``docker pull --platform=linux/amd64 foo:tag@sha256:abc``
    silently pulls whatever ``foo:tag`` currently points at.  We inspect
    ``RepoDigests`` after the pull and require an exact match.
    """
    result = subprocess.run(
        ["docker", "image", "inspect",
         "--format", "{{range .RepoDigests}}{{.}} {{end}}", tag_ref],
        check=True, capture_output=True, text=True,
    )
    digests = set(re.findall(r"sha256:[a-f0-9]{64}", result.stdout))
    if expected_digest not in digests:
        raise RuntimeError(
            f"Digest mismatch for {tag_ref}\n"
            f"  expected: {expected_digest}\n"
            f"  pulled:   {' '.join(sorted(digests)) or '<none>'}"
        )


def _export_and_compress(tag_ref: str, archive_path: Path) -> str:
    """Export ``tag_ref`` to a fully-bundled OCI tarball, then ``pigz`` it.

    Uses the ``docker buildx build --output=type=docker`` trick: a
    throwaway ``FROM <image>`` Dockerfile and buildx's ``type=docker``
    exporter.  Unlike plain ``docker save`` (which on a containerd-
    snapshotter-backed daemon emits an OCI archive containing only blob
    REFERENCES and no layer content), the buildx ``type=docker`` output
    is a self-contained tarball whose ``blobs/sha256/`` entries include
    every layer byte — ``docker load`` on a different machine resolves
    cleanly with no external content-store dependency.

    Returns the sha256 hex digest of the compressed archive for the
    sidecar ``.sha256`` file.  Raises ``RuntimeError`` if any step
    fails, or if the final archive is below ``_MIN_ARCHIVE_BYTES``
    (10 KiB truncation guard).
    """
    sha = hashlib.sha256()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Minimal Dockerfile that resolves to the target image — buildx
        # then emits that image's full layer graph.
        (tmp_path / "Dockerfile").write_text(f"FROM {tag_ref}\n")
        uncompressed = tmp_path / "image.tar"

        buildx = subprocess.run(
            [
                "docker", "buildx", "build",
                "--platform=linux/amd64",
                f"--output=type=docker,dest={uncompressed}",
                "-f", str(tmp_path / "Dockerfile"),
                str(tmp_path),
            ],
            capture_output=True, text=True,
        )
        if buildx.returncode != 0:
            raise RuntimeError(
                f"docker buildx export failed for {tag_ref}: {buildx.stderr.strip()}"
            )
        if not uncompressed.exists():
            raise RuntimeError(
                f"docker buildx produced no output file for {tag_ref}"
            )

        # pigz the full tarball with inline sha256.  One pass through the
        # compressed bytes, same pattern as DockerBuilder._export_to_archive.
        with open(archive_path, "wb") as out:
            with open(uncompressed, "rb") as raw:
                pigz = subprocess.Popen(
                    ["pigz", "-6"],
                    stdin=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                assert pigz.stdout is not None
                while True:
                    chunk = pigz.stdout.read(65536)
                    if not chunk:
                        break
                    out.write(chunk)
                    sha.update(chunk)
                pigz.wait(timeout=300)
                if pigz.returncode != 0:
                    raise RuntimeError(
                        f"pigz failed for {tag_ref}: "
                        f"{pigz.stderr.read().decode(errors='replace')}"
                    )

    size = archive_path.stat().st_size
    if size < _MIN_ARCHIVE_BYTES:
        archive_path.unlink()
        raise RuntimeError(
            f"Archive for {tag_ref} is truncated ({size} bytes < "
            f"{_MIN_ARCHIVE_BYTES}) — buildx export may have produced a "
            f"blob-ref-only tarball.  Aborting rather than shipping a "
            f"broken archive."
        )
    return sha.hexdigest()


def _link_to_shared_cache(
    archive_path: Path, checksum_path: Path, cache_dir: Optional[Path]
) -> None:
    """Hardlink (or copy on EXDEV) archive + checksum into the shared cache.

    Mirrors ``DockerBuilder._link_archive_to_cache`` exactly so consumer
    provisioners don't care whether an archive came from a Dockerfile
    build or a 3rd-party pull — same location, same lookup path.
    """
    if cache_dir is None:
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning(f"Cannot create shared image cache {cache_dir}: {exc}")
        return
    for src in (archive_path, checksum_path):
        dest = cache_dir / src.name
        if dest.exists() or dest.is_symlink():
            try:
                dest.unlink()
            except OSError as exc:
                logger.warning(f"Cannot replace {dest}: {exc}")
                continue
        try:
            os.link(src, dest)
        except OSError:
            try:
                shutil.copy2(src, dest)
            except Exception as copy_exc:
                logger.warning(f"Failed to publish {src.name} to cache: {copy_exc}")


@auto_trace(logger)
def pull_all_thirdparty(
    repo_root: Path,
    local_output_dir: Path,
    shared_cache_dir: Optional[Path],
    force: bool = False,
) -> List[ThirdPartyPullResult]:
    """Discover, pull, and archive every 3rd-party image in this codebase.

    Returns one ``ThirdPartyPullResult`` per declared image.  Raises on
    any pull, digest, save, or compression failure — unlike the 1st-
    party builder which degrades gracefully, a missing 3rd-party archive
    would cause test workers to fail deployment later, so it's
    better to fail the build now.  Callers typically pass the returned
    list to ``BuildDisplay.docker_pull_summary_table`` for rendering.
    """
    manifests = discover_thirdparty_manifests(repo_root)
    if not manifests:
        return []

    _check_no_firstparty_conflict(repo_root, manifests)
    _require_tools()

    local_output_dir.mkdir(parents=True, exist_ok=True)
    results: List[ThirdPartyPullResult] = []
    for img in manifests:
        hash_value = _compute_hash(img.image_ref)
        archive_path = local_output_dir / f"{hash_value}.tar.gz"
        checksum_path = local_output_dir / f"{hash_value}.sha256"

        if archive_path.exists() and checksum_path.exists() and not force:
            _link_to_shared_cache(archive_path, checksum_path, shared_cache_dir)
            results.append(ThirdPartyPullResult(
                image_ref=img.image_ref,
                archive_path=archive_path,
                content_sha=checksum_path.read_text().strip(),
                duration=0.0,
                cached=True,
                success=True,
            ))
            continue

        tag_ref, expected_digest = _split_digest(img.image_ref)

        started = time.monotonic()
        subprocess.run(
            ["docker", "pull", "--platform=linux/amd64", tag_ref],
            check=True,
        )
        if expected_digest is not None:
            _verify_digest(tag_ref, expected_digest)
        content_sha = _export_and_compress(tag_ref, archive_path)
        checksum_path.write_text(content_sha + "\n")
        _link_to_shared_cache(archive_path, checksum_path, shared_cache_dir)
        duration = time.monotonic() - started

        results.append(ThirdPartyPullResult(
            image_ref=img.image_ref,
            archive_path=archive_path,
            content_sha=content_sha,
            duration=duration,
            cached=False,
            success=True,
        ))
    return results
