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

"""Docker image builder with caching and dependency management."""

import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional

from neoaxios.build._telemetry import auto_trace, get_telemetry

from neoaxios.build.cache import BuildCache
from neoaxios.build.constants import DEFAULT_DOCKER_MAX_WORKERS
from neoaxios.build.docker.models import DockerBuildResult, DockerImage

logger = get_telemetry(__name__)

# Profile log path — written when NEOAXIOS_BUILD_PROFILE=1
_PROFILE_LOG = Path("/tmp/docker-build-profile.jsonl")


def _default_cache_root(repo_root: Optional[Path] = None) -> Path:
    """Return the canonical NeoAxios per-user cache root on this machine.

    Resolution precedence:
      1. ``_NEO_REAL_HOME`` (explicit override — sandboxes, CI where
         /etc/passwd isn't accurate).
      2. ``/etc/passwd`` ``pw_dir`` for the current UID — invariant across
         shells and worktree ``$HOME`` rewrites.  Using ``$HOME`` here was
         the original source of two-caches-out-of-sync drift: one shell
         (``$HOME=/home/alice``) publishes, another (``$HOME=/home/alice/
         .wrktree2``) reads a stale per-worktree copy.

    When ``repo_root`` is provided, the consumer's optional
    ``cache.namespace`` from ``build.yaml`` is appended so namespaced
    consumers get an isolated cache root.  Without ``repo_root`` (legacy
    callers), the historical un-namespaced root is returned unchanged.
    """
    from neoaxios.build.cache_namespace import shared_cache_parent

    return shared_cache_parent(repo_root)


def _shared_wheel_cache(repo_root: Optional[Path] = None) -> Optional[Path]:
    """Return the shared NeoAxios wheel cache path, or None when disabled.

    Delegates to :func:`cache_namespace.resolved_wheel_cache_path` for
    the canonical resolution order (alias env → opt-out → build.yaml
    cache.namespace → primary env default → hardcoded default).  Adds
    one wheel-cache-specific concern on top: returns ``None`` when the
    resolved directory doesn't exist, since reads against a missing
    cache silently yield no wheels.
    """
    from neoaxios.build.cache_namespace import resolved_wheel_cache_path

    path = resolved_wheel_cache_path(repo_root)
    if path is None:
        return None
    if not path.is_dir():
        return None
    return path


def _shared_image_cache_path(repo_root: Optional[Path] = None) -> Optional[Path]:
    """Return the shared NeoAxios Docker image cache path, or None when disabled.

    Delegates to :func:`cache_namespace.resolved_image_cache_path` for
    the canonical resolution order.  Unlike the wheel cache, the path
    is returned even when the directory doesn't exist — the caller
    (publisher side) will mkdir it on first write.
    """
    from neoaxios.build.cache_namespace import resolved_image_cache_path

    return resolved_image_cache_path(repo_root)


@lru_cache(maxsize=1)
def _require_pigz() -> None:
    """Verify pigz is installed. Fails the build if missing.

    Raises:
        RuntimeError: If pigz is not found on PATH
    """
    try:
        result = subprocess.run(
            ["which", "pigz"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "pigz is required for image compression. "
                "Install with: apt install pigz"
            )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("pigz availability check timed out") from exc

# Optional Rich progress bar support
try:
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class DockerBuilder:
    """Builds Docker images with caching and dependency management.

    Features:
        - Incremental builds with cache key based on Dockerfile, context, and wheels
        - Parallel builds for independent images
        - Dependency-aware ordering (base images first)
        - Wheel population to Docker contexts
    """

    def __init__(
        self,
        repo_root: Path,
        dist_dir: Optional[Path] = None,
        cache: Optional[BuildCache] = None,
        force: bool = False,
        max_workers: int = DEFAULT_DOCKER_MAX_WORKERS,
    ):
        """Initialize builder with paths and cache.

        Args:
            repo_root: Repository root path
            dist_dir: Directory containing wheel files (default: repo_root/dist)
            cache: BuildCache instance (default: creates new one)
            force: Force rebuild ignoring cache
            max_workers: Maximum parallel build workers
        """
        self.repo_root = Path(repo_root)
        self.dist_dir = dist_dir or (self.repo_root / "dist")
        self.cache = cache or BuildCache(self.repo_root / ".build-cache")
        self.force = force
        self.max_workers = max_workers

        # Cache key storage for Docker images
        self._docker_cache_dir = self.repo_root / ".build-cache" / "docker"
        self._docker_cache_dir.mkdir(parents=True, exist_ok=True)

        # Output directory for tar.gz files (downstream consumer repository)
        self._output_dir = self.repo_root / "docker-images"
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Track which images we've already checked
        self._checked_dockerignore: set[str] = set()

        # Cache for image digests (populated by prefetch_digests)
        self._digest_cache: dict[str, Optional[str]] = {}

        # Deferred archive exports — archive writing decoupled from build
        # so downstream images can start building immediately
        self._export_executor = ThreadPoolExecutor(max_workers=max_workers)
        self._pending_exports: list = []
        self._pending_exports_lock = threading.Lock()

        # Shared build timestamp for consistency across batch builds
        # Set on first use, shared by all images in a build_all() call
        self._build_timestamp: Optional[int] = None

    def _get_build_timestamp(self) -> int:
        """Get the shared build timestamp for this build session.

        Returns the same timestamp for all images in a build batch,
        ensuring consistency across related images.

        Returns:
            Unix timestamp (seconds since epoch)
        """
        if self._build_timestamp is None:
            self._build_timestamp = int(time.time())
        return self._build_timestamp

    def _dockerfile_uses_arg(self, dockerfile: Path, arg_name: str) -> bool:
        """Check if a Dockerfile references a specific ARG.

        Args:
            dockerfile: Path to Dockerfile
            arg_name: ARG name to check for (e.g., "BUILD_TIMESTAMP")

        Returns:
            True if ARG is declared or used in the Dockerfile
        """
        if not dockerfile.exists():
            return False

        try:
            content = dockerfile.read_text()
            # Check for ARG declaration or variable reference
            # Matches: ARG BUILD_TIMESTAMP, ${BUILD_TIMESTAMP}, $BUILD_TIMESTAMP
            return (
                f"ARG {arg_name}" in content
                or f"${{{arg_name}}}" in content
                or f"${arg_name}" in content
            )
        except OSError:
            return False

    def _compute_output_hash(self, image: DockerImage) -> str:
        """Compute hash for output filename matching Makefile convention.

        Uses: echo "image:tag" | sha256sum | cut -c1-16

        Args:
            image: DockerImage to compute hash for

        Returns:
            16-character hex hash string
        """
        hash_input = image.full_name + "\n"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _get_output_path(self, image: DockerImage) -> Path:
        """Get output tar.gz path for an image.

        Args:
            image: DockerImage to get path for

        Returns:
            Path to {hash}.tar.gz in docker-images/
        """
        hash_value = self._compute_output_hash(image)
        return self._output_dir / f"{hash_value}.tar.gz"

    def _check_dockerignore(self, image: DockerImage) -> Optional[str]:
        """Check if .dockerignore is missing or misplaced.

        The .dockerignore must be at the build context root, not in the
        docker/ subfolder. A misplaced .dockerignore causes the entire
        context to be sent to the Docker daemon, slowing builds.

        Returns:
            Error message if check fails, None if OK.
        """
        if image.name in self._checked_dockerignore:
            return None
        self._checked_dockerignore.add(image.name)

        context_dockerignore = image.context / ".dockerignore"
        docker_dir_dockerignore = image.path / ".dockerignore"

        # Case 1: .dockerignore in wrong location (always an error)
        if docker_dir_dockerignore.exists() and not context_dockerignore.exists():
            return (
                f".dockerignore in wrong location\n"
                f"      Found: {docker_dir_dockerignore.relative_to(self.repo_root)}\n"
                f"      Expected: {context_dockerignore.relative_to(self.repo_root)}\n"
                f"      Move it to context root for Docker to use it."
            )

        # Case 2: Missing .dockerignore
        if not context_dockerignore.exists():
            return (
                f"missing .dockerignore at context root\n"
                f"      Expected: {context_dockerignore.relative_to(self.repo_root)}\n"
                f"      Add .dockerignore to exclude unnecessary files from Docker context."
            )

        return None

    def _log_path(self, image: DockerImage) -> Path:
        """Return the log file path for a Docker image build.

        Args:
            image: DockerImage to get log path for

        Returns:
            Path to logs/build/docker-{name}.log
        """
        return self.repo_root / "logs" / "build" / f"docker-{image.name}.log"

    def _make_failed(
        self,
        image: DockerImage,
        start_time: datetime,
        error_message: str,
        duration: Optional[float] = None,
        build_stderr: Optional[str] = None,
    ) -> DockerBuildResult:
        """Create a failed DockerBuildResult."""
        end_time = datetime.now()
        return DockerBuildResult(
            image=image,
            success=False,
            cached=False,
            duration=duration if duration is not None else (end_time - start_time).total_seconds(),
            error_message=error_message,
            start_time=start_time,
            end_time=end_time,
            build_stderr=build_stderr,
            log_path=self._log_path(image),
        )

    def _make_cache_hit(
        self,
        image: DockerImage,
        start_time: datetime,
        output_path: Path,
    ) -> DockerBuildResult:
        """Create a cache-hit DockerBuildResult.

        Reads image ID from sidecar file (fast) instead of decompressing
        the entire multi-GB archive to find manifest.json at the end.
        Falls back to archive manifest, then daemon digest.
        """
        duration = (datetime.now() - start_time).total_seconds()
        image_id = (
            self._load_image_id(image)
            or self._get_archive_image_id(output_path)
            or self._get_image_digest(image.full_name)
        )
        return DockerBuildResult(
            image=image,
            success=True,
            cached=True,
            duration=duration,
            image_id=image_id,
            output_path=output_path if output_path.exists() else None,
            start_time=start_time,
            end_time=datetime.now(),
        )

    def _compose_build_args(self, image: DockerImage) -> list:
        """Assemble the docker build argument list for an image."""
        args = [
            "docker", "build",
            "--progress=plain",
            # Disable provenance attestations to avoid OCI manifest list creation.
            # With the containerd image store, BuildKit wraps attested builds in a
            # manifest list.  Parallel builds then race on the tag-naming step,
            # producing spurious "image already exists" errors.
            "--provenance=false",
            "-t", image.full_name,
            "-f", str(image.dockerfile),
        ]
        # WHEELS_HASH busts uv's layer cache when wheel content changes
        if image.wheel_dependencies:
            wheels_hash = self._compute_wheels_hash(image.wheel_dependencies)[:16]
            args.extend(["--build-arg", f"WHEELS_HASH={wheels_hash}"])
        else:
            args.extend(["--build-arg", "WHEELS_HASH=none"])
        if self._dockerfile_uses_arg(image.dockerfile, "BUILD_TIMESTAMP"):
            args.extend(["--build-arg", f"BUILD_TIMESTAMP={self._get_build_timestamp()}"])
        if self.force:
            args.append("--no-cache")
        args.append(str(image.context))
        return args

    def _export_image_to_archive(
        self,
        image: DockerImage,
        output_path: Path,
        profile: Optional[dict],
    ) -> None:
        """Export a built image to a .tar.gz archive via docker save | pigz.

        Uses adaptive compression: if a previous build showed <20% compression
        benefit, uses pigz -0 (store-only) to skip CPU-intensive compression.
        Computes SHA256 checksum inline during the pipe to avoid a second full read.

        After writing the archive, reads the config digest from its manifest and
        updates the sidecar .image_id file. The archive config digest is the
        authoritative image ID — it is what workers see after ``docker load``.
        On containerd-backed Docker, daemon inspect returns the OCI index digest
        which differs from the config digest.

        Silently continues without an archive on failure (build still succeeds).
        """
        try:
            _require_pigz()
            compression_level = self._get_compression_level(image)

            sha256_hash = hashlib.sha256()
            with open(output_path, "wb") as f:
                save_proc = subprocess.Popen(
                    ["docker", "save", image.full_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                pigz_proc = subprocess.Popen(
                    ["pigz", f"-{compression_level}"],
                    stdin=save_proc.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                assert save_proc.stdout is not None
                save_proc.stdout.close()

                # Stream compressed output to file while computing SHA256 inline
                assert pigz_proc.stdout is not None
                while True:
                    chunk = pigz_proc.stdout.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    sha256_hash.update(chunk)

                pigz_proc.wait(timeout=300)
                save_proc.wait(timeout=10)

                if save_proc.returncode == 0 and pigz_proc.returncode == 0:
                    # Write checksum from inline computation (no second read pass)
                    checksum_path = output_path.parent / (
                        output_path.stem.replace(".tar", "") + ".sha256"
                    )
                    checksum_path.write_text(sha256_hash.hexdigest())
                    if profile is not None:
                        profile["steps"]["checksum"] = 0.0  # inline, no extra cost

                    # Publish to the shared NeoAxios Docker image cache so any
                    # downstream provisioner can find this archive without
                    # having to own the Dockerfile. Same pattern as the wheel
                    # cache: hardlink when possible, copy on EXDEV, silent no-op
                    # when the cache is disabled.
                    self._link_archive_to_cache(output_path, checksum_path)

                    # Save compression profile for adaptive level selection
                    compressed_size = output_path.stat().st_size
                    self._save_compression_profile(image, compressed_size)

                    # Update sidecar with archive config digest (authoritative ID)
                    archive_id = self._get_archive_image_id(output_path)
                    if archive_id:
                        self._save_image_id(image, archive_id)
                else:
                    output_path.unlink()
        except Exception:
            logger.warning(f"Archive export failed for {image.full_name}; continuing without cached archive", exc_info=True)
            if output_path.exists():
                output_path.unlink()

    def _run_docker_pipeline(
        self,
        image: DockerImage,
        start_time: datetime,
        output_path: Path,
        cache_key: str,
        provisional_key: bool = False,
    ) -> DockerBuildResult:
        """Run the full docker build → export pipeline for one image.

        Step 1: docker build (registers in daemon).
        Step 2: Get image ID from daemon (fast).
        Step 3: Save cache key + image ID sidecar (fast).
        Step 4: Queue archive export to background thread (non-blocking).

        If all Docker layers were CACHED and archive exists, skips re-archiving.
        Archive export is decoupled from the build so downstream images can start
        building immediately without waiting for multi-GB compression.
        """
        _profiling = os.environ.get("NEOAXIOS_BUILD_PROFILE") == "1"
        _t0 = time.monotonic()
        _profile: dict = {"image": image.full_name, "steps": {}}

        env = os.environ.copy()
        env["DOCKER_BUILDKIT"] = "1"
        build_args = self._compose_build_args(image)

        # Remove existing image tag to prevent BuildKit containerd
        # "already exists" error when overwriting a tagged image.
        self._remove_existing_tag(image.full_name)

        _t_build = time.monotonic()
        build_result = subprocess.run(
            build_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=600,
            env=env,
        )
        full_stderr = build_result.stderr.decode(errors="replace") if build_result.stderr else ""

        if _profiling:
            _profile["steps"]["docker_build"] = round(time.monotonic() - _t_build, 3)
            (_PROFILE_LOG.parent / f"docker-build-plain-{image.name}.log").write_text(full_stderr)

        if build_result.returncode != 0:
            error_msg = full_stderr[:500] if full_stderr else "Build failed"
            return self._make_failed(image, start_time, error_msg, build_stderr=full_stderr)

        # Save cache key immediately so downstream builds can proceed
        self._save_cache_key(image, cache_key, provisional=provisional_key)

        # Skip archive export if all Docker layers were served from cache
        # AND the archive file already exists on disk from a prior build
        if self._all_layers_cached(full_stderr) and output_path.exists():
            logger.info(f"All layers cached for {image.full_name} — reusing existing archive")
            # Read image ID from existing archive — the archive config digest is
            # the authoritative ID that workers see after docker load. On
            # containerd-backed Docker, daemon inspect returns the OCI index
            # digest which differs from the config digest.
            image_id = self._get_archive_image_id(output_path) or self._get_image_digest(image.full_name)
            if image_id:
                self._save_image_id(image, image_id)
            if _profiling:
                _profile["steps"]["docker_save_pigz"] = 0.0
                _profile["steps"]["skipped_archive"] = True
                _profile["total"] = round(time.monotonic() - _t0, 3)
                with open(_PROFILE_LOG, "a") as _pf:
                    _pf.write(json.dumps(_profile) + "\n")
        else:
            # Use daemon ID as provisional — _export_image_to_archive() will
            # overwrite the sidecar with the archive config digest once the
            # archive is written.
            image_id = self._get_image_digest(image.full_name)
            if image_id:
                self._save_image_id(image, image_id)

            # Queue archive export to background thread — does not block
            # downstream image builds since they reference daemon image, not archive.
            # The export updates the sidecar with the archive config digest;
            # _flush_pending_exports() patches result.image_id afterward.
            _profile_ref = _profile if _profiling else None
            future = self._export_executor.submit(
                self._export_image_to_archive, image, output_path, _profile_ref,
            )

        end_time = datetime.now()
        result = DockerBuildResult(
            image=image,
            success=True,
            cached=False,
            duration=(end_time - start_time).total_seconds(),
            image_id=image_id,
            # Always return the expected output_path — archive may be written
            # by a background thread (deferred export) or already exist on disk
            output_path=output_path,
            start_time=start_time,
            end_time=end_time,
            build_stderr=full_stderr,
            log_path=self._log_path(image),
        )

        if not (self._all_layers_cached(full_stderr) and output_path.exists()):
            with self._pending_exports_lock:
                self._pending_exports.append((future, image, _profile_ref, result))

        return result

    @auto_trace(logger)
    def build(self, image: DockerImage) -> DockerBuildResult:
        """Build a single Docker image directly to tar.gz.

        Builds using docker buildx with output piped directly to pigz,
        creating a tar.gz file in docker-images/ without registering
        in the local Docker daemon.

        Args:
            image: DockerImage to build

        Returns:
            DockerBuildResult with success status, duration, output_path, and cache info
        """
        start_time = datetime.now()
        output_path = self._get_output_path(image)

        dockerignore_error = self._check_dockerignore(image)
        if dockerignore_error:
            return self._make_failed(image, start_time, f".dockerignore error: {dockerignore_error}", duration=0)

        cache_key, provisional_key = self.compute_cache_key(image)
        if not self.force and not image.always_rebuild and self._has_cache(image, cache_key):
            return self._make_cache_hit(image, start_time, output_path)

        try:
            self.populate_wheels(image)
        except Exception as e:
            return self._make_failed(image, start_time, f"Failed to populate wheels: {e}")

        try:
            result = self._run_docker_pipeline(image, start_time, output_path, cache_key, provisional_key)
            # Flush pending exports when build() is called standalone (not via build_all)
            self._flush_pending_exports()
            return result
        except subprocess.TimeoutExpired:
            return self._make_failed(image, start_time, "Build timed out after 600 seconds")
        except Exception as e:
            return self._make_failed(image, start_time, str(e))
        finally:
            self.cleanup_wheels(image)

    def _get_archive_image_id(self, archive_path: Path) -> Optional[str]:
        """Read the image ID from a Docker archive's manifest.json.

        NOTE: Build tools cannot depend on downstream neoaxios-* packages due
        to bootstrap constraints (see pyproject.toml), so this hashing logic
        is implemented locally rather than imported.

        Args:
            archive_path: Path to .tar.gz Docker archive

        Returns:
            Image ID (sha256:...) if found, None otherwise
        """
        if not archive_path.exists():
            return None

        try:
            return self._read_manifest_image_id(archive_path)
        except Exception:
            logger.warning(f"Failed to read image ID from archive manifest: {archive_path}", exc_info=True)
            return None

    @staticmethod
    def _read_manifest_image_id(archive_path: Path) -> Optional[str]:
        """Extract image *config* digest from the archive's legacy manifest.json.

        Returns the digest that workers' Docker daemons assign as the
        image ID after ``docker load`` — which is the **config blob**
        referenced by ``manifest.json[0].Config``, NOT the OCI
        ``index.json.manifests[0].digest``.  On newer containerd-backed
        daemons the two happen to coincide for single-platform archives,
        but on the Debian-stable daemons our test workers run they
        diverge, and ``docker inspect`` / ``docker_client.images.get().id``
        reports the config digest.  Publishing the config digest to the
        validation manifest ensures the E2E image-identity tests compare
        against the value the worker actually reports.
        """
        import json
        import tarfile

        def _parse_legacy_manifest(tar: tarfile.TarFile) -> Optional[str]:
            for member in tar:
                if member.name == "manifest.json":
                    manifest_file = tar.extractfile(member)
                    if manifest_file:
                        manifest = json.loads(manifest_file.read())
                        if manifest and len(manifest) > 0:
                            config_path = manifest[0].get("Config", "")
                            if config_path.startswith("blobs/sha256/"):
                                return "sha256:" + config_path.split("/")[-1]
                            elif config_path.startswith("sha256:"):
                                return config_path
                            else:
                                return "sha256:" + config_path.replace(".json", "")
                    return None
            return None

        _require_pigz()

        with open(archive_path, "rb") as stdin_fh:
            pigz_proc = subprocess.Popen(
                ["pigz", "-dc"],
                stdin=stdin_fh,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                with tarfile.open(fileobj=pigz_proc.stdout, mode="r|") as tar:
                    return _parse_legacy_manifest(tar)
            finally:
                if pigz_proc.stdout:
                    pigz_proc.stdout.close()
                pigz_proc.wait()

    @auto_trace(logger)
    def build_all(
        self, images: list[DockerImage], parallel: bool = True
    ) -> list[DockerBuildResult]:
        """Build multiple images respecting dependency order.

        Independent images are built in parallel when parallel=True.

        Args:
            images: List of DockerImage objects (should be sorted by dependency)
            parallel: Whether to build independent images in parallel

        Returns:
            List of DockerBuildResult objects
        """
        # Prefetch all digests in single docker call (reduces O(n) to O(1) subprocess calls)
        self.prefetch_digests(images)

        if not parallel:
            results = [self.build(img) for img in images]
            self._flush_pending_exports()
            return results

        # Group images by dependency level
        levels = self._group_by_level(images)
        results = []
        total = len(images)

        # Use Rich progress bar if available
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task(f"Building {total} images...", total=total)
                results = self._build_levels(
                    levels, advance_progress=lambda n: progress.advance(task, n),
                )
                # Wait for deferred archive exports inside the progress context
                # so the timer keeps running and the user sees actual completion
                progress.update(task, description="Archiving images...")
                self._flush_pending_exports()
        else:
            results = self._build_levels(levels)
            self._flush_pending_exports()

        return results

    def _build_levels(
        self,
        levels: list[list[DockerImage]],
        advance_progress: Optional[Callable[[int], None]] = None,
    ) -> list[DockerBuildResult]:
        """Execute a build plan level-by-level with optional progress reporting.

        A failure only cascades to images that transitively depend on the
        failed image.  Independent images in later levels still build.

        Args:
            levels: Dependency-ordered groups of images (each group is independent).
            advance_progress: Optional callable that receives the count of images
                just completed; used to update a Rich progress bar.

        Returns:
            List of DockerBuildResult objects for all images.
        """
        results: list[DockerBuildResult] = []
        failed_names: set[str] = set()

        for level_idx, level_images in enumerate(levels):
            buildable, skipped = self._partition_by_failed_deps(
                level_images, failed_names,
            )
            for img in skipped:
                results.append(self._make_skipped(img))
                failed_names.add(img.name)
                if advance_progress:
                    advance_progress(1)

            if not buildable:
                continue

            level_results = (
                [self.build(buildable[0])]
                if len(buildable) == 1
                else self._build_parallel(buildable)
            )
            results.extend(level_results)
            for r in level_results:
                if not r.success:
                    failed_names.add(r.image.name)
            if advance_progress:
                advance_progress(len(level_results))

            # Bless parents referenced by remaining levels so BuildKit's
            # FROM-tag resolver accepts them (see _bless_parents_for_remaining_levels).
            remaining = levels[level_idx + 1:]
            if remaining:
                self._bless_parents_for_remaining_levels(level_results, remaining)

        return results

    def _partition_by_failed_deps(
        self,
        images: list[DockerImage],
        failed_names: set[str],
    ) -> tuple[list[DockerImage], list[DockerImage]]:
        """Split images into buildable and skipped based on failed dependencies."""
        buildable, skipped = [], []
        for img in images:
            has_failed_dep = (
                img.base_image
                and self._normalize_name(img.base_image) in failed_names
            ) or any(
                self._normalize_name(dep) in failed_names
                for dep in img.image_dependencies
            )
            (skipped if has_failed_dep else buildable).append(img)
        return buildable, skipped

    def _make_skipped(self, image: DockerImage) -> DockerBuildResult:
        """Create a result for an image skipped due to dependency failure."""
        return DockerBuildResult(
            image=image,
            success=False,
            cached=False,
            duration=0,
            error_message="Skipped due to dependency failure",
            log_path=self._log_path(image),
        )

    def _build_parallel(self, images: list[DockerImage]) -> list[DockerBuildResult]:
        """Build multiple images in parallel.

        Args:
            images: List of independent DockerImage objects

        Returns:
            List of DockerBuildResult objects
        """
        results = []
        # Use ThreadPoolExecutor - Docker builds are subprocess/I/O bound, not CPU bound
        # ProcessPoolExecutor would fail due to pickling issues with bound methods
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.build, img): img for img in images}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    img = futures[future]
                    results.append(
                        DockerBuildResult(
                            image=img,
                            success=False,
                            cached=False,
                            duration=0,
                            error_message=str(e),
                            log_path=self._log_path(img),
                        )
                    )
        return results

    def _group_by_level(self, images: list[DockerImage]) -> list[list[DockerImage]]:
        """Group images by dependency level for parallel execution.

        Images at the same level have no dependencies on each other.

        Args:
            images: List of DockerImage objects (sorted by dependency)

        Returns:
            List of levels, each containing independent images
        """
        levels: list[list[DockerImage]] = []
        built: set[str] = set()

        remaining = list(images)
        while remaining:
            # Find images whose dependencies are all built
            level = []
            still_remaining = []

            for img in remaining:
                # A dependency is "satisfied" if it's already built OR it's
                # not a local image (external/pre-loaded via required_images
                # cache resolver).  Without the `not _is_local_image` branch,
                # every image whose deps include an external parent like
                # ``neoaxios/base:latest`` can never be placed — no local
                # build ever adds ``base`` to ``built`` — and the whole DAG
                # drops into the circular-dependency fallback, destroying
                # level ordering and forcing intra-repo parents to race
                # with their children.
                deps_satisfied = all(
                    self._normalize_name(dep) in built
                    or not self._is_local_image(dep, images)
                    for dep in img.image_dependencies
                )
                base_satisfied = not img.base_image or self._normalize_name(
                    img.base_image
                ) in built or not self._is_local_image(img.base_image, images)

                if deps_satisfied and base_satisfied:
                    level.append(img)
                else:
                    still_remaining.append(img)

            if not level:
                # Circular dependency or missing - add remaining as single level
                level = still_remaining
                still_remaining = []

            levels.append(level)
            built.update(img.name for img in level)
            remaining = still_remaining

        return levels

    def _is_local_image(self, image_name: str, images: list[DockerImage]) -> bool:
        """Check if image name refers to a local image in the build list.

        An image is considered local if:
        - It has a registry prefix matching a local image's registry (e.g., neoaxios/)
        - Images without registry prefix (e.g., python:3.12) are external (Docker Hub)
        """
        # Extract registry from image name (if any)
        if "/" in image_name:
            # Has registry prefix (e.g., "neoaxios/python:3.12-slim")
            registry = image_name.split("/")[0]
            normalized = self._normalize_name(image_name)
            # Match by registry AND name
            return any(
                img.registry == registry and img.name == normalized
                for img in images
            )
        else:
            # No registry prefix (e.g., "python:3.12-slim-bookworm")
            # This is an external image from Docker Hub
            return False

    def _normalize_name(self, name: str) -> str:
        """Normalize image name (strip registry and tag)."""
        if ":" in name:
            name = name.split(":")[0]
        if "/" in name:
            name = name.split("/")[-1]
        return name

    @staticmethod
    def _remove_existing_tag(image_name: str) -> None:
        """Remove an existing image tag before building.

        Docker BuildKit with the containerd image store refuses to overwrite
        existing image tags, producing 'image already exists' errors. Removing
        the tag before building prevents this.  Only the tag is removed — shared
        layers remain in the BuildKit cache and are reused on the next build.
        """
        subprocess.run(
            ["docker", "rmi", image_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

    def _is_local_base_image(self, image_name: str) -> bool:
        """Check if base image is a local image we build (vs external like Docker Hub).

        Local images have our registry prefix (neoaxios/, neoaxios/).
        External images have no prefix (alpine:3.19) or external prefixes.

        Args:
            image_name: Full image name (e.g., "neoaxios/base:latest" or "alpine:3.19")

        Returns:
            True if local image, False if external
        """
        # Known local registries
        local_registries = {"neoaxios", "myapp"}

        if "/" in image_name:
            registry = image_name.split("/")[0]
            return registry in local_registries
        else:
            # No registry prefix = external (Docker Hub)
            return False

    def needs_rebuild(self, image: DockerImage) -> bool:
        """Check if image needs rebuilding based on cache key.

        Args:
            image: DockerImage to check

        Returns:
            True if rebuild needed, False if cached
        """
        if self.force or image.always_rebuild:
            return True

        cache_key, _ = self.compute_cache_key(image)
        return not self._has_cache(image, cache_key)

    @auto_trace(logger)
    def _hash_context_files(self, image: DockerImage) -> str:
        """Hash all files in the Docker build context directory.

        Walks the context directory, hashes each file's relative path and
        content in sorted order for deterministic output.  This ensures that
        changes to any context file (e.g. pgbouncer.ini, entrypoint.sh)
        invalidate the build cache correctly.

        Args:
            image: DockerImage whose context to hash

        Returns:
            64-character hex SHA256 of all context files
        """
        ctx = hashlib.sha256()
        context_dir = image.context

        if not context_dir.is_dir():
            return ctx.hexdigest()

        # Collect all files, sorted by relative path for determinism
        files = sorted(
            p for p in context_dir.rglob("*") if p.is_file()
        )

        for file_path in files:
            rel = file_path.relative_to(context_dir)
            ctx.update(f"file:{rel}\n".encode())
            try:
                ctx.update(file_path.read_bytes())
            except OSError:
                ctx.update(b"<unreadable>")

        return ctx.hexdigest()

    def compute_cache_key(self, image: DockerImage) -> tuple[str, bool]:
        """Compute SHA256 cache key from build context, config, and wheels.

        Cache key components:
            - All files in the build context directory
            - docker.yaml content (if exists)
            - Parent image digest
            - Wheel dependencies hash

        Args:
            image: DockerImage to compute key for

        Returns:
            Tuple of (64-character hex SHA256, provisional flag).
            provisional=True when parent key file was missing and name fallback
            was used — these keys must not be persisted to avoid false cache
            misses on subsequent runs.
        """
        hasher = hashlib.sha256()
        provisional = False

        # 1. Build context files (includes Dockerfile, config files, scripts)
        context_hash = self._hash_context_files(image)
        hasher.update(b"context:")
        hasher.update(context_hash.encode())

        # 2. docker.yaml content (hashed separately since it may live outside context)
        docker_yaml = image.path / "docker.yaml"
        if docker_yaml.exists():
            hasher.update(b"docker_yaml:")
            hasher.update(docker_yaml.read_bytes())

        # 3. Parent image handling
        # For LOCAL base images: use their stored cache key (content-based, deterministic)
        # For EXTERNAL base images: use name only (stable identifier)
        #
        # DO NOT use Docker daemon digest - it's unstable due to OCI vs legacy format issues.
        # On containerd-backed Docker, `docker inspect` returns OCI index digest which differs
        # from the legacy config digest in archives, causing cache key instability.
        if image.base_image:
            if self._is_local_base_image(image.base_image):
                parent_name = self._normalize_name(image.base_image)
                parent_cache_file = self._docker_cache_dir / f"{parent_name}.key"
                if parent_cache_file.exists():
                    parent_key = parent_cache_file.read_text().strip()
                    hasher.update(b"parent_key:")
                    hasher.update(parent_key.encode())
                else:
                    # Parent key missing — use name as fallback but mark as provisional.
                    # Provisional keys are not persisted by _save_cache_key() to prevent
                    # false cache misses when the parent key becomes available on the next run.
                    hasher.update(b"parent_name:")
                    hasher.update(image.base_image.encode())
                    provisional = True
            else:
                # External base: use name only (stable across builds)
                hasher.update(b"parent_name:")
                hasher.update(image.base_image.encode())

        # 4. Wheel dependencies hash
        if image.wheel_dependencies:
            wheel_hash = self._compute_wheels_hash(image.wheel_dependencies)
            hasher.update(b"wheels:")
            hasher.update(wheel_hash.encode())

        return hasher.hexdigest(), provisional

    @auto_trace(logger)
    def prefetch_digests(self, images: list[DockerImage]) -> None:
        """Prefetch digests for all images and their bases in a single docker call.

        This reduces cache checking from O(n) subprocess calls to O(1) by batching
        all docker inspect queries into a single command.

        Args:
            images: List of DockerImage objects to prefetch digests for
        """
        import json

        # Collect all unique image names to query
        names_to_query: set[str] = set()
        for img in images:
            names_to_query.add(img.full_name)
            if img.base_image:
                names_to_query.add(img.base_image)

        if not names_to_query:
            return

        # Query all images in one subprocess call
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", *sorted(names_to_query)],
                capture_output=True,
                text=True,
                timeout=30,  # Longer timeout for batch query
            )
            # Parse JSON even on partial failure (some images may not exist)
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for item in data:
                        # Map both full name and repo tags to digest
                        digest = item.get("Id")
                        for tag in item.get("RepoTags", []):
                            self._digest_cache[tag] = digest
                except json.JSONDecodeError:
                    logger.warning(
                        "Failed to parse docker inspect JSON output; digest cache not populated",
                        exc_info=True,
                    )
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            logger.warning(
                "docker inspect subprocess failed; falling back to per-image queries",
                exc_info=True,
            )

        # Mark missing images as None in cache
        for name in names_to_query:
            if name not in self._digest_cache:
                self._digest_cache[name] = None

    def _get_image_digest(self, image_name: str) -> Optional[str]:
        """Get Docker image digest (uses cache if prefetched)."""
        # Use cached result if available
        if image_name in self._digest_cache:
            return self._digest_cache[image_name]

        # Fallback to individual query
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image_name, "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                digest = result.stdout.strip()
                self._digest_cache[image_name] = digest
                return digest
            self._digest_cache[image_name] = None
            return None
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _find_wheels(self, wheel_prefix: str) -> list[Path]:
        """Resolve wheel paths for a dependency prefix across all sources.

        Looks up matching ``{prefix}*.whl`` files in two places, in this order:

            1. The repo-local ``dist/`` directory (``self.dist_dir``) — wheels
               produced by the current repo's own build. Local wins so a repo
               rebuilding its own package never accidentally links a stale copy
               from the shared cache.
            2. The shared NeoAxios wheel cache (``$NEOAXIOS_WHEEL_CACHE``) —
               wheels published by other repos' ``make build`` invocations.
               This is what turns cross-repo foundation deps (e.g. a downstream
               Docker image needing ``neoaxios-secure-config``) into a zero-
               friction lookup instead of a build failure.

        Results are de-duplicated by filename: if the same wheel exists in
        both locations (common when the cache hardlinked from local dist),
        we only return the first match.

        Args:
            wheel_prefix: Package name (hyphenated or underscored — gets
                          normalized to underscores for wheel filename match).

        Returns:
            List of Path objects. Empty if no wheels match anywhere.
        """
        normalized = wheel_prefix.replace("-", "_")
        seen: set[str] = set()
        results: list[Path] = []

        def _add(wheel: Path) -> None:
            if wheel.name not in seen:
                seen.add(wheel.name)
                results.append(wheel)

        for wheel in self.dist_dir.glob(f"{normalized}*.whl"):
            _add(wheel)

        # Shared cache is branch-namespaced.  Search order: current-branch
        # subdir first, then main/ as the approved fallback so every
        # worktree still finds foundation wheels canonical to main.
        cache_root = _shared_wheel_cache(self.repo_root)
        if cache_root is not None:
            from neoaxios.build.cache_namespace import wheel_cache_read_dirs
            for read_dir in wheel_cache_read_dirs(cache_root, self.repo_root):
                for wheel in read_dir.glob(f"{normalized}*.whl"):
                    _add(wheel)

        return results

    def _compute_wheels_hash(self, wheel_deps: list[str]) -> str:
        """Compute hash of wheel dependencies based on actual content.

        Uses SHA256 of wheel file content for reliable cache invalidation.
        This ensures Docker images are rebuilt when wheel content changes,
        even if filename and size remain the same. Considers both the repo-
        local ``dist/`` and the shared NeoAxios wheel cache — keeps the
        Docker cache in lockstep with cross-repo wheel updates.
        """
        hasher = hashlib.sha256()
        for dep in sorted(wheel_deps):
            for wheel in self._find_wheels(dep):
                hasher.update(wheel.name.encode())
                # Hash actual wheel content for reliable invalidation
                try:
                    with open(wheel, "rb") as f:
                        for chunk in iter(lambda: f.read(8192), b""):
                            hasher.update(chunk)
                except OSError:
                    # Wheel file unreadable - include marker to invalidate cache
                    hasher.update(b"<unreadable>")
        return hasher.hexdigest()

    def _has_cache(self, image: DockerImage, cache_key: str) -> bool:
        """Check if cache exists for image.

        Cache is valid when:
        1. The Docker image exists in local daemon
        2. The cache key matches (Dockerfile/wheels unchanged)

        Args:
            image: DockerImage to check
            cache_key: Computed cache key

        Returns:
            True if cached image exists and is valid
        """
        # Check if image exists (use digest cache if prefetched)
        digest = self._get_image_digest(image.full_name)
        if digest is None:
            return False

        # Check if cache key matches
        cache_file = self._docker_cache_dir / f"{image.name}.key"
        if cache_file.exists():
            stored_key = cache_file.read_text().strip()
            return stored_key == cache_key

        return False

    def _save_cache_key(self, image: DockerImage, cache_key: str, *, provisional: bool = False) -> None:
        """Save cache key for image.

        Args:
            image: DockerImage to save key for
            cache_key: Computed cache key
            provisional: If True, key was computed with fallback (parent key missing).
                         Provisional keys are not persisted to prevent false cache
                         misses when the parent key becomes available later.
        """
        if provisional:
            logger.debug(f"Skipping cache key save for {image.full_name} — provisional key (parent key was missing)")
            return
        cache_file = self._docker_cache_dir / f"{image.name}.key"
        cache_file.write_text(cache_key)

    def _save_image_id(self, image: DockerImage, image_id: str) -> None:
        """Save image ID to sidecar file for fast cache-hit lookups.

        Stores the archive config digest — the authoritative ID that workers
        see after ``docker load``. This avoids decompressing multi-GB archives
        just to read manifest.json on subsequent cache hits.
        """
        sidecar = self._docker_cache_dir / f"{image.name}.image_id"
        sidecar.write_text(image_id)

    def _load_image_id(self, image: DockerImage) -> Optional[str]:
        """Load image ID from sidecar file.

        Returns the archive config digest, or None if sidecar missing.
        """
        sidecar = self._docker_cache_dir / f"{image.name}.image_id"
        if sidecar.exists():
            return sidecar.read_text().strip()
        return None

    @staticmethod
    def _all_layers_cached(build_stderr: str) -> bool:
        """Detect whether all Docker build layers were served from cache.

        Parses BuildKit --progress=plain output. Identifies step numbers
        that are metadata/export, then checks if any real build step
        actually executed (DONE with non-zero time).

        Args:
            build_stderr: Full stderr from docker build --progress=plain

        Returns:
            True if no build step actually executed (all served from cache)
        """
        import re
        # First pass: identify step numbers that are metadata/export/internal
        excluded_steps: set[str] = set()
        has_cached = False
        for line in build_stderr.splitlines():
            m = re.match(r"^#(\d+)\s+", line)
            if not m:
                continue
            step_id = m.group(1)
            if "[internal]" in line or "exporting" in line or "resolve" in line or " FROM " in line:
                excluded_steps.add(step_id)
            if "CACHED" in line:
                has_cached = True

        # Second pass: check if any non-excluded step actually ran
        for line in build_stderr.splitlines():
            m = re.match(r"^#(\d+)\s+DONE\s+(\d+\.?\d*)s", line)
            if m:
                step_id, step_time = m.group(1), float(m.group(2))
                if step_id not in excluded_steps and step_time > 0.0:
                    return False  # Real build step executed
        return has_cached  # Must have at least one CACHED marker

    def _get_compression_level(self, image: DockerImage) -> int:
        """Get pigz compression level for an image.

        Uses adaptive compression: reads the profile from a previous build.
        If the previous compressed/uncompressed ratio showed <20% savings,
        uses level 0 (store-only) to skip CPU-intensive compression.

        Returns:
            pigz compression level (0=store, 1=fast, default=1)
        """
        profile_file = self._docker_cache_dir / f"{image.name}.compression"
        if profile_file.exists():
            try:
                data = json.loads(profile_file.read_text())
                ratio = data.get("ratio", 0.0)
                # If compression saved less than 20%, use store-only
                if ratio > 0.80:
                    logger.info(f"Using pigz -0 (store-only) for {image.full_name} — previous ratio {ratio * 100:.1f}%")
                    return 0
            except (json.JSONDecodeError, KeyError):
                pass
        return 1  # Default: fast compression

    def _save_compression_profile(self, image: DockerImage, compressed_size: int) -> None:
        """Save compression profile for adaptive level selection.

        Stores the compressed size. On next build, if the ratio (compressed/uncompressed)
        exceeds 0.80 (less than 20% savings), pigz switches to store-only mode.
        """
        # Estimate uncompressed size from docker image inspect
        uncompressed_size = compressed_size  # conservative default
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image.full_name, "--format", "{{.Size}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip().isdigit():
                uncompressed_size = int(result.stdout.strip())
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        ratio = compressed_size / uncompressed_size if uncompressed_size > 0 else 0.0
        profile_file = self._docker_cache_dir / f"{image.name}.compression"
        profile_file.write_text(json.dumps({
            "compressed": compressed_size,
            "uncompressed": uncompressed_size,
            "ratio": round(ratio, 4),
        }))

    def _flush_pending_exports(self) -> None:
        """Wait for all deferred archive exports to complete.

        Called at the end of build_all() and build() to ensure all archives
        are written before the build system reports completion.

        After each export finishes, re-reads the sidecar .image_id (which
        _export_image_to_archive updated with the archive config digest) and
        patches the corresponding DockerBuildResult.image_id. This ensures
        callers (e.g. _write_validation_images) see the authoritative archive
        ID, not the provisional daemon ID.

        Thread-safe: acquires lock before reading the pending list.
        """
        with self._pending_exports_lock:
            exports = list(self._pending_exports)
            self._pending_exports.clear()
        for future, image, profile, result in exports:
            try:
                future.result(timeout=600)
                # Patch result with archive config digest written by the export
                archive_id = self._load_image_id(image)
                if archive_id:
                    result.image_id = archive_id
            except Exception:
                logger.warning(f"Background archive export failed for {image.full_name}", exc_info=True)

    def _bless_parents_for_remaining_levels(
        self,
        completed_level: list[DockerBuildResult],
        remaining_levels: list[list["DockerImage"]],
    ) -> None:
        """Round-trip just-built parent images through ``docker load`` so
        BuildKit's FROM-tag resolver accepts them for subsequent levels.

        Images written to containerd via ``docker build -t`` carry a
        provenance that BuildKit's resolver rejects as not-locally-
        authoritative, causing it to query the registry for FROM-tag
        metadata — which 401s for our private refs (upstream bug
        moby/buildkit#5340).  The cross-repo cache-resolver path via
        ``docker load -i <archive>`` produces a registration the
        resolver accepts.  We reuse the same archive the build already
        writes to ``docker-images/`` to route intra-repo parents through
        that blessed path.

        A bare ``docker save | docker load`` pipe on an already-present
        image is a no-op in containerd (the manifest digest matches an
        existing content-store entry), so we ``docker rmi`` first to
        force fresh registration.

        Applied only to images in ``{neoaxios}`` that are
        referenced by ``base_image`` or ``image_dependencies`` in any
        ``remaining_levels``.  Skips successfully only; a bless failure
        is logged but does not fail the build.
        """
        if not remaining_levels:
            return

        # Names referenced (as FROM or build-order dep) by remaining builds
        referenced_parents: set[str] = set()
        for level in remaining_levels:
            for img in level:
                if img.base_image:
                    referenced_parents.add(self._normalize_name(img.base_image))
                for dep in img.image_dependencies:
                    referenced_parents.add(self._normalize_name(dep))

        if not referenced_parents:
            return

        # Claim pending exports for the images we're about to bless
        claimed: dict[str, tuple] = {}
        with self._pending_exports_lock:
            keep: list[tuple] = []
            for entry in self._pending_exports:
                _, img, _, _ = entry
                if (
                    img.registry in {"neoaxios", "myapp"}
                    and img.name in referenced_parents
                ):
                    claimed[img.full_name] = entry
                else:
                    keep.append(entry)
            self._pending_exports = keep

        for result in completed_level:
            image = result.image
            if not result.success:
                continue
            if image.registry not in {"neoaxios", "myapp"}:
                continue
            if image.name not in referenced_parents:
                continue

            # If an export is in flight for this image, wait for it
            pending = claimed.get(image.full_name)
            if pending is not None:
                try:
                    future, _, _, res = pending
                    future.result(timeout=600)
                    archive_id = self._load_image_id(image)
                    if archive_id:
                        res.image_id = archive_id
                except Exception:
                    logger.warning(
                        f"Archive export failed for {image.full_name}; "
                        f"skipping bless (child builds may fail to resolve FROM)",
                        exc_info=True,
                    )
                    continue

            archive_path = self._get_output_path(image)
            if not archive_path.exists():
                logger.warning(
                    f"Archive missing at {archive_path} for {image.full_name}; "
                    f"skipping bless"
                )
                continue

            _t0 = time.monotonic()
            try:
                subprocess.run(
                    ["docker", "rmi", image.full_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                load_result = subprocess.run(
                    ["docker", "load", "-i", str(archive_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=300,
                )
                if load_result.returncode != 0:
                    logger.warning(
                        f"docker load failed for {image.full_name}: "
                        f"{load_result.stderr.decode(errors='replace').strip()[:500]}"
                    )
                else:
                    logger.info(
                        f"Blessed {image.full_name} via archive round-trip "
                        f"({time.monotonic() - _t0:.1f}s)"
                    )
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
                logger.warning(
                    f"Bless subprocess failed for {image.full_name}: {exc}"
                )

    def populate_wheels(self, image: DockerImage) -> None:
        """Copy required wheels to the docker build context's wheels/ dir.

        Sources (in priority order): the repo-local ``dist/`` first, then the
        shared NeoAxios wheel cache (``$NEOAXIOS_WHEEL_CACHE``). De-duplicates
        by filename. See ``_find_wheels`` for the rationale.

        Args:
            image: DockerImage to populate wheels for
        """
        if not image.wheel_dependencies:
            return

        # Wheels go in context directory (where Dockerfile COPY can find them)
        wheels_dir = image.context / "wheels"

        # Clear stale wheels first to prevent using outdated cached wheels
        # from interrupted builds (fixes Docker layer cache issues)
        if wheels_dir.exists():
            shutil.rmtree(wheels_dir)
        wheels_dir.mkdir(exist_ok=True)

        for wheel_prefix in image.wheel_dependencies:
            for wheel_file in self._find_wheels(wheel_prefix):
                dest = wheels_dir / wheel_file.name
                # _find_wheels already de-dupes by filename; this guard only
                # matters when two different prefixes happen to resolve to the
                # same wheel file (rare but defensible).
                if dest.exists():
                    continue
                shutil.copy2(wheel_file, dest)

    def cleanup_wheels(self, image: DockerImage) -> None:
        """Remove wheels/ directory after build.

        Args:
            image: DockerImage to cleanup
        """
        # Clean up from context directory (where we put them)
        wheels_dir = image.context / "wheels"
        if wheels_dir.exists():
            shutil.rmtree(wheels_dir)

    @auto_trace(logger)
    def _link_archive_to_cache(
        self, archive_path: Path, checksum_path: Path
    ) -> None:
        """Publish a freshly-produced image archive to the shared cache.

        Hardlinks (or copies on EXDEV) both the ``.tar.gz`` archive and
        its matching ``.sha256`` into ``$NEOAXIOS_IMAGE_CACHE`` so any
        downstream provisioner can find them without having to build
        someone else's Dockerfile. Mirrors the semantics of
        ``BuildCoordinator._link_wheels_to_cache`` (wheel-cache side).

        No-op when:
          - ``NEOAXIOS_IMAGE_CACHE`` is unset / empty / whitespace / ``-``.
          - The source archive or checksum is missing.

        Housekeeping errors log warnings but do NOT fail the build —
        the archive already exists in the local docker-images/ dir, so
        a publish failure degrades gracefully into "not available to
        other repos" rather than breaking the current one.
        """
        cache_dir = _shared_image_cache_path(self.repo_root)
        if cache_dir is None:
            return

        if not archive_path.exists() or not checksum_path.exists():
            logger.warning(
                f"Cannot publish image to cache — missing archive "
                f"({archive_path.exists()}) or checksum ({checksum_path.exists()})"
            )
            return

        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(
                f"Cannot create shared image cache {cache_dir}; skipping publish: {exc}"
            )
            return

        for src in (archive_path, checksum_path):
            dest = cache_dir / src.name
            if dest.exists() or dest.is_symlink():
                try:
                    dest.unlink()
                except OSError as exc:
                    logger.warning(
                        f"Cannot replace existing cache entry {dest}; skipping: {exc}"
                    )
                    continue

            method = "hardlink"
            try:
                os.link(src, dest)
            except OSError:
                method = "copy"
                try:
                    shutil.copy2(src, dest)
                except Exception as copy_exc:
                    logger.warning(
                        f"Failed to publish {src.name} to {cache_dir}: {copy_exc}"
                    )
                    continue

            logger.info(
                f"Published {src.name} to shared image cache ({method})"
            )
