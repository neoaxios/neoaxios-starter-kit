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

"""Build coordinator for parallel package builds."""

import os
import shutil
import subprocess
import sys
import tomllib
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from neoaxios.build.cache import BuildCache
from neoaxios.build.dependency import build_dependency_graph, topological_sort
from neoaxios.build.models import BuildPackage, BuildResult
from neoaxios.build.ui import BuildDisplay
from neoaxios.build.utils import detect_operations, generate_summary_table, extract_error_message

from neoaxios.build._telemetry import auto_trace, get_telemetry

logger = get_telemetry(__name__)

display = BuildDisplay()


def parse_package_name(pyproject_path: Path) -> Optional[str]:
    """Parse the package name from pyproject.toml.

    Args:
        pyproject_path: Path to pyproject.toml file

    Returns:
        Package name from [project].name, or None if not found
    """
    try:
        with open(pyproject_path, 'rb') as f:
            data = tomllib.load(f)
        return data.get('project', {}).get('name')
    except Exception:
        return None


def _wheel_name_prefix(package: "BuildPackage") -> str:
    """Return the wheel-filename prefix for a package.

    Wheel filenames are ``{name}-{version}-{pyver}-{abi}-{plat}.whl`` where
    ``name`` is the pyproject ``[project].name`` with ``-`` replaced by ``_``
    (PEP 427 normalization). We use ``display_name`` when available because
    the package directory name is not guaranteed to match the PyPI-published
    name — e.g. a directory called ``neoaxios_fastapi_kit`` publishes as
    ``neoaxios-fastapi-kit``, whose wheel is ``neoaxios_fastapi_kit-*.whl``.
    """
    raw = package.display_name or package.name
    return raw.replace("-", "_")


class BuildCoordinator:
    """Orchestrates parallel package builds."""

    def __init__(
        self,
        repo_root: Path,
        max_workers: int = None,
        timeout: int = 300,
        force: bool = False,
        verbose: bool = False,
        use_cache: bool = True,
        verify_cache: bool = False,
    ):
        """Initialize build coordinator.

        Args:
            repo_root: Repository root directory
            max_workers: Maximum parallel workers (None = auto-detect optimal count)
            timeout: Per-package build timeout in seconds
            force: Force rebuild (sets NEOAXIOS_REBUILD=1, skips cache lookup but saves to cache)
            verbose: Enable verbose output
            use_cache: Enable build cache (default: True)
            verify_cache: Use paranoid content-based cache key (slower, 100% accurate)
        """
        self.repo_root = Path(repo_root).resolve()

        # Store user-specified max_workers (None = auto-detect)
        self._user_max_workers = max_workers

        # Auto-detect physical CPU cores (not hyperthreads)
        if max_workers is None:
            self.max_workers = self._get_physical_cores()
        else:
            self.max_workers = max_workers

        self.timeout = timeout
        self.force = force
        self.verbose = verbose
        self.log_dir = self.repo_root / "logs" / "build"

        # Cache configuration
        # Force skips cache lookup but still saves for subsequent builds
        self.use_cache = use_cache
        self.skip_cache_lookup = force  # Force rebuilds skip cache lookup
        self.verify_cache = verify_cache

        # Initialize build cache (always, so force builds can save artifacts)
        if self.use_cache:
            cache_dir = self.repo_root / ".build-cache"
            self.build_cache = BuildCache(cache_dir)
        else:
            self.build_cache = None

        # Track actual worker count used (set during execute_parallel)
        self._actual_workers = 0

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _get_physical_cores(self) -> int:
        """Get number of physical CPU cores (not hyperthreads).

        Returns:
            Number of physical cores, fallback to 4 if detection fails
        """
        try:
            # Try to read from /proc/cpuinfo (Linux)
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read()
                    # Count unique physical IDs and cores per socket
                    physical_ids = set()
                    cores_per_socket = 0
                    for line in content.split('\n'):
                        if line.startswith('physical id'):
                            physical_ids.add(line.split(':')[1].strip())
                        elif line.startswith('cpu cores'):
                            cores_per_socket = int(line.split(':')[1].strip())

                    if physical_ids and cores_per_socket:
                        return len(physical_ids) * cores_per_socket

            # Fallback: use half of os.cpu_count() (assumes hyperthreading)
            cpu_count = os.cpu_count()
            if cpu_count:
                return cpu_count // 2

        except Exception:
            pass

        # Final fallback
        return 4

    @auto_trace(logger)
    def discover_packages(self) -> List[BuildPackage]:
        """Discover all Python packages by pyproject.toml files.

        Returns:
            List of BuildPackage objects for all discovered packages

        Raises:
            ValueError: If no packages found
        """
        packages = []

        # Find all pyproject.toml files recursively
        pyproject_files = self.repo_root.glob("**/pyproject.toml")

        for pyproject_path in pyproject_files:
            # Skip excluded directories
            path_parts = pyproject_path.parts
            if any(excluded in path_parts for excluded in [
                "__pycache__", ".git", ".tox", ".venv", "venv", "env",
                "node_modules", ".pytest_cache", ".mypy_cache", "build", "dist"
            ]):
                continue

            # Package directory is parent of pyproject.toml
            package_dir = pyproject_path.parent
            package_name = package_dir.name

            # Parse actual package name from pyproject.toml for display
            pyproject_package_name = parse_package_name(pyproject_path)

            # Check for contract files
            has_contracts_yaml = (package_dir / "contracts.yaml").exists()
            has_manifest_yaml = (package_dir / "contracts" / "manifest.yaml").exists()

            # Create BuildPackage
            log_path = self.log_dir / f"{package_name}.log"
            metadata_path = self.log_dir / f"{package_name}.json"

            try:
                package = BuildPackage(
                    name=package_name,
                    package_dir=package_dir,
                    log_path=log_path,
                    metadata_path=metadata_path,
                    has_contracts_yaml=has_contracts_yaml,
                    has_manifest_yaml=has_manifest_yaml,
                    pyproject_path=pyproject_path,
                    display_name=pyproject_package_name,
                )
                packages.append(package)

                if self.verbose:
                    contracts = []
                    if has_contracts_yaml:
                        contracts.append("VAL")
                    if has_manifest_yaml:
                        contracts.append("PUB")
                    contract_info = f" [{'+'.join(contracts)}]" if contracts else ""
                    display.info(f"Discovered: {package.display_name}{contract_info}")

            except ValueError as e:
                if self.verbose:
                    display.error(f"Error creating BuildPackage for {pyproject_path}: {e}")
                continue

        if not packages:
            raise ValueError(f"No Python packages (pyproject.toml) found in {self.repo_root}")

        # Sort by display_name (actual package name from pyproject.toml) for consistent output
        return sorted(packages, key=lambda p: p.display_name.lower())

    @auto_trace(logger)
    def execute_build(self, package: BuildPackage) -> BuildResult:
        """Execute single package build (called by worker process).

        Builds the package using python -m build, then runs contract operations if needed.
        Uses build cache to skip rebuilds when source hasn't changed.

        Args:
            package: Package to build

        Returns:
            BuildResult with exit code, timing, and captured output
        """
        start_time = datetime.now()
        all_stdout = []
        all_stderr = []
        operations = []

        # Compute cache key if caching enabled
        cache_key = None
        if self.build_cache:
            cache_key = self.build_cache.compute_cache_key(
                package,
                paranoid=self.verify_cache
            )

            # Skip cache lookup if force rebuild requested
            if not self.skip_cache_lookup and self.build_cache.has_cache(package, cache_key):
                # Cache hit - restore from cache
                if self.build_cache.restore_from_cache(package, cache_key):
                    # Sync wheels to repo dist even on cache hit
                    # This ensures Docker builds can always find required wheels
                    self._sync_wheel_to_repo_dist(package)
                    # Publish to the shared NeoAxios wheel cache so consumer
                    # repos' pip/uv see the restored wheel via *_FIND_LINKS.
                    self._link_wheels_to_cache(package)

                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()

                    cache_key_short = cache_key[:12]
                    stdout_msg = f"♻️  Restored from cache (key: {cache_key_short}...)"
                    operations.append("cache-hit")

                    return BuildResult(
                        package=package,
                        exit_code=0,
                        duration=duration,
                        stdout=stdout_msg,
                        stderr="",
                        operations=operations,
                        start_time=start_time,
                        end_time=end_time,
                    )

        try:
            # STEP 1: Build wheel
            all_stdout.append("=== Building Wheel ===")

            # Clean old artifacts if FORCE mode
            if self.force:
                # Collect all directories to clean
                dirs_to_clean = []

                # Fixed artifact directories
                for artifact_dir in ["build", "dist"]:
                    artifact_path = package.package_dir / artifact_dir
                    if artifact_path.exists():
                        dirs_to_clean.append(artifact_path)

                # Egg-info directories (both at package root AND in src/ for src-layout)
                dirs_to_clean.extend(
                    p for p in package.package_dir.glob("*.egg-info") if p.is_dir()
                )
                dirs_to_clean.extend(
                    p for p in package.package_dir.glob("src/*.egg-info") if p.is_dir()
                )

                # Clean all directories (single implementation)
                for dir_path in dirs_to_clean:
                    shutil.rmtree(dir_path)

            # Build wheel.  Use sys.executable rather than a bare "python3"
            # lookup so the subprocess uses the interpreter that's running
            # the coordinator — critical on remote build worker hosts where
            # system python3 (/usr/bin/python3) has no `build` module but the
            # test venv does.
            process = subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--outdir", "dist/"],
                cwd=package.package_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            all_stdout.append(process.stdout)
            all_stderr.append(process.stderr)

            if process.returncode != 0:
                all_stdout.append("❌ Wheel build failed")
                # Extract error for better reporting
                error_msg = extract_error_message("\n".join(all_stderr), "\n".join(all_stdout))
                e = subprocess.CalledProcessError(process.returncode, "build")
                e.failure_stage = "wheel"
                e.error_message = error_msg
                raise e

            all_stdout.append("✅ Wheel built")
            operations.append("wheel")

            # Sync wheel to repository dist/ for downstream-consumer compatibility
            self._sync_wheel_to_repo_dist(package)
            # Publish to the shared NeoAxios wheel cache so downstream
            # pip/uv see the new wheel via *_FIND_LINKS.
            self._link_wheels_to_cache(package)

            # STEP 2: Contract validation (if contracts.yaml exists)
            if package.has_contracts_yaml:
                all_stdout.append("\n=== Contract Operations ===")
                process = subprocess.run(
                    ["make", "validate"],
                    cwd=package.package_dir,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                all_stdout.append(process.stdout)
                all_stderr.append(process.stderr)

                if process.returncode == 0:
                    all_stdout.append("✅ Contracts validated")
                    operations.append("contracts-validate")

                    # Type generation (after validation)
                    process = subprocess.run(
                        ["make", "generate"],
                        cwd=package.package_dir,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    all_stdout.append(process.stdout)
                    all_stderr.append(process.stderr)

                    if process.returncode == 0:
                        all_stdout.append("✅ Types generated")
                        operations.append("types-generate")
                    else:
                        all_stdout.append("❌ Types generation failed")
                        error_msg = extract_error_message("\n".join(all_stderr), "\n".join(all_stdout))
                        e = subprocess.CalledProcessError(process.returncode, "make generate")
                        e.failure_stage = "types-generate"
                        e.error_message = error_msg
                        raise e
                else:
                    all_stdout.append("❌ Contract validation failed")
                    error_msg = extract_error_message("\n".join(all_stderr), "\n".join(all_stdout))
                    e = subprocess.CalledProcessError(process.returncode, "make validate")
                    e.failure_stage = "contract-validate"
                    e.error_message = error_msg
                    raise e

            # STEP 3: Contract publishing (if contracts/manifest.yaml exists)
            if package.has_manifest_yaml:
                all_stdout.append("\n=== Contract Operations ===")
                process = subprocess.run(
                    ["make", "publish"],
                    cwd=package.package_dir,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                all_stdout.append(process.stdout)
                all_stderr.append(process.stderr)

                if process.returncode == 0:
                    all_stdout.append("✅ Contracts published")
                    operations.append("contracts-publish")
                else:
                    all_stdout.append("❌ Contract publishing failed")
                    error_msg = extract_error_message("\n".join(all_stderr), "\n".join(all_stdout))
                    e = subprocess.CalledProcessError(process.returncode, "make publish")
                    e.failure_stage = "contract-publish"
                    e.error_message = error_msg
                    raise e

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            result = BuildResult(
                package=package,
                exit_code=0,
                duration=duration,
                stdout="\n".join(all_stdout),
                stderr="\n".join(all_stderr),
                operations=operations,
                start_time=start_time,
                end_time=end_time,
            )

            result.save_log()
            result.save_metadata()

            # Save to cache on success
            if self.build_cache and cache_key:
                self.build_cache.save_to_cache(package, cache_key)

            return result

        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            stderr_combined = f"Build timeout after {self.timeout}s"

            result = BuildResult(
                package=package,
                exit_code=124,
                duration=self.timeout,
                stdout="\n".join(all_stdout),
                stderr=stderr_combined,
                operations=operations,
                start_time=start_time,
                end_time=end_time,
                failure_stage="timeout",
                error_message=stderr_combined,
            )

            result.save_log()
            result.save_metadata()

            return result

        except subprocess.CalledProcessError as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Extract failure info from exception (if set)
            failure_stage = getattr(e, 'failure_stage', None)
            error_message = getattr(e, 'error_message', None)

            result = BuildResult(
                package=package,
                exit_code=e.returncode,
                duration=duration,
                stdout="\n".join(all_stdout),
                stderr="\n".join(all_stderr),
                operations=operations,
                start_time=start_time,
                end_time=end_time,
                failure_stage=failure_stage,
                error_message=error_message,
            )

            result.save_log()
            result.save_metadata()

            return result

        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            stderr_combined = f"Unexpected error: {e}\n" + "\n".join(all_stderr)

            result = BuildResult(
                package=package,
                exit_code=1,
                duration=duration,
                stdout="\n".join(all_stdout),
                stderr=stderr_combined,
                operations=operations,
                start_time=start_time,
                end_time=end_time,
                failure_stage="unexpected",
                error_message=str(e),
            )

            result.save_log()
            result.save_metadata()

            return result

    @auto_trace(logger)
    def execute_parallel_by_levels(
        self,
        packages: List[BuildPackage],
        build_levels: List[List[str]],
    ) -> List[BuildResult]:
        """Execute builds in dependency-aware levels.

        Args:
            packages: List of all packages to build
            build_levels: List of build levels from topological sort

        Returns:
            List of BuildResult objects (one per package)
        """
        # Create package lookup
        package_map = {pkg.name: pkg for pkg in packages}

        # Determine optimal worker count
        if self._user_max_workers is not None:
            worker_count = min(self._user_max_workers, len(packages))
        else:
            worker_count = min(len(packages), self.max_workers)

        self._actual_workers = worker_count

        all_results = []
        completed = 0
        total_packages = len(packages)

        # Use Rich progress bar if available, otherwise simple progress
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task(
                    f"Building {total_packages} packages...",
                    total=total_packages
                )

                # Process each level sequentially, but parallelize within each level
                for level_num, level_packages in enumerate(build_levels, 1):
                    # Get BuildPackage objects for this level
                    level_pkgs = [package_map[name] for name in level_packages if name in package_map]

                    if not level_pkgs:
                        continue

                    # Build this level in parallel
                    with ProcessPoolExecutor(max_workers=worker_count) as executor:
                        futures = {
                            executor.submit(self.execute_build, pkg): pkg
                            for pkg in level_pkgs
                        }

                        for future in as_completed(futures):
                            try:
                                result = future.result()
                                all_results.append(result)
                                completed += 1
                                progress.update(task, completed=completed)

                            except KeyboardInterrupt:
                                display.info("\n\nBuild interrupted by user")
                                executor.shutdown(wait=False, cancel_futures=True)
                                sys.exit(130)

                            except Exception as e:
                                display.error(f"Error collecting result: {e}")
                                progress.update(task, completed=completed)
        else:
            # Fallback to simple progress output
            display.info(f"Building {total_packages} packages in {len(build_levels)} levels with {worker_count} workers...")

            # Process each level sequentially, but parallelize within each level
            for level_num, level_packages in enumerate(build_levels, 1):
                if self.verbose:
                    display.info(f"\n[Level {level_num}/{len(build_levels)}] Building: {', '.join(level_packages)}")

                # Get BuildPackage objects for this level
                level_pkgs = [package_map[name] for name in level_packages if name in package_map]

                if not level_pkgs:
                    continue

                # Build this level in parallel
                with ProcessPoolExecutor(max_workers=worker_count) as executor:
                    futures = {
                        executor.submit(self.execute_build, pkg): pkg
                        for pkg in level_pkgs
                    }

                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            all_results.append(result)
                            completed += 1

                            # Per-package completion lines are gated on
                            # --verbose: the summary table below reports
                            # the same ``status × display_name × duration``
                            # data in a denser form, so a default run
                            # doesn't duplicate it.  --verbose restores
                            # the line-per-package stream for slow builds
                            # where watching progress as-it-happens matters.
                            if self.verbose:
                                status = "✓" if result.success else "✗"
                                display.info(
                                    f"[{completed}/{total_packages}] {status} "
                                    f"{result.package.display_name} "
                                    f"({result.duration:.1f}s)"
                                )

                        except KeyboardInterrupt:
                            display.info("\n\nBuild interrupted by user")
                            executor.shutdown(wait=False, cancel_futures=True)
                            sys.exit(130)

                        except Exception as e:
                            display.error(f"Error collecting result: {e}")

        return all_results

    @auto_trace(logger)
    def _sync_wheel_to_repo_dist(self, package: BuildPackage) -> None:
        """Sync built wheels from package dist/ to repository root dist/.

        Copies all wheel files from package-local dist/ directory to the
        repository-level dist/ directory. Removes old wheels for the same
        package before copying to avoid version conflicts.

        Args:
            package: Package whose wheels should be synced

        Raises:
            PermissionError: If unable to copy or remove wheels due to permissions
        """
        pkg_dist = package.package_dir / "dist"
        repo_dist = self.repo_root / "dist"

        # Handle missing package dist directory
        if not pkg_dist.exists():
            logger.warning(
                "Package dist directory not found, skipping wheel sync",
                package=package.name,
                pkg_dist=str(pkg_dist),
            )
            return

        # Guard against pkg_dist == repo_dist, which happens when the
        # package lives AT the repo root (single-package projects).
        # The sync below removes "old" wheels from repo_dist before copying
        # the "new" ones from pkg_dist — if they are the same directory, we'd
        # delete the freshly-built wheel and then fail on copy. Nothing to do
        # in that case: the wheel is already where it needs to be.
        if pkg_dist.resolve() == repo_dist.resolve():
            logger.info(
                "pkg_dist is the same directory as repo_dist — wheel already at final location, skipping sync",
                package=package.name,
                dist=str(pkg_dist.resolve()),
            )
            return

        # Find wheels in package dist
        wheels = list(pkg_dist.glob("*.whl"))
        if not wheels:
            logger.warning(
                "No wheels found in package dist, skipping sync",
                package=package.name,
                pkg_dist=str(pkg_dist),
            )
            return

        # Create repo dist if not exists
        repo_dist.mkdir(parents=True, exist_ok=True)

        # Extract the wheel-name prefix. Wheel filenames use the normalized
        # project name from pyproject.toml [project].name (PEP 427: '-' → '_'),
        # NOT the directory name. display_name holds that value; fall back to
        # the dir name only when pyproject lacks a project.name.
        wheel_prefix = _wheel_name_prefix(package)

        try:
            # Remove old wheels for this package from repo dist
            old_wheels = list(repo_dist.glob(f"{wheel_prefix}-*.whl"))
            for old_wheel in old_wheels:
                logger.info(
                    "Removing old wheel from repo dist",
                    package=package.name,
                    old_wheel=old_wheel.name,
                )
                old_wheel.unlink()

            # Copy new wheels to repo dist
            for wheel in wheels:
                dest = repo_dist / wheel.name
                logger.info(
                    "Syncing wheel to repo dist",
                    package=package.name,
                    wheel=wheel.name,
                    dest=str(dest),
                )
                shutil.copy2(wheel, dest)

        except PermissionError as e:
            logger.log_error(
                e,
                message="Permission denied while syncing wheels",
                package=package.name,
                pkg_dist=str(pkg_dist),
                repo_dist=str(repo_dist),
            )
            raise

        except Exception as e:
            logger.log_error(
                e,
                message="Unexpected error syncing wheels",
                package=package.name,
                pkg_dist=str(pkg_dist),
                repo_dist=str(repo_dist),
            )
            raise

    @auto_trace(logger)
    def _link_wheels_to_cache(self, package: BuildPackage) -> None:
        """Publish freshly-produced wheels to the shared NeoAxios wheel cache.

        Hardlinks wheels from the repo ``dist/`` directory into the
        shared cache so downstream pip / uv picks them up via
        ``UV_FIND_LINKS`` / ``PIP_FIND_LINKS``. Building is publishing —
        no separate step.

        Cache resolution:
            1. ``WHEEL_CACHE`` / ``NEOAXIOS_WHEEL_CACHE`` = ``-`` → opt
               out (no publish).  ``WHEEL_CACHE`` (unprefixed alias)
               wins when both are set, so a per-project Makefile can
               override the default that shell integration auto-exports
               for the prefixed name.
            2. ``WHEEL_CACHE=/path`` or ``NEOAXIOS_WHEEL_CACHE=/path`` →
               explicit override.
            3. Default (unset):
               ``_NEO_REAL_HOME/.cache/neoaxios/.wheel-cache``
               (or ``$HOME/.cache/neoaxios/.wheel-cache`` if
               _NEO_REAL_HOME is also unset). Setting the env var is
               the *anomaly*, not the default — the cache should work
               even in shells that never sourced the project's
               integration block.

        Behavior:
            - Purges any existing ``{wheel_prefix}-*.whl`` from the cache
              before installing the new wheel, guaranteeing one wheel per
              package at any time (matters when the version string is reused
              while the content-hash changes during local development).
            - Falls back to ``shutil.copy2`` when hardlinking fails
              (``EXDEV``: cache and repo on different filesystems).
            - Cache-housekeeping errors are logged but do NOT fail the build.

        Args:
            package: Package whose wheels should be published.
        """
        from neoaxios.build.cache_namespace import resolved_wheel_cache_path

        cache_root = resolved_wheel_cache_path(self.repo_root)
        if cache_root is None:
            logger.debug(
                "wheel cache explicit opt-out (WHEEL_CACHE=- or NEOAXIOS_WHEEL_CACHE=-); "
                "skipping cache link",
                package=package.name,
            )
            return

        # Branch-namespaced cache subdirectory.  Each worktree's wheels
        # land in their own slot so parallel builds don't overwrite each
        # other; the main/ slot is the approved fallback that every
        # worktree reads from when it didn't build a package locally.
        from neoaxios.build.cache_namespace import wheel_cache_write_dir
        cache_dir = wheel_cache_write_dir(cache_root, self.repo_root)
        repo_dist = self.repo_root / "dist"

        wheel_prefix = _wheel_name_prefix(package)
        wheels = list(repo_dist.glob(f"{wheel_prefix}-*.whl"))
        if not wheels:
            logger.debug(
                "No wheels matched in repo dist; nothing to publish to cache",
                package=package.name,
                wheel_prefix=wheel_prefix,
                repo_dist=str(repo_dist),
            )
            return

        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(
                "Cannot create shared wheel cache; skipping publish",
                package=package.name,
                cache_dir=str(cache_dir),
                error=str(exc),
            )
            return

        # Purge stale wheels for this exact package before writing the fresh
        # one. Stale entries are possible whenever (a) the wheel filename is
        # unchanged because the version was not bumped, yet the content hash
        # has changed, or (b) an earlier build published a wheel that is now
        # wrong because a dep was updated. Pip's resolver picks the highest
        # compatible version; with identical versions that degenerates to
        # "whichever file is on disk" — so we make it exactly one file.
        for stale in cache_dir.glob(f"{wheel_prefix}-*.whl"):
            try:
                stale.unlink()
                logger.info(
                    "Purged stale wheel from shared cache",
                    package=package.name,
                    wheel=stale.name,
                    cache_dir=str(cache_dir),
                )
            except OSError as exc:
                logger.warning(
                    "Failed to remove stale wheel from cache; cache may be inconsistent",
                    package=package.name,
                    wheel=stale.name,
                    cache_dir=str(cache_dir),
                    error=str(exc),
                )

        # Publish each fresh wheel. Prefer hardlink (free, shares the inode
        # with repo dist so both locations stay in lockstep); copy on EXDEV.
        for wheel in wheels:
            dest = cache_dir / wheel.name
            # Hardlink refuses to clobber; remove any lingering destination.
            if dest.exists() or dest.is_symlink():
                try:
                    dest.unlink()
                except OSError as exc:
                    logger.warning(
                        "Cannot remove existing cache entry; skipping this wheel",
                        package=package.name,
                        wheel=wheel.name,
                        error=str(exc),
                    )
                    continue

            method = "hardlink"
            try:
                os.link(wheel, dest)
            except OSError as link_exc:
                # EXDEV (cross-device) or platform-level hardlink restriction.
                method = "copy"
                try:
                    shutil.copy2(wheel, dest)
                except Exception as copy_exc:
                    logger.warning(
                        "Failed to publish wheel to shared cache",
                        package=package.name,
                        wheel=wheel.name,
                        cache_dir=str(cache_dir),
                        hardlink_error=str(link_exc),
                        copy_error=str(copy_exc),
                    )
                    continue

            logger.info(
                "Published wheel to shared cache",
                package=package.name,
                wheel=wheel.name,
                cache_dir=str(cache_dir),
                method=method,
            )

    @auto_trace(logger)
    def generate_summary_report(self, results: List[BuildResult]) -> str:
        """Generate comprehensive summary report.

        Args:
            results: List of build results

        Returns:
            Formatted summary string
        """
        lines = []

        # Statistics
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful
        total_time = max((r.end_time for r in results if r.end_time), default=datetime.now()) - \
                     min((r.start_time for r in results if r.start_time), default=datetime.now())
        total_seconds = total_time.total_seconds()

        # Summary table — pass dist dir so the footer matches docker tables.
        # Trailing blank intentionally not added here; docker_summary_table
        # emits its own leading blank so the Wheels → Docker Images gap is
        # one blank line, not two.
        lines.append(generate_summary_table(results, dist_dir=self.repo_root / "dist"))

        # Failed packages detail with actionable hints
        if failed > 0:
            from neoaxios.build.utils import generate_error_hint

            lines.append("❌ Failed Packages:")
            lines.append("")
            for result in sorted(results, key=lambda r: r.package.display_name.lower()):
                if not result.success:
                    # Header
                    stage_display = f" - Failed at: {result.failure_stage.replace('-', ' ').title()}" if result.failure_stage else ""
                    lines.append(f"  {result.package.display_name} (exit code {result.exit_code}){stage_display}")

                    # Error message
                    if result.error_message:
                        lines.append(f"    ├─ Error: {result.error_message}")

                    # Log path
                    lines.append(f"    ├─ Log:   {result.package.log_path}")

                    # Actionable hint
                    hint = generate_error_hint(result.error_message, result.failure_stage)
                    if hint:
                        lines.append(f"    └─ Hint:  {hint}")
                    else:
                        lines.append(f"    └─ Hint:  Check log file for details")

                    lines.append("")


        return "\n".join(lines)
