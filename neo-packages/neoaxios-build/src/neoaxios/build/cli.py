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

"""Command-line interface for NeoAxios build system."""

import argparse
import json
import os
import sys
from pathlib import Path

# Suppress telemetry startup message in CLI output
os.environ.setdefault("LOGBOOK_QUIET", "1")

from neoaxios.build._telemetry import auto_trace, get_telemetry

from neoaxios.build.config import load_build_config
from neoaxios.build.constants import DEFAULT_DOCKER_MAX_WORKERS
from neoaxios.build.coordinator import BuildCoordinator
from neoaxios.build.dependency import build_dependency_graph, topological_sort
from neoaxios.build.docker.builder import _shared_image_cache_path
from neoaxios.build.ui import BuildDisplay

logger = get_telemetry(__name__)
display = BuildDisplay()


@auto_trace(logger)
def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Parallel Build System for NeoAxios projects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Build all packages (wheels only)
  %(prog)s --docker                 # Build wheels then Docker images
  %(prog)s docker build             # Build Docker images only
  %(prog)s --force                  # Force rebuild
  %(prog)s --max-workers 8          # Limit to 8 parallel workers
  %(prog)s --verbose                # Show detailed progress
        """
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Docker subcommand with nested subcommands
    docker_parser = subparsers.add_parser("docker", help="Docker image operations")
    docker_subparsers = docker_parser.add_subparsers(dest="docker_command", help="Docker operations")

    # docker build subcommand
    docker_build_parser = docker_subparsers.add_parser("build", help="Build Docker images")
    docker_build_parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory",
    )
    docker_build_parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_DOCKER_MAX_WORKERS,
        help=f"Maximum parallel workers (default: {DEFAULT_DOCKER_MAX_WORKERS})",
    )
    docker_build_parser.add_argument(
        "--force",
        action="store_true",
        help="Force rebuild (ignore cache)",
    )
    docker_build_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory (default: current directory)",
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum parallel workers (default: auto-detect physical cores)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Per-package build timeout in seconds (default: 300)",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force rebuild (disables cache)",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable build cache (always rebuild)",
    )

    parser.add_argument(
        "--verify-cache",
        action="store_true",
        help="Use paranoid content-based cache key (slower, 100%% accurate)",
    )

    parser.add_argument(
        "--docker",
        action="store_true",
        help="Build Docker images after building wheels",
    )

    return parser.parse_args()


# Module-level guard — ensures the cache-state banner prints at most
# once per process.  Without this, a full build (wheels → docker) would
# emit it twice (once from ``main()`` before the wheel phase, once from
# ``build_docker_images`` before the docker phase) with no change in
# state between the two prints.  Docker-subcommand-only invocations
# still get the banner via the first call.
_cache_state_printed: bool = False


@auto_trace(logger)
def _print_cache_state(repo_root: Path, phase: str) -> None:
    """Emit a one-block status of every caching layer the build touches.

    Prints the shared NeoAxios wheel cache path (resolved from
    $NEOAXIOS_WHEEL_CACHE), the repo-local dist dir, and the Docker image
    archive dir. Including this in the build output makes env-related
    failures diagnosable at a glance — if "Shared wheel cache" reads
    "<unset>" or "<disabled>", that's the cause of a downstream
    "wheel not found" error in a Docker build's ``uv pip install
    --find-links=/wheels/`` step.

    Subsequent calls within the same process are no-ops so a
    wheels-then-docker build doesn't print the banner twice.

    Args:
        repo_root: Repository root path.
        phase: "wheels", "docker", or "full" — affects which dirs are
            included on the first call.  "full" prints all four paths
            (both wheel and image dirs) in one block.
    """
    global _cache_state_printed
    if _cache_state_printed:
        return
    _cache_state_printed = True
    import os

    def _resolve_cache(primary_env, alias_env, subdir):
        """Compute the cache path the build will read/write and a one-line
        origin tag for the banner.  Defers to
        :func:`cache_namespace._resolve_cache_path` so the displayed path
        always matches what coordinator / builder will actually use.

        Returns (path_or_None, origin_label). None only for explicit opt-out
        (env=-).
        """
        from neoaxios.build.cache_namespace import (
            _resolve_cache_path,
            try_get_cache_namespace,
        )

        alias_raw = os.environ.get(alias_env, "").strip()
        primary_raw = os.environ.get(primary_env, "").strip()
        path = _resolve_cache_path(
            alias_env=alias_env,
            primary_env=primary_env,
            cache_subdir=subdir,
            repo_root=repo_root,
        )
        if path is None:
            return None, "explicit opt-out"

        # Tag the path's provenance for the banner — same precedence
        # ordering used by _resolve_cache_path.
        if alias_raw and alias_raw != "-":
            origin = f"env override ({alias_env})"
        else:
            ns = try_get_cache_namespace(repo_root)
            if ns:
                origin = f"build.yaml namespace={ns}"
            elif primary_raw and primary_raw != "-":
                origin = f"env override ({primary_env})"
            else:
                origin = "default"
        return path, origin

    wc_path, wc_origin = _resolve_cache(
        "NEOAXIOS_WHEEL_CACHE", "WHEEL_CACHE", ".wheel-cache"
    )
    if wc_path is None:
        wc_display = "<disabled>  (WHEEL_CACHE=- or NEOAXIOS_WHEEL_CACHE=-)"
    else:
        # Branch-namespaced cache: count wheels in the current branch's
        # subdir + main/ (the approved fallback).  The flat-root migration
        # path is also tallied so the banner reflects what pip can
        # actually find.
        from neoaxios.build.cache_namespace import (
            branch_namespace,
            wheel_cache_read_dirs,
        )
        namespace = branch_namespace(repo_root)
        read_dirs = wheel_cache_read_dirs(wc_path, repo_root)
        total_wheels = 0
        for d in read_dirs:
            total_wheels += len(list(d.glob("*.whl")))
        # Include flat-root wheels if any linger during migration
        total_wheels += len(list(wc_path.glob("*.whl")))
        exists_note = "exists" if wc_path.is_dir() else "MISSING — created on first publish"
        wc_display = (
            f"{wc_path}  [{exists_note}, {total_wheels} wheels, "
            f"namespace={namespace}, {wc_origin}]"
        )

    display.info(f"  Shared wheel cache:  {wc_display}")
    display.info(f"  Repo wheel dist:     {repo_root / 'dist'}")

    if phase in ("docker", "full"):
        display.info(f"  Repo image dist:     {repo_root / 'docker-images'}")

        ic_path, ic_origin = _resolve_cache(
            "NEOAXIOS_IMAGE_CACHE", "IMAGE_CACHE", ".docker-image-cache"
        )
        if ic_path is None:
            ic_display = "<disabled>  (IMAGE_CACHE=- or NEOAXIOS_IMAGE_CACHE=-)"
        else:
            archive_count = len(list(ic_path.glob("*.tar.gz"))) if ic_path.is_dir() else 0
            exists_note = "exists" if ic_path.is_dir() else "MISSING — created on first publish"
            ic_display = f"{ic_path}  [{exists_note}, {archive_count} archives, {ic_origin}]"
        display.info(f"  Shared image cache:  {ic_display}")
    display.newline()


def build_docker_images(
    repo_root: Path,
    force: bool = False,
    max_workers: int = DEFAULT_DOCKER_MAX_WORKERS,
    verbose: bool = False,
) -> int:
    """Build Docker images.

    Args:
        repo_root: Repository root path
        force: Force rebuild ignoring cache
        max_workers: Maximum parallel workers
        verbose: Enable verbose output

    Returns:
        Exit code (0 = success)
    """
    from neoaxios.build.docker import (
        DockerBuilder,
        DockerImageDiscovery,
        ImageCacheMiss,
        resolve_required_images,
    )

    _print_cache_state(repo_root, phase="docker")

    # Load config for Docker scan paths
    config = load_build_config(repo_root)

    # Resolve cross-project base images from the shared image cache
    # BEFORE discovering / building this project's own images.  Each
    # ``required_images`` entry is loaded into the local Docker daemon
    # so Dockerfiles that ``FROM`` a base image built by another project
    # resolve without rebuilding the upstream Dockerfile from source.
    # Cache miss is a hard error — populate the cache by running
    # ``make build`` in the project that owns that base image.
    #
    # ``required_images is None`` means the section was omitted; an empty
    # list means the project opted in but has no cross-project deps
    # (e.g. its Dockerfiles ``FROM`` Docker Hub images only). Both absent
    # and empty skip the resolve step; only presence-with-entries
    # actually loads archives.
    if config.required_images:
        try:
            resolved = resolve_required_images(repo_root, config.required_images)
            for r in resolved:
                display.info(
                    f"  Resolved base image: {r.ref}  ({r.archive.name})"
                )
        except ImageCacheMiss as exc:
            display.error(str(exc))
            return 1

    # Discover images.  Consumers that declared ``required_images`` — even
    # as an empty list — have opted into the ownership model: either the
    # cache resolver above already loaded their cross-repo base images,
    # or they have none to begin with.  Either way we MUST NOT let the
    # legacy built-in auto-discovery sweep the docker/base/*/ tree
    # and schedule rebuilds of images the project neither needs nor
    # owns.  The signal is presence of the section, not truthiness of
    # the list — an explicit empty ``required_images: []`` must still
    # suppress the sweep.
    skip_builtins = config.required_images is not None
    discovery = DockerImageDiscovery(
        repo_root,
        scan_paths=config.docker_scan_paths,
        skip_builtins=skip_builtins,
    )
    images = discovery.discover_all()

    if not images:
        display.info("No Docker images found")
        return 0

    # Build images
    builder = DockerBuilder(
        repo_root=repo_root,
        force=force,
        max_workers=max_workers,
    )

    results = builder.build_all(images, parallel=True)

    for result in results:
        result.save_log()

    output_dir = repo_root / "docker-images"

    # Sort results by image name for consistent display
    sorted_results = sorted(results, key=lambda r: r.image.full_name)

    # Print summary table
    display.docker_summary_table(sorted_results, output_dir)

    # Show failures
    failed = sum(1 for r in sorted_results if not r.success)
    if failed > 0:
        display.docker_failures(sorted_results)
        display.info(f"\nDocker build logs saved to: {repo_root / 'logs' / 'build'}")
        return 1

    # Write validation image IDs to JSON for E2E testing
    _write_validation_image_ids(repo_root, results, config)

    # Pull every 3rd-party image declared by this codebase and archive it
    # into docker-images/ + shared cache.  Same hash convention and
    # archive layout as 1st-party builds, so test workers can't tell
    # the difference.  Failures here raise — unlike the 1st-party builder
    # which degrades gracefully, a missing 3rd-party archive causes
    # downstream deployment to fail later with a less actionable error.
    from neoaxios.build.docker.thirdparty_puller import pull_all_thirdparty
    pull_results = pull_all_thirdparty(
        repo_root=repo_root,
        local_output_dir=output_dir,
        shared_cache_dir=_shared_image_cache_path(repo_root),
        force=force,
    )
    display.docker_pull_summary_table(pull_results, output_dir)

    # Publish deploy.yaml manifests to the shared deployments dir so
    # downstream consumers' ``_include: shared/<name>.yaml`` can resolve them.
    # Runs on every invocation (even when builds are cached) so the
    # mirror stays current with the in-repo source of truth.
    from neoaxios.build.docker.deploy_publisher import publish_deploy_manifests
    try:
        copied, up_to_date, total, shared_dir = publish_deploy_manifests(repo_root)
        if total:
            # 2-space indent matches every other trailing info line
            # (validation IDs, Build complete, etc.)
            display.info(
                f"\n  Deploy manifests published to {shared_dir}: "
                f"{copied} updated, {up_to_date} unchanged ({total} total)"
            )
    except OSError as exc:
        logger.warning(f"Cannot publish deploy manifests: {exc}")

    return 0


@auto_trace(logger)
def _write_validation_image_ids(repo_root: Path, results, config) -> None:
    """Publish the validation image IDs to the shared image cache.

    Enables downstream E2E tests to verify Docker provisioning loads the
    correct images.  The file is published alongside the image archives
    in ``$NEOAXIOS_IMAGE_CACHE`` (default
    ``~/.cache/neoaxios/.docker-image-cache/expected_validation_images.json``),
    so downstream consumers can pick it up via the same shared-cache
    pathway used to resolve the image archives themselves.  An optional
    ``config.contracts`` write path is also honored when set, for
    projects that need a project-relative copy of the same payload.

    Args:
        repo_root: Repository root path
        results: List of DockerBuildResult objects
        config: Build config (may have an optional ``contracts`` section
            that controls the secondary write path).
    """
    # Find validation image results
    validation_images = {}
    for r in results:
        if r.success and r.image_id and "validation" in r.image.name:
            # Map to full image name: neoaxios/validation-1:latest
            full_name = r.image.full_name
            validation_images[full_name] = r.image_id

    if not validation_images:
        return

    payload = json.dumps(validation_images, indent=2) + "\n"

    # Primary sink: the shared image cache, reachable by every sibling
    # repo (external runners included) via `_shared_image_cache_path()`.
    cache_dir = _shared_image_cache_path(repo_root)
    if cache_dir is not None:
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / "expected_validation_images.json").write_text(payload)
            display.file_written(
                "Validation image IDs published to shared cache",
                cache_dir / "expected_validation_images.json",
                relative_to=None,
            )
        except OSError as exc:
            logger.warning(
                f"Cannot publish validation image IDs to cache {cache_dir}: {exc}"
            )

    # Optional project-relative sink (controlled by config.contracts).
    if config.contracts is not None:
        output_file = (
            repo_root
            / config.contracts.root
            / "devtools"
            / "myapp"
            / "tests"
            / "e2e"
            / "expected_validation_images.json"
        )
        if output_file.parent.exists():
            output_file.write_text(payload)
            display.file_written(
                "Validation image IDs written to",
                output_file,
                relative_to=repo_root,
            )


def _prune_stale_wheels(repo_root: Path, packages) -> int:
    """Remove wheels in ``<repo_root>/dist/`` whose distname isn't in the
    current package set.

    Prevents ghost artifacts from accumulating in dist/ after a package is
    moved out of this codebase (or renamed/deleted).  Left in place, they poison
    downstream consumers that pip-install every wheel in dist/ — e.g.
    test workers running ``uv pip install dist/*.whl`` against a rsync'd
    copy of the repo, which fails if a stale wheel's declared dependency
    no longer resolves from the repo closure.

    Expected names are derived from ``BuildPackage.display_name`` (the
    pyproject.toml ``[project].name``) normalized to wheel-filename form
    (``-`` → ``_``).  Wheel filenames follow PEP 427: ``<dist>-<version>-
    <python>-<abi>-<platform>.whl``; the distname is everything before the
    first of the four trailing hyphen-separated fields.
    """
    dist_dir = repo_root / "dist"
    if not dist_dir.exists():
        return 0

    expected = {
        (pkg.display_name or pkg.name).replace("-", "_")
        for pkg in packages
    }

    pruned_names = []
    for whl in sorted(dist_dir.glob("*.whl")):
        distname = whl.stem.rsplit("-", 4)[0]
        if distname not in expected:
            whl.unlink()
            pruned_names.append(whl.name)
    # Single-line summary (was per-file info line + separate summary).
    if pruned_names:
        suffix = "" if len(pruned_names) == 1 else "s"
        display.info(
            f"  Pruned {len(pruned_names)} stale wheel{suffix} from dist/: "
            + ", ".join(pruned_names)
        )
    return len(pruned_names)


@auto_trace(logger)
def main():
    """Main entry point."""
    args = parse_args()

    # Handle docker subcommand
    if args.command == "docker":
        if args.docker_command == "build":
            return build_docker_images(
                repo_root=args.repo_root,
                force=args.force,
                max_workers=args.max_workers,
                verbose=args.verbose,
            )
        else:
            display.error("docker subcommand required (build)")
            return 1

    # Print header + cache banner once for the whole build.  Using
    # phase="full" prints all four paths (both wheel and image) up-front,
    # so the later ``build_docker_images`` call's redundant call is a
    # no-op (module-level guard).
    display.header("Parallel Build System")
    _print_cache_state(args.repo_root, phase="full")

    # Create coordinator
    coordinator = BuildCoordinator(
        repo_root=args.repo_root,
        max_workers=args.max_workers,
        timeout=args.timeout,
        force=args.force,
        verbose=args.verbose,
        use_cache=not args.no_cache,
        verify_cache=args.verify_cache,
    )

    # Discover packages.  Non-verbose runs skip the count line because
    # the next "Building N packages in K levels..." message says the
    # same thing with more information.
    try:
        packages = coordinator.discover_packages()
        if args.verbose:
            display.info(f"Discovered {len(packages)} packages")
            display.list_items([pkg.display_name for pkg in packages])
            display.newline()
    except ValueError as e:
        display.error(str(e))
        return 1

    # Build dependency graph
    dep_graph = build_dependency_graph(packages)
    build_levels = topological_sort(dep_graph)

    if args.verbose:
        display.section("Dependency-aware build order:")
        for level_num, level in enumerate(build_levels, 1):
            display.info(f"  Level {level_num}: {', '.join(level)}")
        display.newline()

    # Execute builds in dependency order
    try:
        results = coordinator.execute_parallel_by_levels(packages, build_levels)
    except KeyboardInterrupt:
        display.info("\nBuild cancelled by user")
        return 130
    except Exception as e:
        display.error(f"Build error: {e}")
        return 1

    # Generate summary
    summary = coordinator.generate_summary_report(results)
    display.info(summary)

    # Save summary to file
    summary_path = coordinator.log_dir / "summary.txt"
    with open(summary_path, 'w') as f:
        f.write(summary)

    # Check for wheel build failures
    failed_results = [r for r in results if not r.success]
    if failed_results:
        display.info(f"\n❌ {len(failed_results)} package(s) failed. Build logs:")
        for r in sorted(failed_results, key=lambda r: r.package.display_name.lower()):
            display.info(f"   {r.package.log_path}")
        return 1

    # Prune stale wheels in dist/ — wheels produced by a package that has
    # since been moved/renamed/deleted no longer correspond to any source
    # under package_roots.  Left in place, they'd poison downstream consumers
    # that pip-install everything in dist/ (e.g. test workers), because
    # their dependency declarations may reference packages no longer
    # available in the repo's closure.  Runs only after a fully-successful
    # build so we never delete a wheel we just produced.  Emits its own
    # single-line summary — no separate summary print here.
    _prune_stale_wheels(args.repo_root, packages)

    # Build Docker images if --docker flag
    if getattr(args, 'docker', False):
        docker_exit = build_docker_images(
            repo_root=args.repo_root,
            force=args.force,
            max_workers=args.max_workers or DEFAULT_DOCKER_MAX_WORKERS,
            verbose=args.verbose,
        )
        if docker_exit != 0:
            return docker_exit

    # Build-complete marker — clear end-of-output signal.  Matches the
    # docker tables' footer conventions (indented two spaces).
    display.info(f"\n✓ Build complete — logs: {coordinator.log_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
