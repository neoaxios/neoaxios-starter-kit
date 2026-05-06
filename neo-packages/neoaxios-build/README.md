# neoaxios-build-system

Build orchestrator for multi-package Python projects. Discovers the package graph from
`pyproject.toml` files, builds wheels in dependency order with bounded parallelism, and
caches both wheel and Docker-image artifacts using a content hash so unchanged packages
are not rebuilt.

## What it does

- **Dependency-aware parallel builds.** Topologically sorts packages by their declared
  dependencies and builds independent leaves concurrently.
- **Hash-based cache.** Each package's source tree (excluding `tests/`, `build/`,
  `__pycache__/`, etc.) is hashed; wheels and Docker images keyed by the hash are
  reused across runs and worktrees, with optional fallback to the main branch's cache
  for shared foundation wheels.
- **Docker integration.** Discovers `docker.yaml` metadata files alongside Dockerfiles,
  resolves base-image dependencies, and builds container images with the same caching
  behavior as wheels.
- **Validation tooling.** Static-analysis scripts under `scripts/` enforce telemetry
  instrumentation coverage, FlightRecorder coverage in tests, cross-package import
  boundaries, cache-key registry coverage, and migration-script integrity.

## Install

```bash
pip install neoaxios-build-system
```

Requires Python 3.10+. Runtime dependencies are intentionally minimal (`build`, `PyYAML`)
to avoid circular dependencies — this is the package that builds every other package.

For optional progress-bar output:

```bash
pip install "neoaxios-build-system[progress]"
```

## Usage

The package installs the `neoaxios-build` console script:

```bash
# Build all packages discovered under the current project root
neoaxios-build

# Force a full rebuild ignoring cache
neoaxios-build --force

# Build only specified packages (and their transitive dependencies)
neoaxios-build neo-packages/foundation/fastapi_kit
```

A wrapper script `bin/nmake` provides a thin alias suitable for `make`-style invocation.

## Validators (`scripts/`)

| Script | Purpose |
|---|---|
| `validate_telemetry_coverage.py` | Confirms production functions are instrumented with `@auto_trace`. |
| `validate_flightrecorder_coverage.py` | Confirms integration tests use `@flight_recorded`. |
| `validate_import_boundaries.py` | Enforces that cross-package imports go through declared public surfaces (`__all__` or the shared-abstraction registry). |
| `validate_cache_key_coverage.py` | Confirms every Redis key family used in source has a registry entry. |
| `discover_docker_images.py` | Emits the JSON image-discovery manifest consumed by deployment tooling. |
| `detect_changed_packages.py` | Lists packages whose source has changed relative to a baseline ref. |

## License

Apache License 2.0. See [LICENSE](LICENSE).
