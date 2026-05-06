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

"""NeoAxios Build System.

Dependency-aware parallel build system with intelligent caching for
multi-package Python projects.

Imports are split into eager and lazy to avoid initializing telemetry
(which creates per-PID log files and prints startup banners) when callers
only need config, models, or cache.  BuildCoordinator and its dependency
chain (utils → ui → telemetry) load on first access via __getattr__.
"""

# ── Eager imports (no telemetry dependency) ──────────────────────────────
from neoaxios.build.cache import BuildCache
from neoaxios.build.config import (
    BuildConfig,
    ContractsConfig,
    PackageRoot,
    discover_package_dirs,
    discover_source_dirs,
    find_package_in_roots,
    load_build_config,
)
from neoaxios.build.models import BuildPackage, BuildResult
from neoaxios.build.dependency import build_dependency_graph, topological_sort

__version__ = "0.2.1"

__all__ = [
    "BuildCache",
    "BuildConfig",
    "BuildCoordinator",
    "BuildPackage",
    "BuildResult",
    "ContractsConfig",
    "PackageRoot",
    "build_dependency_graph",
    "discover_package_dirs",
    "discover_source_dirs",
    "find_package_in_roots",
    "load_build_config",
    "topological_sort",
]


# ── Lazy imports (telemetry-heavy: coordinator → utils → ui → telemetry) ─
def __getattr__(name):
    if name == "BuildCoordinator":
        from neoaxios.build.coordinator import BuildCoordinator
        globals()["BuildCoordinator"] = BuildCoordinator
        return BuildCoordinator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
