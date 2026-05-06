#!/usr/bin/env python3
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
"""Extract build paths from a project's build.yaml as Make-compatible values.

Uses load_build_config() from neoaxios.build.config — no duplicate parsing.
Called from vars.mk via $(shell python3 ...).

The project root is resolved from (in order): --repo-root flag,
NEOAXIOS_REPO_ROOT env var, or the current working directory. The script
itself does NOT try to infer the project from its own __file__ location,
since it may be installed anywhere (in-tree, pip-installed wheel, etc.).

The `neoaxios.build` package must be importable — pip install the
neoaxios-build package editable into the active venv before invoking.

Usage:
    python3 extract_build_paths.py CONTRACT_ROOT
    python3 extract_build_paths.py PACKAGE_ROOTS --repo-root /path/to/project
    NEOAXIOS_REPO_ROOT=/path python3 extract_build_paths.py PROVIDERS_PATTERN
"""

import argparse
import os
import sys
from pathlib import Path

from neoaxios.build.config import load_build_config


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract a build.yaml variable value for Make consumption."
    )
    parser.add_argument(
        "variable",
        help="Variable name (CONTRACT_ROOT, PACKAGE_ROOTS, "
        "PROVIDERS_PATTERN, CONSUMERS_PATTERN, CONSUMERS_EXCLUDE).",
    )
    parser.add_argument(
        "--repo-root",
        default=os.environ.get("NEOAXIOS_REPO_ROOT") or os.getcwd(),
        help="Project root containing build.yaml. "
        "Defaults to $NEOAXIOS_REPO_ROOT or the current working directory.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()

    try:
        config = load_build_config(repo_root)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # getattr fallback: a consumer's venv may carry an older neoaxios-build
    # wheel that predates the `layer1_profile` / `cache_namespace` fields.
    # This script runs at vars.mk parse time, before the bootstrap target
    # can refresh wheels — so a hard attribute access would crash every
    # consumer on first upgrade.
    layer1_profile = getattr(config, "layer1_profile", "default")
    cache_namespace = getattr(config, "cache_namespace", None) or ""

    # config.contracts may be None for consumers that neither publish nor
    # consume cross-package contracts. Emit empty strings for contract-derived
    # values so Make sees "" rather than crashing on AttributeError.
    if config.contracts is None:
        values = {
            "CONTRACT_ROOT": "",
            "PACKAGE_ROOTS": " ".join(r.path for r in config.package_roots),
            "PROVIDERS_PATTERN": "",
            "CONSUMERS_PATTERN": "",
            "CONSUMERS_EXCLUDE": "",
            "LAYER1_PROFILE": layer1_profile,
            "CACHE_NAMESPACE": cache_namespace,
        }
    else:
        values = {
            "CONTRACT_ROOT": config.contracts.root,
            "PACKAGE_ROOTS": " ".join(r.path for r in config.package_roots),
            "PROVIDERS_PATTERN": config.contracts.providers_pattern,
            "CONSUMERS_PATTERN": config.contracts.consumers_pattern,
            "CONSUMERS_EXCLUDE": " ".join(config.contracts.consumers_exclude),
            "LAYER1_PROFILE": layer1_profile,
            "CACHE_NAMESPACE": cache_namespace,
        }

    print(values.get(args.variable, ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
