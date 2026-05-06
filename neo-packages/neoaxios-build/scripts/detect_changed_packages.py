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
"""Detect test project paths affected by current changes.

Outputs space-separated project root paths that contain pytest config
and have files modified in the working tree or on the current branch (vs main).

Usage:
    python3 neo-packages/neoaxios-build/scripts/detect_changed_packages.py

Output:
    Space-separated paths, e.g.:
    neo-packages/foundation/fastapi_kit neo-packages/foundation/config

    Empty output if no test projects are affected.
"""

import subprocess
from pathlib import Path


def get_changed_files():
    """Collect all files changed in working tree and on branch vs main."""
    changed = set()
    for cmd in [
        ["git", "diff", "--name-only", "HEAD"],
        ["git", "diff", "--name-only", "--cached"],
        ["git", "diff", "--name-only", "main...HEAD"],
    ]:
        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL
            ).strip()
            changed.update(f for f in out.split("\n") if f)
        except subprocess.CalledProcessError:
            pass
    return changed


def map_to_test_projects(changed_files):
    """Map changed files to their containing pytest config project roots."""
    roots = set()
    for f in changed_files:
        p = Path(f)
        while p != p.parent:
            p = p.parent
            if (p / "pytest config").exists():
                roots.add(str(p))
                break
    return sorted(roots)


def main() -> None:
    changed = get_changed_files()
    if not changed:
        return
    projects = map_to_test_projects(changed)
    if projects:
        print(" ".join(projects))


if __name__ == "__main__":
    main()
