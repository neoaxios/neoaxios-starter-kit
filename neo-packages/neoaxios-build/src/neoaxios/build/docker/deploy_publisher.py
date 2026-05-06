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

"""Mirror per-image ``deploy.yaml`` manifests into the shared deployments dir.

Called on every ``neoaxios-build docker build`` invocation (regardless of
image-cache hits) so the shared mirror stays in sync with each repo's
source-of-truth manifests.  Downstream consumers read from the shared dir
when they resolve ``_include: shared/<name>.yaml`` in a project config.

Publish key derivation
----------------------
Walk the ancestor directories of ``deploy.yaml`` leaf-first; the first
directory whose name is not ``docker`` becomes the publish key:

    docker/base/redis/deploy.yaml                 → redis
    docker/thirdparty/<name>/deploy.yaml          → <name>
    neo-packages/<category>/<pkg>/docker/deploy.yaml  → <pkg>

This keeps the shared-dir filename predictable from the source path,
without forcing owners to add a ``publish_as:`` field.

Idempotence
-----------
Content-hash gated: identical content leaves the mirror untouched, so a
fresh ``neoaxios-build docker build`` after an unrelated edit doesn't
churn the mirror's mtimes (and doesn't trigger downstream watchers).
"""

import hashlib
import os
import pwd
from pathlib import Path
from typing import List, Tuple

EXCLUDED_DIR_NAMES = {
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".test-cache",
    "logs",
    ".build-cache",
}


def resolve_shared_deployments_dir() -> Path:
    """Where ``deploy.yaml`` mirrors land for downstream consumers.

    Resolution precedence mirrors the consumer's ``_resolve_shared_deployments_dir``
    so publisher and consumer always agree:

      1. ``NEOAXIOS_DEPLOYMENT_OVERRIDE`` env var (escape hatch for CI
         and sandboxes).
      2. ``<user-home>/.config/neoaxios/myapp/deployments`` — with user
         home taken from ``/etc/passwd`` (or ``_NEO_REAL_HOME``), not
         ``$HOME``, so this codebase's per-worktree ``$HOME`` rewrites don't
         route the publisher and the reader into different dirs.
    """
    override = os.environ.get("NEOAXIOS_DEPLOYMENT_OVERRIDE", "").strip()
    if override:
        return Path(override).expanduser()
    explicit_home = os.environ.get("_NEO_REAL_HOME", "").strip()
    home = explicit_home if explicit_home else pwd.getpwuid(os.getuid()).pw_dir
    return Path(home) / ".config" / "neoaxios" / "myapp" / "deployments"


def _derive_publish_key(deploy_file: Path, repo_root: Path) -> str:
    rel = deploy_file.relative_to(repo_root)
    for parent in rel.parents:
        if parent == Path("."):
            break
        if parent.name != "docker":
            return parent.name
    return deploy_file.stem


def discover_deploy_manifests(repo_root: Path) -> List[Path]:
    results: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        if "deploy.yaml" in filenames:
            results.append(Path(dirpath) / "deploy.yaml")
    return sorted(results)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def publish_deploy_manifests(repo_root: Path) -> Tuple[int, int, int, Path]:
    """Copy every ``deploy.yaml`` under ``repo_root`` into the shared dir.

    Returns ``(copied, up_to_date, total, shared_dir)`` where ``copied``
    is the count of manifests whose content changed (or were new),
    ``up_to_date`` is unchanged mirrors, and ``total`` is both combined.
    Callers typically log a one-line summary with these numbers.
    """
    shared_dir = resolve_shared_deployments_dir()
    shared_dir.mkdir(parents=True, exist_ok=True)

    copied = up_to_date = 0
    manifests = discover_deploy_manifests(repo_root)
    for src in manifests:
        key = _derive_publish_key(src, repo_root)
        dest = shared_dir / f"{key}.yaml"
        content = src.read_bytes()
        if dest.exists() and _sha256(content) == _sha256(dest.read_bytes()):
            up_to_date += 1
        else:
            dest.write_bytes(content)
            copied += 1
    return copied, up_to_date, len(manifests), shared_dir
