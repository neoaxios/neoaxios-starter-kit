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

"""Branch-aware wheel cache namespacing.

The shared wheel cache at ``~/.cache/neoaxios/.wheel-cache/`` uses
branch-named subdirectories to prevent cross-worktree collision on
identically-named wheels.  A worktree on branch ``wt/1`` writes to
``.wheel-cache/wt-1/``; main-branch builds write to
``.wheel-cache/main/``.

When reading, callers search the branch namespace first, then fall back
to ``main/``.

Fallback policy
---------------
Main-branch fallback is the ONE intentional cache-level fallback in
this build system. It is a deliberate exception to the broader
no-fallbacks policy for the following reasons:

* foundation wheels (``neoaxios-logging``, ``neoaxios-fastapi-kit``,
  etc.) are canonical on the project's ``main`` branch and rarely
  rebuilt from worktrees.
* A worktree on a feature branch typically depends on those foundation
  wheels but does not rebuild them locally — it expects them to be
  present in the shared cache.
* Without the main-fallback, a fresh worktree on a new branch would
  have an empty cache namespace and pip would fall back to PyPI,
  defeating the cache entirely.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional


def _resolve_env_alias(primary: str, alias: str) -> str:
    """Return the alias's value if set (non-empty), else the primary's value.

    Shared resolution for cache env vars that accept an unprefixed alias
    (``WHEEL_CACHE`` / ``IMAGE_CACHE``) as an override for the prefixed
    canonical name (``NEOAXIOS_WHEEL_CACHE`` / ``NEOAXIOS_IMAGE_CACHE``).

    The alias wins so a per-repo Makefile or shell export of the short
    name can override the default that the shell-integration auto-
    exports for the prefixed name.  Both unset / whitespace-only values
    count as "not set".

    Returns:
        The raw (stripped) env value — ``""`` when neither is set,
        ``"-"`` when explicit opt-out, or a path spec.
    """
    alias_val = os.environ.get(alias, "").strip()
    if alias_val:
        return alias_val
    return os.environ.get(primary, "").strip()


def wheel_cache_env_spec() -> str:
    """Resolved spec for the shared wheel cache ($WHEEL_CACHE | $NEOAXIOS_WHEEL_CACHE)."""
    return _resolve_env_alias("NEOAXIOS_WHEEL_CACHE", "WHEEL_CACHE")


def image_cache_env_spec() -> str:
    """Resolved spec for the shared image cache ($IMAGE_CACHE | $NEOAXIOS_IMAGE_CACHE)."""
    return _resolve_env_alias("NEOAXIOS_IMAGE_CACHE", "IMAGE_CACHE")


def _real_home() -> Path:
    """Return the canonical home directory.

    Honors ``$_NEO_REAL_HOME`` when set (used by shell integrations
    that rewrite ``$HOME`` for per-worktree shells), and falls back to
    the user's ``/etc/passwd`` entry so a rewritten shell still resolves
    to the same cache path as the canonical shell.
    """
    import pwd

    explicit = os.environ.get("_NEO_REAL_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return Path(pwd.getpwuid(os.getuid()).pw_dir).expanduser()


def try_get_cache_namespace(repo_root: Path) -> Optional[str]:
    """Return the ``cache.namespace`` declared in ``<repo_root>/build.yaml``.

    Returns ``None`` for any of:
      * build.yaml is absent (e.g. ad-hoc invocations outside a project root)
      * build.yaml is malformed in a way that ``load_build_config`` rejects
      * the ``cache`` section is omitted

    Errors are swallowed deliberately: this helper feeds path resolution
    on every cache read/write, and a transient build.yaml problem must
    not prevent the resolver from returning a usable default path.  The
    real validation lives in ``load_build_config`` and surfaces the
    moment ``make build`` or any other config-driven command runs.

    Args:
        repo_root: Repo whose build.yaml declares the namespace (or not).
    """
    try:
        # Late import — config.py imports from this module would create
        # a cycle if we top-level imported it.  Late binding is fine, the
        # call cost is negligible compared to filesystem I/O.
        from neoaxios.build.config import load_build_config

        cfg = load_build_config(Path(repo_root))
    except Exception:
        return None
    return cfg.cache_namespace


def shared_cache_parent(repo_root: Optional[Path]) -> Path:
    """Return the parent directory under which wheel + image caches live.

    Resolution:
      * No repo_root or no ``cache.namespace`` declared → ``~/.cache/neoaxios``
        (the default shared root).
      * ``cache.namespace: <name>`` declared → ``~/.cache/neoaxios/<name>``,
        isolating the build caches from any other project's.

    The actual wheel cache appends ``.wheel-cache``; the image cache
    appends ``.docker-image-cache``.  Callers are responsible for that
    last segment so this helper stays cache-kind-agnostic.
    """
    base = _real_home() / ".cache" / "neoaxios"
    if repo_root is None:
        return base
    namespace = try_get_cache_namespace(repo_root)
    return base / namespace if namespace else base


def _resolve_cache_path(
    *,
    alias_env: str,
    primary_env: str,
    cache_subdir: str,
    repo_root: Optional[Path],
) -> Optional[Path]:
    """Apply the full cache-path resolution precedence.

    Returns ``None`` for explicit opt-out; a ``Path`` otherwise (the
    directory may not yet exist — callers either tolerate that or
    treat absence as "no cache available").

    Precedence (highest first):
      1. ``$<alias_env>`` set explicitly:
         * ``-`` → opt-out (None).
         * any other value → that path (user's per-invocation override
           takes priority over both the build.yaml declaration and the
           shell-integration default).
      2. ``$<primary_env>=-`` → opt-out (the explicit-opt-out semantics
         of the prefixed name remain honored even when shell integration
         normally auto-exports it to a default path).
      3. ``cache.namespace`` declared in ``<repo_root>/build.yaml`` →
         ``~/.cache/neoaxios/<namespace>/<cache_subdir>``.  This sits
         ABOVE the prefixed env var as a path so a per-project
         declaration wins over the shell-integration default; it sits
         BELOW the alias env var so a user can still override
         per-invocation.
      4. ``$<primary_env>=/path`` → that path (the shell integration's
         auto-exported default for any project that hasn't declared a
         namespace).
      5. ``~/.cache/neoaxios/<cache_subdir>`` → the hardcoded final
         fallback when neither env nor build.yaml has anything to say.
    """
    alias_raw = os.environ.get(alias_env, "").strip()
    primary_raw = os.environ.get(primary_env, "").strip()

    if alias_raw == "-":
        return None
    if alias_raw:
        return Path(alias_raw).expanduser()

    if primary_raw == "-":
        return None

    if repo_root is not None:
        namespace = try_get_cache_namespace(Path(repo_root))
        if namespace:
            return _real_home() / ".cache" / "neoaxios" / namespace / cache_subdir

    if primary_raw:
        return Path(primary_raw).expanduser()

    return _real_home() / ".cache" / "neoaxios" / cache_subdir


def resolved_wheel_cache_path(repo_root: Optional[Path]) -> Optional[Path]:
    """Resolve the wheel cache path applying full precedence.

    See ``_resolve_cache_path`` for the precedence rules.  Wheel-cache-
    specific shorthand: passes ``WHEEL_CACHE`` / ``NEOAXIOS_WHEEL_CACHE``
    as the env var names and ``.wheel-cache`` as the subdirectory.
    """
    return _resolve_cache_path(
        alias_env="WHEEL_CACHE",
        primary_env="NEOAXIOS_WHEEL_CACHE",
        cache_subdir=".wheel-cache",
        repo_root=repo_root,
    )


def resolved_image_cache_path(repo_root: Optional[Path]) -> Optional[Path]:
    """Resolve the Docker image cache path applying full precedence.

    See ``_resolve_cache_path`` for the precedence rules.  Image-cache-
    specific shorthand: passes ``IMAGE_CACHE`` / ``NEOAXIOS_IMAGE_CACHE``
    as the env var names and ``.docker-image-cache`` as the subdirectory.
    """
    return _resolve_cache_path(
        alias_env="IMAGE_CACHE",
        primary_env="NEOAXIOS_IMAGE_CACHE",
        cache_subdir=".docker-image-cache",
        repo_root=repo_root,
    )


def branch_namespace(repo_root: Path) -> str:
    """Compute the wheel cache namespace for this codebase's current branch.

    Resolution precedence:
      1. ``NEOAXIOS_WHEEL_CACHE_NAMESPACE`` env var (explicit override).
      2. Current git branch, slugified (``wt/1`` → ``wt-1``).
      3. Short git SHA prefixed with ``detached-`` when HEAD is detached.
      4. ``main`` as final fallback when git state is unreachable.

    Args:
        repo_root: Path to the git checkout whose branch determines the
            namespace.  Usually the repo under build.

    Returns:
        A filesystem-safe slug suitable as a subdirectory name.
    """
    explicit = os.environ.get("NEOAXIOS_WHEEL_CACHE_NAMESPACE", "").strip()
    if explicit:
        return explicit.replace("/", "-")

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            branch = result.stdout.strip()
            if branch and branch != "HEAD":
                return branch.replace("/", "-")

            sha_result = subprocess.run(
                ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            sha = sha_result.stdout.strip()
            if sha:
                return f"detached-{sha}"
    except (subprocess.SubprocessError, OSError):
        pass

    return "main"


def wheel_cache_write_dir(cache_root: Path, repo_root: Path) -> Path:
    """Return the directory where the published wheels should be written.

    The directory may not exist yet; callers should ``mkdir(parents=True)``.

    Args:
        cache_root: Top-level shared cache path (``~/.cache/neoaxios/.wheel-cache``).
        repo_root: Path to the repo whose branch selects the namespace.
    """
    return cache_root / branch_namespace(repo_root)


def wheel_cache_read_dirs(cache_root: Path, repo_root: Path) -> list[Path]:
    """Return the ordered list of cache directories to search on read.

    The search order is::

        1. ``cache_root/<current-branch-slug>/``  (primary)
        2. ``cache_root/main/``                   (approved fallback)

    Only existing directories are returned — callers can iterate without
    filtering.  When the repo's branch IS ``main``, only step 1 applies
    (no duplicate search).

    Args:
        cache_root: Top-level shared cache path.
        repo_root: Path to the repo whose branch selects the primary
            namespace.
    """
    namespace = branch_namespace(repo_root)
    paths: list[Path] = []

    branch_dir = cache_root / namespace
    if branch_dir.is_dir():
        paths.append(branch_dir)

    if namespace != "main":
        # APPROVED FALLBACK: main/ is searched after the current
        # branch's own cache.  This is the single exception to the broader
        # no-fallbacks policy — foundation wheels live here, and every
        # worktree depends on them without rebuilding locally.
        main_dir = cache_root / "main"
        if main_dir.is_dir():
            paths.append(main_dir)

    # MIGRATION COMPAT: the flat cache root is searched last to keep
    # pre-existing wheels (written by builds that ran before the
    # namespaced layout was introduced) findable during the transition.
    # This is transitional code, not an additional approved fallback.
    if cache_root.is_dir():
        # Only include if it has any wheels directly (not just subdirs)
        if any(cache_root.glob("*.whl")):
            paths.append(cache_root)

    return paths
