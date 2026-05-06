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
"""Validate that every Redis key family used in production code is declared
in its owning package's ``cache-key-registry.yaml``.

Per-package model: each package owns a ``cache-key-registry.yaml`` at its
directory root. The validator discovers every ``**/cache-key-registry.yaml``
under the repo root and merges them; key names must be globally unique across
all per-package files.

Design
------
Each entry in a per-package ``cache-key-registry.yaml`` under ``keys:`` has a ``pattern``
field like ``"{base}:lock:gauge_refresh"`` or
``"{ns}:resource_policy:{resource_id}:config"``. The leading brace-placeholder
(``{base}``, ``{ns}``, ``{domain_scope}``, ...) is the CacheNamespace
prefix that ``make_key()`` prepends at runtime. The ``relative template``
is what the caller passes to ``make_key()``: everything after that
leading placeholder, with interpolated variables (e.g., ``{resource_id}``)
still intact.

This script scans every Python source file under the configured package
roots and collects every argument passed as the first positional to:

    * ``ns.make_key("...")`` / ``ns.make_key_at("...")`` — the canonical
      CacheNamespace API used everywhere in the project.
    * Raw Redis client calls whose first positional is a literal or
      f-string (``redis.set("foo:bar", ...)``). Raw calls are rare and
      typically discouraged on their own, but we include them so a
      missing registry entry is still surfaced.

Call-site expressions are normalized to ``relative templates`` (f-string
variable slots become ``{}``), and then matched against the registry's
normalized templates (registry variable slots also become ``{}``). A
call-site template matches if it equals any registry template or is a
template prefix of one.

Exit codes
----------
    0 — every call-site template matches a registered family (including
        the empty case when no usages are found).
    1 — at least one unregistered family is present.
    2 — registry missing or malformed / scan failed.

Every Redis key family must be registered in a per-package
cache-key-registry.yaml. Missing registry is a hard error — there are
no silent skips.

Usage:
    python3 neo-packages/neoaxios-build/scripts/validate_cache_key_coverage.py
    python3 neo-packages/neoaxios-build/scripts/validate_cache_key_coverage.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

# Repo root inference.
_REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent.parent.parent

# Ensure neoaxios.build is importable and module logger works.
sys.path.insert(0, str(_REPO_ROOT_DEFAULT / "neo-packages" / "neoaxios-build" / "src"))

from neoaxios_logging import auto_trace, get_telemetry  # noqa: E402

from neoaxios.build.config import (  # noqa: E402
    load_build_config,
    discover_source_dirs,
)

import _display as display  # noqa: E402

logger = get_telemetry(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Method names that are REDIS-ONLY (do not collide with dict, HTTP client,
# Pydantic model, or FastAPI response accessors). Methods like ``get``,
# ``set``, ``hset``, ``delete``, ``exists``, ``expire``, ``publish`` are
# intentionally EXCLUDED because they collide with non-Redis APIs and
# would produce a blizzard of false positives. Methods listed here have
# distinctive Redis semantics; any call to them with a string first
# positional argument is extremely likely to be a Redis key construction.
#
# The canonical CacheNamespace API (``make_key`` / ``make_key_at``) is
# the primary detection mechanism for the namespace contract. Raw-Redis
# detection is a defense-in-depth supplement for the rare cases where
# callers bypass the namespace wrapper.
REDIS_KEY_METHODS = frozenset({
    "setex", "setnx",
    "getset", "getdel",
    "incrby", "decrby",
    "hincrby", "hmset", "hmget",
    "sadd", "srem", "smembers",
    "zadd", "zrem", "zrange", "zrangebyscore", "zrangebylex",
    "xadd", "xread", "xreadgroup", "xack", "xgroup_create",
    "pexpire",
})

# Directories to skip — test code, build artifacts, and venvs.
_EXCLUDED_PATH_PARTS = frozenset({
    "tests", "test",
    "venv", ".venv",
    "examples",
    "build", "dist",
    "__pycache__", ".eggs", "egg-info",
})

# Regex to recognize the leading CacheNamespace placeholder in a
# registry pattern (e.g., ``{base}:foo`` → placeholder ``{base}``).
_LEADING_PLACEHOLDER_RE = re.compile(r"^\{[^{}]+\}:?")

# Regex to normalize ``{anything}`` interpolation slots to ``{}`` so the
# comparison is structural rather than variable-name sensitive.
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")


@dataclass(frozen=True)
class RegisteredFamily:
    """A registry entry after template normalization.

    Attributes:
        name: Registry key name (top-level key under ``keys:``).
        pattern: Raw ``pattern`` field from the registry YAML.
        template: Normalized relative template — pattern minus leading
            placeholder, with remaining slots reduced to ``{}``.
    """

    name: str
    pattern: str
    template: str


@dataclass
class KeyUsage:
    """A single detected key-family usage at a call site."""

    literal_template: str      # template derived from the call-site arg
    file: Path
    line: int
    mechanism: str             # "make_key" | "make_key_at" | "raw_redis:<m>"
    display_literal: str       # human-readable rendering for diagnostics


@dataclass
class ScanReport:
    """Aggregated scan output."""

    usages: List[KeyUsage] = field(default_factory=list)
    unregistered: List[KeyUsage] = field(default_factory=list)
    registered: List[RegisteredFamily] = field(default_factory=list)
    files_scanned: int = 0


# ---------------------------------------------------------------------------
# Registry loading
# ---------------------------------------------------------------------------


@auto_trace(logger)
def load_registered_families(registry_path: Path) -> List[RegisteredFamily]:
    """Load the cache-key-registry YAML(s) and normalize each entry.

    Accepts either:
      - a path to a single ``cache-key-registry.yaml`` file (legacy / tests), or
      - a directory (typically the repo root) under which every per-package
        ``**/cache-key-registry.yaml`` is discovered and merged.

    Raises:
        FileNotFoundError: registry path is missing.
        ValueError: any discovered file is empty or lacks ``keys:``, or two
            files declare the same key name.
    """
    paths: List[Path]
    if registry_path.is_file():
        paths = [registry_path]
    elif registry_path.is_dir():
        excluded = {".venv", "build", "node_modules", ".git", "__pycache__", ".pytest_cache"}
        paths = []
        for candidate in registry_path.rglob("cache-key-registry.yaml"):
            parts = set(candidate.parts)
            if "build" in parts and "lib" in parts:
                continue
            if any(p in excluded for p in candidate.parts):
                continue
            paths.append(candidate)
        paths.sort()
        if not paths:
            raise FileNotFoundError(
                f"No per-package cache-key-registry.yaml files found under "
                f"{registry_path}. Every Redis key family must be declared in "
                f"its owning package's file."
            )
    else:
        raise FileNotFoundError(
            f"Cache key registry not found at {registry_path}. "
            f"Every Redis key family must be declared in its owning package's "
            f"cache-key-registry.yaml."
        )

    result: List[RegisteredFamily] = []
    seen: dict[str, Path] = {}
    for fp in paths:
        with open(fp, "r") as fh:
            raw = yaml.safe_load(fh)
        if not raw:
            raise ValueError(f"Cache key registry {fp} is empty")
        keys_map = raw.get("keys")
        if not keys_map:
            raise ValueError(
                f"Cache key registry {fp} missing required 'keys' mapping"
            )
        for name, entry in keys_map.items():
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Registry entry {name!r} in {fp} must be a mapping, got "
                    f"{type(entry).__name__}"
                )
            if name in seen:
                raise ValueError(
                    f"Duplicate cache key declaration: {name!r} appears in "
                    f"both {seen[name]} and {fp}. Each cache key must be "
                    f"declared in exactly one package's "
                    f"cache-key-registry.yaml."
                )
            pattern = entry.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(
                    f"Registry entry {name!r} in {fp} missing non-empty "
                    f"'pattern' field"
                )
            template = _relative_template(pattern)
            result.append(
                RegisteredFamily(name=name, pattern=pattern, template=template)
            )
            seen[name] = fp
    return result


def _relative_template(pattern: str) -> str:
    """Strip the leading ``{placeholder}:`` from a registry pattern and
    normalize remaining variable slots to ``{}``.

    Examples:
        ``{base}:lock:gauge_refresh`` -> ``lock:gauge_refresh``
        ``{ns}:resource_policy:{resource_id}:config``
            -> ``resource_policy:{}:config``
        ``perm_cache:{hmac_hash}`` (global scope, no leading placeholder)
            -> ``perm_cache:{}``
    """
    trimmed = _LEADING_PLACEHOLDER_RE.sub("", pattern, count=1)
    # Some entries are leaf patterns with no placeholder prefix (global
    # scope keys like `perm_cache:{hmac_hash}`). In those cases the
    # substitution above is a no-op, which is the right behavior.
    return _PLACEHOLDER_RE.sub("{}", trimmed)


# ---------------------------------------------------------------------------
# Call-site extraction
# ---------------------------------------------------------------------------


class _KeyCallVisitor(ast.NodeVisitor):
    """Collect key-family usages from make_key* and raw Redis calls."""

    def __init__(self, file_path: Path) -> None:
        self._file = file_path
        self.usages: List[KeyUsage] = []

    # notrace: ast.NodeVisitor dispatch callback — invoked per-node during
    # tree traversal; tracing would produce thousands of spans per file.
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        mechanism = self._detect_mechanism(node)
        if mechanism is not None and node.args:
            template, display = _arg_to_template(node.args[0])
            if template is not None and _looks_like_redis_key(
                template, mechanism
            ):
                self.usages.append(
                    KeyUsage(
                        literal_template=template,
                        file=self._file,
                        line=node.lineno,
                        mechanism=mechanism,
                        display_literal=display,
                    )
                )
        self.generic_visit(node)

    def _detect_mechanism(self, node: ast.Call) -> Optional[str]:
        func = node.func
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in {"make_key", "make_key_at"}:
                return attr
            if attr in REDIS_KEY_METHODS:
                return f"raw_redis:{attr}"
        return None


def _looks_like_redis_key(template: str, mechanism: str) -> bool:
    """Heuristic: a Redis key template has at least one ``:`` segment.

    ``make_key`` calls (which are Redis-specific by definition) always
    produce Redis keys. Raw Redis method calls (``setex``, ``hincrby``,
    ...) might occasionally be called with a field name rather than a
    key (e.g., ``hincrby(key, field, 1)`` uses field as 2nd arg — we
    only look at position 0, which IS the key). We additionally require
    the template to contain a segment separator to filter out stray
    non-key strings that happen to appear as the first positional arg.
    """
    if mechanism in {"make_key", "make_key_at"}:
        return True
    # Raw redis calls: require segmented structure to qualify as a key.
    return ":" in template


def _arg_to_template(arg: ast.AST) -> tuple[Optional[str], str]:
    """Convert a call-site first-arg AST node to a normalized template.

    Returns:
        (template, display_literal). The first element is None when the
        argument is neither a literal nor an f-string (e.g., a fully
        dynamic expression like ``make_key(variable)``) — such cases
        cannot be statically bound to a family and are skipped. The
        display_literal is a human-friendly rendering for diagnostics.
    """
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        s = arg.value
        return s, repr(s)

    if isinstance(arg, ast.JoinedStr):
        parts: List[str] = []
        display_parts: List[str] = []
        for piece in arg.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
                display_parts.append(piece.value)
            elif isinstance(piece, ast.FormattedValue):
                parts.append("{}")
                try:
                    display_parts.append(f"{{{ast.unparse(piece.value)}}}")
                except Exception:  # ast.unparse can fail on exotic or synthetic nodes; this is a human-readable display string only (the canonical template is already "{}" in parts), so an opaque placeholder is acceptable
                    display_parts.append("{?}")
            else:
                # Unknown f-string component — refuse to guess.
                return None, ""
        return "".join(parts), "f" + repr("".join(display_parts))

    return None, ""


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _template_matches(
    usage_template: str, registered: List[RegisteredFamily]
) -> Optional[RegisteredFamily]:
    """Return the registered family whose template matches the usage, or None.

    A usage matches when any of the following holds, in order:

        1. Exact template equality: call-site equals a registered template.
        2. Call-site is a segment-aligned *shorter* template and a
           registered template starts with it (e.g., call-site
           ``"model:"`` matches registered ``"model:{}"`` — legitimate
           prefix scan).
        3. A segment-aligned prefix of the call-site matches a
           registered template (e.g., ``"seller:{}:usage:extra"`` still
           matches ``"seller:{}:usage"`` because the family is rooted
           at the registered prefix).

    We never match across partial segments.
    """
    # (1) exact match.
    for fam in registered:
        if fam.template == usage_template:
            return fam

    # (2) call-site is a prefix of a registered template.
    usage_prefix = usage_template.rstrip(":")
    for fam in registered:
        reg_segments = fam.template.split(":")
        # Check each segment-aligned prefix of the registered template.
        for cut in range(1, len(reg_segments) + 1):
            reg_prefix = ":".join(reg_segments[:cut])
            if reg_prefix == usage_prefix:
                return fam

    # (3) shorten usage template to a registered family.
    segments = usage_template.split(":")
    while segments:
        candidate = ":".join(segments)
        for fam in registered:
            if fam.template == candidate:
                return fam
        segments.pop()

    return None


# ---------------------------------------------------------------------------
# Source-file scanning
# ---------------------------------------------------------------------------


@auto_trace(logger)
def scan_source_tree(
    repo_root: Path, registered: List[RegisteredFamily]
) -> ScanReport:
    """Scan every configured package root for key-family usages.

    Args:
        repo_root: Repository root containing build.yaml.
        registered: Registered families (already normalized).

    Returns:
        ScanReport summarizing usages and any unregistered violations.
    """
    config = load_build_config(repo_root)
    # Cache keys can appear in any package root.
    src_dirs = discover_source_dirs(repo_root, config.package_roots)

    report = ScanReport(registered=list(registered))

    for src_dir, _pkg in src_dirs:
        for py_file in src_dir.rglob("*.py"):
            rel_parts = py_file.relative_to(src_dir).parts
            if any(part in _EXCLUDED_PATH_PARTS for part in rel_parts):
                continue
            report.files_scanned += 1
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                raise RuntimeError(
                    f"Failed to parse {py_file}: {exc}"
                ) from exc

            visitor = _KeyCallVisitor(py_file)
            visitor.visit(tree)
            for usage in visitor.usages:
                report.usages.append(usage)
                if _template_matches(usage.literal_template, registered) is None:
                    report.unregistered.append(usage)

    return report


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


@auto_trace(logger)
def print_report(report: ScanReport, verbose: bool) -> None:
    """Emit a human-readable summary of the scan."""
    total = len(report.usages)
    bad = len(report.unregistered)
    display.report_header("Cache Key Coverage Report")
    display.report_row(f"Files scanned:           {report.files_scanned}")
    display.report_row(f"Registered families:     {len(report.registered)}")
    display.report_row(f"Key-family usages found: {total}")
    display.report_row(f"Unregistered usages:     {bad}")
    display.blank()

    if verbose and report.usages:
        by_template: Dict[str, List[KeyUsage]] = {}
        for u in report.usages:
            by_template.setdefault(u.literal_template, []).append(u)
        display.info("Detected call-site templates:")
        for template in sorted(by_template):
            count = len(by_template[template])
            matched = _template_matches(template, report.registered)
            status = (
                f"matches registry entry {matched.name!r}"
                if matched is not None
                else "NO MATCH"
            )
            display.info(f"  - {template!r} ({count} usages) [{status}]")
        display.blank()

    if report.unregistered:
        display.info("Unregistered key families:")
        display.report_divider()
        for u in report.unregistered:
            display.report_row(
                f"  {u.file}:{u.line}: {u.mechanism} "
                f"template={u.literal_template!r} arg={u.display_literal}"
            )
        display.report_divider()
        display.info(
            "Add each family to the owning package's cache-key-registry.yaml "
            "under 'keys:'."
        )


@auto_trace(logger)
def main() -> int:
    """CLI entry point.

    Returns:
        0, 1, or 2 as described in the module docstring.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Validate that every Redis key family used in production "
            "source is registered in the owning package's "
            "cache-key-registry.yaml."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_REPO_ROOT_DEFAULT,
        help="Repository root containing build.yaml and config/",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print per-template usage counts and registry match status",
    )
    args = parser.parse_args()

    # Discover all per-package cache-key-registry.yaml files under the repo
    # root and merge them. Pass the repo root (a directory) to
    # load_registered_families which handles single-file and directory inputs.
    registry_path = args.repo_root

    try:
        registered = load_registered_families(registry_path)
    except (FileNotFoundError, ValueError) as exc:
        display.error(str(exc))
        return 2

    try:
        report = scan_source_tree(args.repo_root, registered)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        display.error(str(exc))
        return 2

    print_report(report, args.verbose)

    return 0 if not report.unregistered else 1


if __name__ == "__main__":
    sys.exit(main())
