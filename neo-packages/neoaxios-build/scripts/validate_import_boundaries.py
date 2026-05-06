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
"""Import boundary validator for cross-package import enforcement.

Scans all Python source files in configured package roots and verifies that cross-package
imports use the target package's public surface (symbols in __all__ or canonical
paths from shared-abstraction-registry.md). Internal module access across package
boundaries is flagged as a violation with actionable fix suggestions.

Usage:
    python3 neo-packages/neoaxios-build/scripts/validate_import_boundaries.py [options]

    # Validate all packages
    python3 neo-packages/neoaxios-build/scripts/validate_import_boundaries.py

    # Validate specific package
    python3 neo-packages/neoaxios-build/scripts/validate_import_boundaries.py --package secure_cache

    # Verbose output
    python3 neo-packages/neoaxios-build/scripts/validate_import_boundaries.py -v

Exit Codes:
    0 - All cross-package imports use public surfaces (or are exempted)
    1 - One or more boundary violations found
"""

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Add build system to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from neoaxios.build.ast_utils import parse_all_from_init


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class Violation:
    """A single import boundary violation."""

    __slots__ = ("source_file", "source_package", "import_module",
                 "target_package", "suggestion")

    def __init__(
        self,
        source_file: Path,
        source_package: str,
        import_module: str,
        target_package: str,
        suggestion: str,
    ):
        self.source_file = source_file
        self.source_package = source_package
        self.import_module = import_module
        self.target_package = target_package
        self.suggestion = suggestion

    def format_message(self) -> str:
        """Return an actionable violation message."""
        return (
            f"  {self.source_file}: "
            f"Package {self.source_package} imports {self.import_module} "
            f"-- use {self.suggestion} instead"
        )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

EXCLUDED_DIRS = {"tests", "test", "venv", ".venv", "examples", "build", "dist",
                 "__pycache__", ".eggs", "egg-info"}


def discover_source_files(repo_root: Path, roots) -> List[Path]:
    """Find all .py files under configured package roots.

    Supports both nested (category/package/src/) and flat (package/src/) layouts.
    Excludes test directories, venvs, examples, and build artifacts.
    """
    from neoaxios.build.config import discover_source_dirs

    src_dirs_with_pkg = discover_source_dirs(repo_root, roots)

    source_files: List[Path] = []

    for src_dir, _ in src_dirs_with_pkg:
        for py_file in src_dir.rglob("*.py"):
            # Check no excluded directory appears in the path relative to src_dir
            rel_parts = py_file.relative_to(src_dir).parts
            if any(part in EXCLUDED_DIRS for part in rel_parts):
                continue
            # Skip egg-info directories
            if any(".egg-info" in part for part in rel_parts):
                continue
            source_files.append(py_file)

    return sorted(source_files)


# ---------------------------------------------------------------------------
# Package ownership resolution
# ---------------------------------------------------------------------------

def build_module_to_package_map(repo_root: Path, roots) -> Dict[str, str]:
    """Map top-level Python module names to their owning package directory names.

    Scans src/ directories to find top-level Python packages
    (directories with __init__.py) or modules.

    Returns a dict: module_name -> package_path (e.g. "secure_cache" ->
    "foundation/secure_cache").
    """
    from neoaxios.build.config import discover_source_dirs

    module_map: Dict[str, str] = {}
    src_dirs_with_pkg = discover_source_dirs(repo_root, roots)

    for src_dir, pkg_path in src_dirs_with_pkg:
        for entry in src_dir.iterdir():
            if entry.name.startswith(".") or entry.name.startswith("_"):
                continue
            if ".egg-info" in entry.name:
                continue
            if entry.is_dir() and (entry / "__init__.py").exists():
                module_map[entry.name] = pkg_path
            elif entry.is_file() and entry.suffix == ".py":
                module_map[entry.stem] = pkg_path

    return module_map


def determine_owning_package(file_path: Path, repo_root: Path, roots) -> Optional[str]:
    """Determine which package owns a source file based on its path.

    Returns the package path like "foundation/secure_cache" or None.
    """
    from neoaxios.build.config import determine_owning_package as _determine

    return _determine(file_path, repo_root, roots)


# ---------------------------------------------------------------------------
# Import extraction (structured)
# ---------------------------------------------------------------------------

class ImportStatement:
    """Represents a single import statement with full structural detail."""

    __slots__ = ("module", "names", "lineno")

    def __init__(self, module: str, names: List[str], lineno: int):
        self.module = module  # The module being imported from (or the imported module)
        self.names = names    # The specific names imported (empty for plain `import X`)
        self.lineno = lineno


def extract_structured_imports(source: str) -> List[ImportStatement]:
    """Parse source code and return structured import statements.

    Unlike ast_utils.extract_imports which returns a flat set of names,
    this preserves the relationship between modules and imported names,
    which is required for cross-package boundary detection.

    Relative imports (level > 0, e.g. ``from ..config import X``) are
    excluded because they are intra-package by definition and cannot
    represent cross-package boundary violations.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    imports: List[ImportStatement] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportStatement(
                    module=alias.name,
                    names=[],
                    lineno=node.lineno,
                ))
        elif isinstance(node, ast.ImportFrom):
            # Skip relative imports (level > 0) -- they are intra-package
            if node.module and node.level == 0:
                names = [alias.name for alias in node.names]
                imports.append(ImportStatement(
                    module=node.module,
                    names=names,
                    lineno=node.lineno,
                ))

    return imports


# ---------------------------------------------------------------------------
# Public surface resolution
# ---------------------------------------------------------------------------

def load_all_from_init(init_path: Path) -> Optional[Set[str]]:
    """Parse __all__ from an __init__.py file.

    Returns the set of exported symbol names, or None if __all__ is not defined.
    Delegates to ``parse_all_from_init`` from ast_utils.
    """
    symbols = parse_all_from_init(init_path)
    if symbols is None:
        return None
    return set(symbols)


def build_public_surfaces(
    repo_root: Path,
    module_to_package: Dict[str, str],
    roots,
) -> Dict[str, Set[str]]:
    """Build a map of module_name -> set of public symbols from __all__.

    Only includes modules that define __all__ in their top-level __init__.py.
    """
    surfaces: Dict[str, Set[str]] = {}

    for module_name, pkg_path in module_to_package.items():
        # Search across all configured roots for the __init__.py
        for root in roots:
            root_dir = repo_root / root.path
            init_path = root_dir / pkg_path / "src" / module_name / "__init__.py"
            if init_path.is_file():
                all_symbols = load_all_from_init(init_path)
                if all_symbols is not None:
                    surfaces[module_name] = all_symbols
                break

    return surfaces


def parse_registry_import_paths(repo_root: Path) -> Set[str]:
    """Parse the shared-abstraction registry for canonical import paths.

    Extracts import path strings from backtick-delimited code in the Import
    column of registry tables. Returns a set of full import path strings
    like "from neoaxios_secure_cache import SecureCacheGateway" and
    "from some_pkg.heartbeat_status import A, B, C".
    """
    registry_path = repo_root / "docs" / "shared-abstraction-registry.md"
    if not registry_path.is_file():
        return set()

    content = registry_path.read_text(encoding="utf-8")
    # Match backtick-delimited import statements in table cells.
    # Pattern handles both single-symbol (``from X import Y``) and
    # multi-symbol (``from X import A, B, C``) forms — the body runs
    # up to the closing backtick so comma-separated imports are
    # captured intact.
    pattern = re.compile(r"`(from\s+\S+\s+import\s+[^`]+)`")
    return set(pattern.findall(content))


def build_registry_surfaces(repo_root: Path) -> Dict[str, Set[str]]:
    """Build a map of module_name -> set of symbols from the abstraction registry.

    Parses canonical import paths like ``from neoaxios_secure_cache import X`` and
    ``from some_pkg.heartbeat_status import A, B, C`` and adds every
    imported symbol to the public surface of the target module.
    """
    registry_imports = parse_registry_import_paths(repo_root)
    surfaces: Dict[str, Set[str]] = {}

    for import_stmt in registry_imports:
        # Parse "from X.Y.Z import A, B, C" — symbols field is
        # comma-separated and may include whitespace / trailing
        # punctuation (", ", ","). The module path itself is a single
        # dotted identifier so \S+ suffices for it.
        match = re.match(r"from\s+(\S+)\s+import\s+(.+)", import_stmt)
        if not match:
            continue
        module_path = match.group(1)
        symbols_field = match.group(2)
        # Split on comma, strip whitespace, drop empty fragments
        # (``import A,`` trailing comma case). Aliased imports
        # (``import A as B``) register the alias as-published.
        symbols: List[str] = []
        for raw in symbols_field.split(","):
            token = raw.strip()
            if not token:
                continue
            # Strip "as <alias>" — use the alias when present; the
            # canonical surface is whatever name consumers bind.
            if " as " in token:
                token = token.split(" as ", 1)[1].strip()
            symbols.append(token)
        # The top-level module is the first component
        top_module = module_path.split(".")[0]
        for symbol in symbols:
            # Add symbol as accessible from the full module path
            surfaces.setdefault(module_path, set()).add(symbol)
            # Also register under the top-level module for "from X import Y" access
            if module_path != top_module:
                surfaces.setdefault(top_module, set()).add(symbol)

    return surfaces


# ---------------------------------------------------------------------------
# Exemption handling
# ---------------------------------------------------------------------------

def parse_exemption_file(exempt_path: Path) -> Set[str]:
    """Parse a .import-boundary-exempt file.

    Each non-empty, non-comment line is an exempt import path.
    Justification text follows the path after '#'.
    Blank lines and lines starting with '#' are skipped.

    Returns set of exempt import path strings.
    """
    if not exempt_path.is_file():
        return set()

    exemptions: Set[str] = set()
    for line in exempt_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Split on first '#' to separate path from justification
        path_part = stripped.split("#")[0].strip()
        if path_part:
            exemptions.add(path_part)

    return exemptions


def load_package_exemptions(
    repo_root: Path,
    module_to_package: Dict[str, str],
    roots,
) -> Dict[str, Set[str]]:
    """Load .import-boundary-exempt files for all packages.

    Returns dict: package_path -> set of exempt import paths.
    """
    exemptions: Dict[str, Set[str]] = {}

    for _, pkg_path in module_to_package.items():
        if pkg_path in exemptions:
            continue
        # Search across all configured roots
        for root in roots:
            exempt_file = repo_root / root.path / pkg_path / ".import-boundary-exempt"
            if exempt_file.is_file():
                exempt_set = parse_exemption_file(exempt_file)
                if exempt_set:
                    exemptions[pkg_path] = exempt_set
                break

    return exemptions


# ---------------------------------------------------------------------------
# Cross-package boundary checking
# ---------------------------------------------------------------------------

def is_cross_package_import(
    import_module: str,
    source_package: str,
    module_to_package: Dict[str, str],
) -> Optional[str]:
    """Determine if an import targets a different neo-package.

    Returns the target package path if cross-package, None otherwise.
    """
    # Get the top-level module name from the import
    top_module = import_module.split(".")[0]

    # Check if this module belongs to a known neo-package
    target_pkg = module_to_package.get(top_module)
    if target_pkg is None:
        # Not a neo-package module (stdlib, third-party, etc.)
        return None

    if target_pkg == source_package:
        # Same package -- not a cross-package import
        return None

    return target_pkg


def is_internal_import(import_module: str) -> bool:
    """Check if an import accesses internal modules of a package.

    An import is "internal" if it goes deeper than the top-level module.
    Examples:
        "secure_cache" -> False (top-level)
        "secure_cache.redis._pool" -> True (internal)
        "secure_cache.config" -> True (submodule)
    """
    parts = import_module.split(".")
    return len(parts) > 1


def is_import_on_public_surface(
    import_module: str,
    imported_names: List[str],
    all_surfaces: Dict[str, Set[str]],
    registry_surfaces: Dict[str, Set[str]],
) -> bool:
    """Check if an import resolves through the target's public surface.

    A cross-package import is allowed if:
    1. It imports directly from the top-level module and the names are in __all__
    2. The full import path + symbol is in the shared-abstraction-registry
    """
    top_module = import_module.split(".")

    # Case 1: Direct top-level import ("from neoaxios_secure_cache import X")
    if len(top_module) == 1:
        module_name = top_module[0]
        surface = all_surfaces.get(module_name, set())
        if imported_names:
            return all(name in surface for name in imported_names)
        # Plain `import neoaxios_secure_cache` is always fine
        return True

    # Case 2: Submodule import -- check if the specific path+names are in registry
    full_module = import_module
    top_mod = top_module[0]

    # Check registry surfaces for the full module path.
    # If the module path exists as a key in registry_surfaces, it means the
    # shared-abstraction-registry lists it as a canonical import source.
    # Any import from a registry-recognized module path is allowed -- the
    # registry entry signals "this submodule is a public surface", not just
    # the specific example symbol listed.
    if full_module in registry_surfaces:
        return True

    # Check if imported names are on the top-level __all__
    # (importing from submodule but the symbol is re-exported at top level)
    top_surface = all_surfaces.get(top_mod, set())
    if imported_names and top_surface:
        if all(name in top_surface for name in imported_names):
            # The name IS on the public surface, but import path goes through internals
            # This is still a violation -- should import from top level
            return False

    return False


def find_suggestion(
    import_module: str,
    imported_names: List[str],
    all_surfaces: Dict[str, Set[str]],
    registry_surfaces: Dict[str, Set[str]],
) -> str:
    """Generate a suggestion for the correct import path."""
    top_module = import_module.split(".")[0]
    top_surface = all_surfaces.get(top_module, set())

    # Check if any imported names exist in the top-level __all__
    suggestions = []
    for name in imported_names:
        if name in top_surface:
            suggestions.append(f"from {top_module} import {name}")

    if suggestions:
        return ", ".join(suggestions)

    # Check registry for the correct import path
    for reg_module, reg_symbols in registry_surfaces.items():
        for name in imported_names:
            if name in reg_symbols:
                suggestions.append(f"from {reg_module} import {name}")

    if suggestions:
        return ", ".join(suggestions)

    # Fallback: suggest the top-level import
    if imported_names:
        return f"from {top_module} import <public symbol>"
    return f"import {top_module}"


def check_file_boundaries(
    file_path: Path,
    source_package: str,
    module_to_package: Dict[str, str],
    all_surfaces: Dict[str, Set[str]],
    registry_surfaces: Dict[str, Set[str]],
    exemptions: Set[str],
) -> List[Violation]:
    """Check a single file for import boundary violations."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    imports = extract_structured_imports(source)
    violations: List[Violation] = []

    for imp in imports:
        # Check if this targets another neo-package
        target_pkg = is_cross_package_import(
            imp.module, source_package, module_to_package
        )
        if target_pkg is None:
            continue

        # Skip if the import is exempted
        if imp.module in exemptions:
            continue

        # Top-level imports are always fine
        if not is_internal_import(imp.module):
            # "from neoaxios_secure_cache import X" or "import neoaxios_secure_cache"
            # Check that imported names are on public surface
            top_module = imp.module.split(".")[0]
            top_surface = all_surfaces.get(top_module, set())
            if not imp.names:
                # Plain `import X` -- always OK for top-level
                continue
            if top_surface and all(name in top_surface for name in imp.names):
                continue
            if not top_surface:
                # No __all__ defined -- can't enforce, skip with warning
                continue
            # Names not in __all__ -- violation
            for name in imp.names:
                if name not in top_surface:
                    violations.append(Violation(
                        source_file=file_path,
                        source_package=source_package,
                        import_module=f"{imp.module}.{name}",
                        target_package=target_pkg,
                        suggestion=find_suggestion(
                            imp.module, [name], all_surfaces, registry_surfaces
                        ),
                    ))
            continue

        # Submodule import -- check if it's on public surface via registry
        if is_import_on_public_surface(
            imp.module, imp.names, all_surfaces, registry_surfaces
        ):
            continue

        # This is a boundary violation
        suggestion = find_suggestion(
            imp.module, imp.names, all_surfaces, registry_surfaces
        )
        violations.append(Violation(
            source_file=file_path,
            source_package=source_package,
            import_module=imp.module,
            target_package=target_pkg,
            suggestion=suggestion,
        ))

    return violations


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate cross-package import boundaries across configured package roots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                  # Validate all packages
  %(prog)s --package secure_cache           # Validate specific package only
  %(prog)s -v                               # Verbose output
  %(prog)s --repo-root /path/to/repo        # Custom repo root
        """,
    )

    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory (default: current directory)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output (show per-file scanning details)",
    )

    parser.add_argument(
        "--package",
        type=str,
        default=None,
        help="Filter to files belonging to a specific package (module name)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point. Returns 0 if clean, 1 if violations found."""
    args = parse_args()
    repo_root = args.repo_root.resolve()

    print("=" * 60)
    print("  Import Boundary Validation")
    print("=" * 60)
    print()

    # Load config once — all helpers receive roots as parameter
    from neoaxios.build.config import load_build_config
    config = load_build_config(repo_root)
    roots = config.roots_for_validator("import_boundaries")

    # Build module-to-package mapping
    module_to_package = build_module_to_package_map(repo_root, roots)
    if args.verbose:
        print(f"Discovered {len(module_to_package)} module-to-package mappings")

    # Build public surfaces from __all__
    all_surfaces = build_public_surfaces(repo_root, module_to_package, roots)
    if args.verbose:
        print(f"Loaded __all__ surfaces for {len(all_surfaces)} packages")

    # Build registry surfaces
    registry_surfaces = build_registry_surfaces(repo_root)
    if args.verbose:
        registry_symbol_count = sum(len(v) for v in registry_surfaces.values())
        print(f"Loaded {registry_symbol_count} registry import paths")

    # Load exemptions
    package_exemptions = load_package_exemptions(repo_root, module_to_package, roots)
    total_exemptions = sum(len(v) for v in package_exemptions.values())
    if args.verbose and total_exemptions:
        print(f"Loaded {total_exemptions} exemption(s) across "
              f"{len(package_exemptions)} package(s)")

    # Discover source files
    source_files = discover_source_files(repo_root, roots)
    if args.verbose:
        print(f"Discovered {len(source_files)} source files")
    print()

    # Check each file
    all_violations: List[Violation] = []
    files_checked = 0

    for file_path in source_files:
        source_package = determine_owning_package(file_path, repo_root, roots)
        if source_package is None:
            continue

        # Apply package filter
        if args.package:
            # Match by module name from the relative path under any root
            rel_path = file_path.relative_to(repo_root)
            rel_parts = rel_path.parts
            if "src" in rel_parts:
                src_idx = rel_parts.index("src")
                if src_idx + 1 < len(rel_parts):
                    file_module = rel_parts[src_idx + 1]
                    if file_module != args.package:
                        continue

        # Get exemptions for this package
        exemptions = package_exemptions.get(source_package, set())

        if args.verbose:
            print(f"  Scanning: {file_path.relative_to(repo_root)}")

        violations = check_file_boundaries(
            file_path=file_path,
            source_package=source_package,
            module_to_package=module_to_package,
            all_surfaces=all_surfaces,
            registry_surfaces=registry_surfaces,
            exemptions=exemptions,
        )
        all_violations.extend(violations)
        files_checked += 1

    # Report results
    print(f"Checked {files_checked} files")
    if total_exemptions:
        print(f"Exemptions: {total_exemptions} import path(s) exempted")
        for pkg, paths in sorted(package_exemptions.items()):
            for p in sorted(paths):
                print(f"  {pkg}: {p}")
    print()

    if all_violations:
        print(f"FAILED: {len(all_violations)} boundary violation(s) found")
        print()
        # Group violations by source package for readability
        by_package: Dict[str, List[Violation]] = {}
        for v in all_violations:
            by_package.setdefault(v.source_package, []).append(v)

        for pkg, violations in sorted(by_package.items()):
            print(f"[{pkg}]")
            for v in violations:
                print(v.format_message())
            print()

        return 1

    print("PASSED: All cross-package imports use public surfaces")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
