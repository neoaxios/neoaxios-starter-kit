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
"""
Telemetry Coverage Validation Script

Validates that all production source files have proper Logbook telemetry
instrumentation across the NeoAxios packages.

Exit Codes:
    0: 100% coverage achieved
    1: Missing telemetry in one or more files
"""

import argparse
import ast
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add build system to path for shared AST utilities
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from neoaxios.build.ast_utils import get_decorator_name


@dataclass
class FunctionAnalysis:
    """Analysis results for a single function."""

    name: str
    line_number: int
    is_async: bool
    has_auto_trace: bool
    is_private: bool = False  # Starts with _
    is_dunder: bool = False  # Starts with __
    has_notrace: bool = False  # Has # notrace: <reason> marker


@dataclass
class FileAnalysis:
    """Analysis results for a single Python file."""

    path: Path
    has_telemetry_import: bool
    has_auto_trace_import: bool
    has_logger_init: bool
    is_instrumented: bool
    functions_count: int
    functions_traced: int
    functions: List[FunctionAnalysis] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.functions is None:
            self.functions = []


@dataclass
class PackageReport:
    """Coverage report for a single package."""

    name: str
    total_files: int
    instrumented_files: int
    missing_files: List[Path]

    @property
    def coverage_percent(self) -> float:
        """Calculate coverage percentage."""
        if self.total_files == 0:
            return 100.0
        return (self.instrumented_files / self.total_files) * 100


class AutoTraceDetector(ast.NodeVisitor):
    """AST visitor to detect @auto_trace decorator usage on functions."""

    def __init__(self, source_lines: Optional[List[str]] = None):
        self.functions: List[FunctionAnalysis] = []
        self._nesting_depth = 0  # Track function nesting
        self._source_lines = source_lines or []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function definition for @auto_trace decorator."""
        self._analyze_function(node, is_async=False)
        # Track nesting for child functions
        self._nesting_depth += 1
        self.generic_visit(node)
        self._nesting_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Analyze async function definition for @auto_trace decorator."""
        self._analyze_function(node, is_async=True)
        # Track nesting for child functions
        self._nesting_depth += 1
        self.generic_visit(node)
        self._nesting_depth -= 1

    def _analyze_function(self, node, is_async: bool):
        """Analyze a function node for @auto_trace decorator."""
        func_name = node.name
        line_number = node.lineno
        is_private = func_name.startswith('_') and not func_name.startswith('__')
        is_dunder = func_name.startswith('__') and func_name.endswith('__')

        # Skip nested functions (closures, route handlers, inner helpers)
        # These are typically high-frequency or implementation details
        if self._nesting_depth > 0:
            return

        # Skip protocol method stubs (methods with only ... or pass as body)
        # These are abstract interface definitions with no implementation
        if self._is_protocol_stub(node):
            return

        # Skip Pydantic validators (high-frequency, called on every model instantiation)
        # These are decorated with @field_validator, @model_validator, @validator, @root_validator
        if self._is_pydantic_validator(node):
            return

        # Skip property methods (simple getters, no side effects)
        if self._is_property(node):
            return

        # Check for # notrace: <reason> marker on def line or line above
        has_notrace = self._has_notrace_marker(line_number)

        # Check for @auto_trace decorator
        has_auto_trace = False

        for decorator in node.decorator_list:
            decorator_name = get_decorator_name(decorator)
            if decorator_name == 'auto_trace':
                has_auto_trace = True
                break

        self.functions.append(FunctionAnalysis(
            name=func_name,
            line_number=line_number,
            is_async=is_async,
            has_auto_trace=has_auto_trace,
            is_private=is_private,
            is_dunder=is_dunder,
            has_notrace=has_notrace,
        ))

    def _is_protocol_stub(self, node) -> bool:
        """Check if function is a protocol stub (body is only ... or pass).

        Protocol stubs are abstract interface definitions that have no
        implementation. They don't need @auto_trace since there's no code to trace.

        Handles cases:
        - Body is just `...`
        - Body is just `pass`
        - Body is docstring followed by `...` or `pass`
        """
        body = node.body

        # Skip leading docstring if present
        start_idx = 0
        if body and isinstance(body[0], ast.Expr):
            if isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                start_idx = 1  # Skip docstring

        # After docstring, should only have one statement
        remaining = body[start_idx:]
        if len(remaining) != 1:
            return False

        stmt = remaining[0]

        # Check for ... (Ellipsis) - handles both ast.Constant and legacy ast.Ellipsis
        if isinstance(stmt, ast.Expr):
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
                return True
            # ast.Ellipsis is deprecated in Python 3.14, but check for compatibility
            if hasattr(ast, 'Ellipsis') and isinstance(stmt.value, getattr(ast, 'Ellipsis', type(None))):
                return True

        # Check for pass statement
        if isinstance(stmt, ast.Pass):
            return True

        return False

    def _is_pydantic_validator(self, node) -> bool:
        """Check if function is a Pydantic validator.

        Pydantic validators are called on every model instantiation which would
        create excessive log noise. They are decorated with:
        - @field_validator (Pydantic v2)
        - @model_validator (Pydantic v2)
        - @validator (Pydantic v1, deprecated)
        - @root_validator (Pydantic v1, deprecated)
        """
        pydantic_decorators = {
            'field_validator',
            'model_validator',
            'validator',
            'root_validator',
        }

        for decorator in node.decorator_list:
            decorator_name = get_decorator_name(decorator)
            if decorator_name in pydantic_decorators:
                return True

        return False

    def _is_property(self, node) -> bool:
        """Check if function is a property getter/setter.

        Properties are simple attribute accessors that typically have no side
        effects and are called frequently. Tracing them would create log noise.
        """
        property_decorators = {
            'property',
            'cached_property',
            'functools.cached_property',
        }

        for decorator in node.decorator_list:
            decorator_name = get_decorator_name(decorator)
            if decorator_name in property_decorators:
                return True
            # Also check for property.setter, property.getter, property.deleter
            if isinstance(decorator, ast.Attribute):
                if decorator.attr in ('setter', 'getter', 'deleter'):
                    return True

        return False

    def _has_notrace_marker(self, line_number: int) -> bool:
        """Check if function has a # notrace: <reason> comment.

        Checks the def line itself and the line immediately above it.
        The marker must have a non-empty reason after the colon.
        """
        for offset in (0, -1):
            idx = line_number - 1 + offset  # Convert 1-based to 0-based
            if 0 <= idx < len(self._source_lines):
                line = self._source_lines[idx]
                if '# notrace:' in line:
                    # Verify reason is non-empty
                    marker_pos = line.index('# notrace:')
                    reason = line[marker_pos + len('# notrace:'):].strip()
                    if reason:
                        return True
        return False


class TelemetryValidator:
    """Validates telemetry coverage across Python source files."""

    # Patterns to identify telemetry instrumentation
    TELEMETRY_IMPORT_PATTERNS = [
        r'from\s+telemetry\s+import\s+.*get_telemetry',
        r'from\s+\.telemetry\s+import\s+.*get_telemetry',
        r'from\s+\.\.\s*telemetry\s+import\s+.*get_telemetry',
    ]

    # Patterns for auto_trace import
    AUTO_TRACE_IMPORT_PATTERNS = [
        r'from\s+telemetry\s+import\s+.*auto_trace',
        r'from\s+telemetry\.logbook\.core\.decorators\s+import\s+.*auto_trace',
        r'from\s+telemetry\.logbook\s+import\s+.*auto_trace',
    ]

    LOGGER_INIT_PATTERN = r'logger\s*=\s*get_telemetry\s*\(\s*__name__\s*\)'

    # Files and directories to exclude
    EXCLUDE_PATTERNS = {
        '__init__.py',
        '__pycache__',
        'tests',
        'testing',
        'test_',
        'conftest.py',
        '.pyc',
    }

    def __init__(self, root_path: Path, verbose: bool = False):
        """
        Initialize the validator.

        Args:
            root_path: Root directory of the project
            verbose: Enable verbose output
        """
        self.root_path = root_path
        self.verbose = verbose

        # Load package roots from build.yaml for the telemetry validator
        from neoaxios.build.config import load_build_config, PackageRoot
        config = load_build_config(root_path)
        self._roots = config.roots_for_validator("telemetry")

    def should_exclude(self, file_path: Path) -> bool:
        """
        Check if a file should be excluded from analysis.

        Args:
            file_path: Path to check

        Returns:
            True if file should be excluded
        """
        # Check filename and parent directories
        for pattern in self.EXCLUDE_PATTERNS:
            # 'test_' pattern should only match files starting with 'test_'
            if pattern == 'test_':
                if file_path.name.startswith('test_'):
                    return True
                if any(part.startswith('test_') for part in file_path.parts):
                    return True
            else:
                if pattern in file_path.name:
                    return True
                if any(pattern in part for part in file_path.parts):
                    return True

        return False

    def has_functions(self, file_path: Path) -> Tuple[bool, int]:
        """
        Check if a Python file contains function definitions.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (has_functions, function_count)
        """
        try:
            content = file_path.read_text(encoding='utf-8')
            tree = ast.parse(content)

            function_count = 0
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function_count += 1

            return function_count > 0, function_count
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Error parsing {file_path}: {e}")
            return False, 0

    def analyze_file(self, file_path: Path) -> FileAnalysis:
        """
        Analyze a single Python file for telemetry instrumentation.

        Args:
            file_path: Path to Python file

        Returns:
            FileAnalysis with results
        """
        try:
            content = file_path.read_text(encoding='utf-8')

            # Check for telemetry import
            has_import = any(
                re.search(pattern, content)
                for pattern in self.TELEMETRY_IMPORT_PATTERNS
            )

            # Check for auto_trace import
            has_auto_trace_import = any(
                re.search(pattern, content)
                for pattern in self.AUTO_TRACE_IMPORT_PATTERNS
            )

            # Check for logger initialization
            has_logger = bool(re.search(self.LOGGER_INIT_PATTERN, content))

            # Parse AST and detect @auto_trace decorators on functions
            source_lines = content.splitlines()
            tree = ast.parse(content)
            detector = AutoTraceDetector(source_lines=source_lines)
            detector.visit(tree)

            # Filter to public functions only (exclude dunder methods like __init__)
            public_functions = [
                f for f in detector.functions
                if not f.is_dunder
            ]

            # Count traced functions (auto_trace OR notrace marker)
            functions_traced = sum(
                1 for f in public_functions
                if f.has_auto_trace or f.has_notrace
            )
            func_count = len(public_functions)

            # File is considered instrumented if:
            # 1. Has no public functions (utility/constant files), OR
            # 2. All public functions have @auto_trace decorator or # notrace marker
            #    - If ANY function uses @auto_trace, the file must also have
            #      the telemetry import and logger init
            #    - If ALL functions use # notrace: (none use @auto_trace),
            #      import/logger are not required (e.g., circular import constraint)
            if func_count == 0:
                is_instrumented = True
            else:
                all_covered = all(
                    f.has_auto_trace or f.has_notrace for f in public_functions
                )
                any_traced = any(f.has_auto_trace for f in public_functions)
                if all_covered and any_traced:
                    is_instrumented = has_import and has_logger
                elif all_covered:
                    # All functions explicitly opted out via # notrace:
                    is_instrumented = True
                else:
                    is_instrumented = False

            return FileAnalysis(
                path=file_path,
                has_telemetry_import=has_import,
                has_auto_trace_import=has_auto_trace_import,
                has_logger_init=has_logger,
                is_instrumented=is_instrumented,
                functions_count=func_count,
                functions_traced=functions_traced,
                functions=public_functions,
            )

        except Exception as e:
            return FileAnalysis(
                path=file_path,
                has_telemetry_import=False,
                has_auto_trace_import=False,
                has_logger_init=False,
                is_instrumented=False,
                functions_count=0,
                functions_traced=0,
                functions=[],
                error=str(e)
            )

    def scan_package(self, package_path: Path) -> List[FileAnalysis]:
        """
        Scan all Python files in a package.

        Args:
            package_path: Path to package directory

        Returns:
            List of FileAnalysis results
        """
        results = []

        # Try to find source directory - packages may use src/ or have code directly
        src_path = package_path / "src"
        if not src_path.exists():
            # Look for Python package directories (contain __init__.py or *.py files)
            # Common patterns: package_name/, telemetry/, etc.
            for item in package_path.iterdir():
                if item.is_dir() and not item.name.startswith('.') and item.name not in {
                    'tests', 'docs', 'examples', 'scripts', 'build', 'dist',
                    '__pycache__', '.pytest_cache', '.git', 'templates'
                }:
                    # Check if it looks like a Python package
                    if (item / '__init__.py').exists() or list(item.glob('*.py')):
                        src_path = item
                        break

        if not src_path.exists():
            if self.verbose:
                print(f"  ℹ️  No source directory found in {package_path.name}")
            return results

        # Find all Python files
        for py_file in src_path.rglob("*.py"):
            if self.should_exclude(py_file):
                if self.verbose:
                    print(f"  ⏭️  Skipping {py_file.relative_to(src_path)}")
                continue

            if self.verbose:
                print(f"  🔍 Analyzing {py_file.relative_to(src_path)}")

            analysis = self.analyze_file(py_file)
            results.append(analysis)

        return results

    def generate_package_report(
        self,
        package_name: str,
        analyses: List[FileAnalysis]
    ) -> PackageReport:
        """
        Generate coverage report for a package.

        Args:
            package_name: Name of the package
            analyses: List of file analyses

        Returns:
            PackageReport with coverage data
        """
        total = len(analyses)
        instrumented = sum(1 for a in analyses if a.is_instrumented)
        missing = [a.path for a in analyses if not a.is_instrumented]

        return PackageReport(
            name=package_name,
            total_files=total,
            instrumented_files=instrumented,
            missing_files=missing
        )

    def validate_all_packages(
        self,
        target_package: Optional[str] = None
    ) -> Tuple[Dict[str, PackageReport], Dict[str, List[FileAnalysis]]]:
        """
        Validate telemetry coverage across all packages.

        Args:
            target_package: Optional specific package to check

        Returns:
            Tuple of (reports dict, analyses dict)
        """
        reports = {}
        all_analyses = {}

        from neoaxios.build.config import discover_package_dirs, find_package_in_roots

        # Get list of packages to scan from configured roots
        packages: list = []
        if target_package:
            result = find_package_in_roots(target_package, self.root_path, self._roots)
            if result:
                packages = [result]
            else:
                print(f"❌ Package not found: {target_package}")
                sys.exit(1)
        else:
            packages = discover_package_dirs(
                self.root_path, self._roots, require_src=True
            )

        if not packages:
            print("❌ No packages found in configured roots")
            sys.exit(1)

        # Scan each package
        for package_name, package_path in packages:

            if self.verbose:
                print(f"\n📦 Scanning package: {package_name}")

            analyses = self.scan_package(package_path)
            report = self.generate_package_report(package_name, analyses)
            reports[package_name] = report
            all_analyses[package_name] = analyses

        return reports, all_analyses

    def print_report(
        self,
        reports: Dict[str, PackageReport],
        all_analyses: Dict[str, List[FileAnalysis]]
    ) -> bool:
        """
        Print formatted coverage report.

        Args:
            reports: Dictionary of package reports
            all_analyses: Dictionary of all file analyses by package

        Returns:
            True if 100% coverage, False otherwise
        """
        print("\n" + "=" * 70)
        print("Telemetry Coverage Report (Function-Level)")
        print("=" * 70 + "\n")

        total_files = 0
        total_instrumented = 0
        total_functions = 0
        total_traced = 0
        all_missing: List[Tuple[str, Path, List[FunctionAnalysis]]] = []

        # Print per-package reports
        for package_name in sorted(reports.keys()):
            report = reports[package_name]
            analyses = all_analyses.get(package_name, [])

            total_files += report.total_files
            total_instrumented += report.instrumented_files

            # Calculate function-level stats for this package
            pkg_functions = sum(a.functions_count for a in analyses)
            pkg_traced = sum(a.functions_traced for a in analyses)

            total_functions += pkg_functions
            total_traced += pkg_traced

            # Status indicator
            if report.coverage_percent == 100:
                status = "✅"
            else:
                status = "⚠️ "
                for analysis in analyses:
                    if not analysis.is_instrumented:
                        missing_funcs = [
                            f for f in analysis.functions
                            if not f.has_auto_trace and not f.has_notrace
                        ]
                        all_missing.append((package_name, analysis.path, missing_funcs))

            print(f"Package: {package_name}")
            print(
                f"  {status} Files: {report.instrumented_files}/{report.total_files} "
                f"({report.coverage_percent:.1f}%)"
            )

            if pkg_functions > 0:
                func_coverage = (pkg_traced / pkg_functions) * 100
                print(
                    f"     Functions: {pkg_traced} traced, "
                    f"{pkg_functions - pkg_traced} missing ({func_coverage:.1f}%)"
                )

            # Show missing files and functions
            if report.missing_files:
                for analysis in analyses:
                    if not analysis.is_instrumented:
                        try:
                            # Try to make a readable relative path via any root
                            displayed = False
                            for root in self._roots:
                                root_dir = self.root_path / root.path
                                try:
                                    rel_from_root = analysis.path.relative_to(root_dir)
                                    # Find src/ within the relative path
                                    parts = rel_from_root.parts
                                    if "src" in parts:
                                        src_idx = parts.index("src")
                                        display_path = "/".join(parts[:src_idx]) + "/src/" + "/".join(parts[src_idx + 1:])
                                        print(f"    ❌ {display_path}")
                                        displayed = True
                                        break
                                except ValueError:
                                    continue
                            if not displayed:
                                print(f"    ❌ {analysis.path}")
                        except Exception:
                            print(f"    ❌ {analysis.path}")

                        # Show missing functions
                        missing_funcs = [
                            f for f in analysis.functions
                            if not f.has_auto_trace and not f.has_notrace
                        ]
                        for func in missing_funcs[:5]:  # Limit to 5 per file
                            print(f"       Line {func.line_number}: {func.name}()")
                        if len(missing_funcs) > 5:
                            print(f"       ... and {len(missing_funcs) - 5} more")

            print()

        # Print overall summary
        print("-" * 70)
        if total_files == 0:
            print("No files found to analyze")
            return True

        overall_file_percent = (total_instrumented / total_files) * 100
        print(f"Files: {total_instrumented}/{total_files} ({overall_file_percent:.1f}%)")

        if total_functions > 0:
            overall_func_percent = (total_traced / total_functions) * 100
            print(
                f"Functions: {total_traced} traced / "
                f"{total_functions} total ({overall_func_percent:.1f}%)"
            )

        if overall_file_percent == 100:
            print("\nStatus: ✅ COMPLETE - 100% coverage achieved!")
            return True
        else:
            missing_count = sum(
                len([f for f in funcs if not f.has_auto_trace])
                for _, _, funcs in all_missing
            )
            print(
                f"\nStatus: ⚠️  INCOMPLETE - {len(all_missing)} files, "
                f"{missing_count} functions missing @auto_trace"
            )
            return False


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate telemetry coverage across NeoAxios packages",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--package",
        type=str,
        help="Specific package to check (e.g., 'neoaxios_fastapi_kit')"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Root directory of the project (default: current directory)"
    )

    args = parser.parse_args()

    # Initialize validator
    validator = TelemetryValidator(
        root_path=args.root,
        verbose=args.verbose
    )

    # Validate packages
    reports, all_analyses = validator.validate_all_packages(target_package=args.package)

    # Print report and determine exit code
    complete = validator.print_report(reports, all_analyses)

    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
