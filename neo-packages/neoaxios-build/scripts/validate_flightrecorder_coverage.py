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
FlightRecorder Coverage Validation Script

Validates that integration/E2E tests use FlightRecorder for observability.
Scans configured package roots for integration tests and checks FlightRecorder usage.

Usage:
    python validate_flightrecorder_coverage.py                 # Check all packages
    python validate_flightrecorder_coverage.py --verbose       # Detailed output
    python validate_flightrecorder_coverage.py --package=neoaxios_fastapi_kit  # Specific package
"""

import ast
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Add build system to path for shared AST utilities
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from neoaxios.build.ast_utils import get_decorator_name


@dataclass
class TestFile:
    """Represents a test file with metadata."""
    path: Path
    package: str
    is_integration: bool
    has_flightrecorder: bool
    reasons: List[str]  # Why it's classified as integration test
    line_count: int
    test_count: int


class IntegrationTestDetector(ast.NodeVisitor):
    """AST visitor to detect integration test patterns."""

    # Common FlightRecorder fixture names
    FLIGHTRECORDER_FIXTURE_NAMES = {
        'flight_recorder',
        'flightrecorder',
        'fr',
        'recorder',
        'test_recorder',
    }

    def __init__(self):
        self.is_integration = False
        self.has_flightrecorder = False
        self.has_flightrecorder_fixture = False
        self.reasons = []
        self.test_count = 0
        self.has_real_io = False
        self.has_session_fixtures = False
        self.has_asyncio = False
        self.has_long_tests = False
        self.imports = set()

    def visit_Import(self, node: ast.Import):
        """Track imports."""
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports."""
        if node.module:
            self.imports.add(node.module)
            # Check for FlightRecorder import
            if node.module == "telemetry.flight_recorder":
                for alias in node.names:
                    if alias.name == "FlightRecorder":
                        self.has_flightrecorder = True
            # Also check for flight_recorded decorator
            if "flight_recorder" in node.module or "telemetry" in node.module:
                for alias in node.names:
                    if alias.name in ("flight_recorded", "FlightRecorder"):
                        self.has_flightrecorder = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze test functions."""
        func_name = node.name

        # Count test functions
        if func_name.startswith("test_"):
            self.test_count += 1

            # Check for FlightRecorder fixture in function parameters
            for arg in node.args.args:
                arg_name = arg.arg
                if arg_name in self.FLIGHTRECORDER_FIXTURE_NAMES:
                    self.has_flightrecorder = True
                    self.has_flightrecorder_fixture = True

            # Check for integration test patterns in name
            integration_keywords = [
                "_integration", "_e2e", "_workflow", "test_full_",
                "_end_to_end", "_e2e_", "_real_"
            ]
            for keyword in integration_keywords:
                if keyword in func_name:
                    self.is_integration = True
                    self.reasons.append(f"Test name pattern: '{func_name}'")
                    break

            # Check for asyncio usage (common in integration tests)
            if node.returns and isinstance(node.returns, ast.Name):
                if "Coroutine" in ast.unparse(node.returns):
                    self.has_asyncio = True

            # Check for session-scoped fixtures
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    if hasattr(decorator.func, 'attr') and decorator.func.attr == 'fixture':
                        for keyword in decorator.keywords:
                            if keyword.arg == 'scope' and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value == 'session':
                                    self.has_session_fixtures = True

            # Check for pytest.mark.e2e or pytest.mark.integration
            for decorator in node.decorator_list:
                decorator_str = ast.unparse(decorator)
                if any(marker in decorator_str for marker in ['@pytest.mark.e2e', '@pytest.mark.integration', '@pytest.mark.e2e_']):
                    self.is_integration = True
                    self.reasons.append(f"Pytest marker: {decorator_str}")

            # Check for flight_recorded decorator
            for decorator in node.decorator_list:
                decorator_name = get_decorator_name(decorator)
                if decorator_name == 'flight_recorded':
                    self.has_flightrecorder = True

            # Check function body for integration patterns
            self._analyze_function_body(node)

        self.generic_visit(node)

    def _analyze_function_body(self, node: ast.FunctionDef):
        """Analyze function body for integration patterns."""
        body_str = ast.unparse(node)

        # Check for I/O operations (not mocked)
        io_patterns = [
            'requests.', 'httpx.', 'aiohttp.',  # HTTP clients
            'subprocess.', 'Popen(',  # Process execution
            'open(', 'Path.open', 'with open',  # File I/O
            'socket.', 'asyncio.open_connection',  # Network
            'ssh.', 'paramiko.',  # SSH
            'docker.', 'kubernetes.',  # Container orchestration
        ]

        # Check for absence of mocking (strong indicator of integration test)
        has_mock = any(pattern in body_str for pattern in ['Mock(', 'MagicMock', 'patch(', 'mock.'])

        for pattern in io_patterns:
            if pattern in body_str and not has_mock:
                self.has_real_io = True
                self.reasons.append(f"Real I/O detected: {pattern}")
                break

        # Check for FlightRecorder instantiation
        if 'FlightRecorder(' in body_str:
            self.has_flightrecorder = True

    def visit_ClassDef(self, node: ast.ClassDef):
        """Analyze test classes."""
        class_name = node.name

        # Check for integration test patterns in class name
        if any(keyword in class_name.lower() for keyword in ['integration', 'e2e', 'endtoend', 'workflow']):
            self.is_integration = True
            self.reasons.append(f"Class name pattern: '{class_name}'")

        self.generic_visit(node)


def check_conftest_for_flightrecorder(test_dir: Path) -> bool:
    """
    Check if conftest.py files in the test directory define FlightRecorder fixtures.

    Args:
        test_dir: Path to test directory

    Returns:
        True if FlightRecorder fixture is defined in conftest
    """
    # Check conftest files from current dir up to tests root
    current = test_dir
    while current.name != 'tests' and current.parent != current:
        conftest = current / 'conftest.py'
        if conftest.exists():
            try:
                content = conftest.read_text()
                # Check for FlightRecorder fixture definition
                if 'FlightRecorder' in content and '@pytest.fixture' in content:
                    return True
                if 'flight_recorder' in content and '@pytest.fixture' in content:
                    return True
            except Exception:
                pass
        current = current.parent

    # Also check tests/conftest.py
    tests_conftest = test_dir
    while tests_conftest.name != 'tests' and tests_conftest.parent != tests_conftest:
        tests_conftest = tests_conftest.parent
    conftest = tests_conftest / 'conftest.py'
    if conftest.exists():
        try:
            content = conftest.read_text()
            if 'FlightRecorder' in content and '@pytest.fixture' in content:
                return True
            if 'flight_recorder' in content and '@pytest.fixture' in content:
                return True
        except Exception:
            pass

    return False


def analyze_test_file(file_path: Path, package: str, conftest_has_fr: bool = False) -> TestFile:
    """Analyze a single test file."""
    try:
        content = file_path.read_text()
        tree = ast.parse(content)

        detector = IntegrationTestDetector()
        detector.visit(tree)

        line_count = len(content.splitlines())

        # Additional heuristics based on file metadata
        file_name = file_path.stem

        # Check filename patterns
        if any(pattern in file_name for pattern in ['integration', 'e2e', 'workflow', 'end_to_end']):
            detector.is_integration = True
            detector.reasons.append(f"Filename pattern: '{file_name}'")

        # Check if file is in integration/e2e subdirectory
        if 'integration' in file_path.parts or 'e2e' in file_path.parts:
            detector.is_integration = True
            detector.reasons.append(f"Directory structure: {'/'.join(file_path.parts[-3:])}")

        # Large test files (>150 LOC) with multiple tests suggest integration
        if line_count > 150 and detector.test_count > 5:
            if detector.has_asyncio or detector.has_real_io:
                detector.is_integration = True
                detector.reasons.append(f"Large file with I/O: {line_count} LOC, {detector.test_count} tests")

        # Files with real I/O and asyncio are likely integration tests
        if detector.has_real_io and detector.has_asyncio:
            detector.is_integration = True
            if "Real I/O" not in str(detector.reasons):
                detector.reasons.append("Async operations with real I/O")

        # Session fixtures indicate integration tests
        if detector.has_session_fixtures:
            detector.is_integration = True
            detector.reasons.append("Session-scoped fixtures")

        # If conftest defines FlightRecorder fixture and test uses it via fixture param,
        # mark as having FlightRecorder
        if conftest_has_fr and detector.has_flightrecorder_fixture:
            detector.has_flightrecorder = True

        return TestFile(
            path=file_path,
            package=package,
            is_integration=detector.is_integration,
            has_flightrecorder=detector.has_flightrecorder,
            reasons=detector.reasons,
            line_count=line_count,
            test_count=detector.test_count
        )

    except Exception as e:
        print(f"Error analyzing {file_path}: {e}", file=sys.stderr)
        return TestFile(
            path=file_path,
            package=package,
            is_integration=False,
            has_flightrecorder=False,
            reasons=[f"Error: {e}"],
            line_count=0,
            test_count=0
        )


def scan_packages(repo_root: Path, target_package: str = None) -> Dict[str, List[TestFile]]:
    """Scan all packages for test files."""
    from neoaxios.build.config import load_build_config, discover_package_dirs, find_package_in_roots

    config = load_build_config(repo_root)
    roots = config.roots_for_validator("flightrecorder")
    results = defaultdict(list)

    # Build list of packages from configured roots
    packages = []
    if target_package:
        result = find_package_in_roots(target_package, repo_root, roots)
        if result:
            packages.append(result)
        else:
            print(f"Error: Package not found: {target_package}", file=sys.stderr)
            sys.exit(1)
    else:
        packages = discover_package_dirs(
            repo_root, roots, require_src=False
        )
        # Filter to only packages with a tests directory
        packages = [(name, path) for name, path in packages if (path / "tests").exists()]

    for package_name, package_dir in sorted(packages):
        tests_dir = package_dir / "tests"
        if not tests_dir.exists():
            continue

        # Check if conftest defines FlightRecorder fixture (cache per tests_dir)
        conftest_fr_cache = {}

        # Find all test files recursively
        for test_file in sorted(tests_dir.rglob("test_*.py")):
            # Check conftest for this test file's directory
            test_parent = test_file.parent
            if test_parent not in conftest_fr_cache:
                conftest_fr_cache[test_parent] = check_conftest_for_flightrecorder(test_parent)

            conftest_has_fr = conftest_fr_cache[test_parent]
            test_data = analyze_test_file(test_file, package_name, conftest_has_fr)
            results[package_name].append(test_data)

    return results


def generate_report(results: Dict[str, List[TestFile]], verbose: bool = False) -> Tuple[int, int, int]:
    """Generate coverage report."""
    total_integration = 0
    total_instrumented = 0
    total_files = 0

    print("\nFlightRecorder Coverage Report")
    print("=" * 70)
    print()

    # Sort packages by name
    for package in sorted(results.keys()):
        test_files = results[package]
        total_files += len(test_files)

        # Filter integration tests
        integration_tests = [t for t in test_files if t.is_integration]
        instrumented = [t for t in integration_tests if t.has_flightrecorder]

        total_integration += len(integration_tests)
        total_instrumented += len(instrumented)

        if len(integration_tests) == 0:
            print(f"Package: {package}")
            print(f"  ℹ️  0 integration tests (all unit tests)")
            print()
            continue

        # Calculate coverage
        coverage_pct = (len(instrumented) / len(integration_tests) * 100) if integration_tests else 0

        # Status indicator
        if coverage_pct == 100:
            status = "✅"
        elif coverage_pct >= 80:
            status = "⚠️"
        else:
            status = "❌"

        print(f"Package: {package}")
        print(f"  {status} {len(instrumented)}/{len(integration_tests)} integration tests instrumented ({coverage_pct:.0f}%)")

        if instrumented:
            print(f"  Files: {', '.join(sorted(set(t.path.name for t in instrumented)))}")

        # Show missing instrumentation
        missing = [t for t in integration_tests if not t.has_flightrecorder]
        if missing:
            print(f"  Missing FlightRecorder:")
            for test in missing:
                rel_path = test.path.relative_to(test.path.parent.parent.parent)
                print(f"    - {rel_path}")
                if verbose:
                    print(f"      Reasons: {', '.join(test.reasons)}")
                    print(f"      Stats: {test.line_count} LOC, {test.test_count} tests")

        print()

    # Overall summary
    print("-" * 70)
    if total_integration == 0:
        print(f"Overall: No integration tests found in {total_files} test files")
        print("Status: ✅ COMPLETE (no integration tests to instrument)")
    else:
        overall_pct = (total_instrumented / total_integration * 100) if total_integration else 0
        status = "✅ COMPLETE" if overall_pct == 100 else "❌ INCOMPLETE"
        print(f"Overall: {total_instrumented}/{total_integration} integration tests ({overall_pct:.0f}%)")
        print(f"Status: {status}")

    print()

    return total_integration, total_instrumented, total_files


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate FlightRecorder coverage in integration tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all packages
  %(prog)s --verbose                # Detailed output
  %(prog)s --package=neoaxios_fastapi_kit      # Check specific package
        """
    )
    parser.add_argument(
        "--package",
        help="Check specific package only",
        type=str
    )
    parser.add_argument(
        "--verbose", "-v",
        help="Show detailed output with reasons",
        action="store_true"
    )

    args = parser.parse_args()

    # Find repo root (script is at neo-packages/neoaxios-build/scripts/)
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent.parent

    if not (repo_root / "build.yaml").exists():
        print(f"Error: Could not find build.yaml at {repo_root}", file=sys.stderr)
        sys.exit(1)

    # Scan packages
    print(f"Scanning packages from {repo_root}...")
    if args.package:
        print(f"Filtering: package={args.package}")

    results = scan_packages(repo_root, args.package)

    if not results:
        print("No test files found!")
        sys.exit(0)

    # Generate report
    total_integration, total_instrumented, total_files = generate_report(results, args.verbose)

    # Exit with status code
    if total_integration == 0:
        sys.exit(0)  # No integration tests, nothing to do
    elif total_instrumented == total_integration:
        sys.exit(0)  # Full coverage
    else:
        sys.exit(1)  # Incomplete coverage


if __name__ == "__main__":
    main()
