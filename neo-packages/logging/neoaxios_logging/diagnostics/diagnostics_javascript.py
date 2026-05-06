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

"""JavaScript/TypeScript specific diagnostics for test."""

import re
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .diagnostics import DiagnosticCheck, DiagnosticResult, DiagnosticIssue, DiagnosticLevel
from .diagnostics_base import (
    ConfigSyntaxValidator,
    DependencyAnalyzer,
    TestPerformanceAnalyzer,
    ConfigValidationResult,
    TestPerformanceData,
    BaseConfigSyntaxCheck,
    BaseCircularDependencyCheck,
    BaseSlowTestDetectionCheck,
    DiagnosticCategory,
)


class JavaScriptConfigValidator(ConfigSyntaxValidator):
    """JavaScript/TypeScript config file validator."""

    def get_config_patterns(self) -> List[str]:
        """Return patterns for JS/TS config files."""
        return [
            "vitest.config.js",
            "vitest.config.ts",
            "vitest.config.mjs",
            "vitest.config.cjs",
            "vite.config.js",
            "vite.config.ts",
            "vite.config.mjs",
            "vite.config.cjs",
            "jest.config.js",
            "jest.config.ts",
            "jest.config.mjs",
            "webpack.config.js",
            "webpack.config.ts",
            "rollup.config.js",
            "rollup.config.ts",
        ]

    def validate_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate JavaScript/TypeScript syntax."""
        # Check if Node.js is available
        try:
            node_check = subprocess.run(["node", "--version"], capture_output=True, timeout=5)
            if node_check.returncode != 0:
                return ConfigValidationResult(
                    valid=True,  # Can't validate without Node.js
                    error_message="Node.js not available for validation",
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ConfigValidationResult(
                valid=True, error_message="Node.js not available for validation"  # Skip validation
            )

        # Validation script using Node.js
        validation_script = """
const fs = require('fs');
const path = require('path');

const configPath = process.argv[2];
const configContent = fs.readFileSync(configPath, 'utf8');

try {
    // Try to parse as JavaScript module
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    const func = new AsyncFunction('require', 'module', 'exports', '__filename', '__dirname', configContent);
    
    console.log(JSON.stringify({valid: true}));
} catch (error) {
    // Extract line/column from error
    const lineMatch = error.stack ? error.stack.match(/:(\\d+):(\\d+)/) : null;
    console.log(JSON.stringify({
        valid: false,
        error: error.message,
        line: lineMatch ? parseInt(lineMatch[1]) : null,
        column: lineMatch ? parseInt(lineMatch[2]) : null
    }));
}
"""

        try:
            result = subprocess.run(
                ["node", "-e", validation_script, str(config_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout.strip())
                return ConfigValidationResult(
                    valid=data.get("valid", False),
                    error_message=data.get("error"),
                    line_number=data.get("line"),
                    column_number=data.get("column"),
                    suggestions=["Check JavaScript syntax", "Ensure proper module exports"],
                )

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            return ConfigValidationResult(
                valid=False,
                error_message=f"Validation failed: {str(e)}",
                suggestions=["Check if file is valid JavaScript/TypeScript"],
            )

        return ConfigValidationResult(valid=True)

    def validate_schema(self, config_path: Path, content: str) -> List[str]:
        """Validate config content for common issues."""
        issues = []
        config_name = config_path.name.lower()

        # Vitest-specific checks
        if "vitest" in config_name:
            if "globals:" in content and "true" in content and "setupFiles" not in content:
                issues.append(
                    "Using globals: true without setupFiles - consider adding setup files"
                )

            if "coverage" in content and "c8" in content:
                issues.append("Both coverage and c8 configured - use one coverage provider")

        # Jest-specific checks
        if "jest" in config_name:
            if "testEnvironment" not in content:
                issues.append("No testEnvironment specified - defaults to 'node'")

            if "transform" in content and "babel" not in content and ".ts" in content:
                issues.append("TypeScript files found but no Babel transformer configured")

        # General checks
        if "test" in config_name or "vitest" in config_name or "jest" in config_name:
            # Check for explicitly disabled timeouts (timeout: 0 or testTimeout: 0)
            import re

            timeout_zero_pattern = r"(?:timeout|testTimeout)\s*:\s*0"
            if re.search(timeout_zero_pattern, content):
                issues.append("Test timeout disabled - tests may hang indefinitely")
            # For configs without explicit timeout, only warn for e2e/integration tests
            elif "timeout" not in content and "testTimeout" not in content:
                if "e2e" in content or "integration" in content:
                    issues.append("Consider configuring test timeout for E2E/integration tests")

        return issues


class JavaScriptDependencyAnalyzer(DependencyAnalyzer):
    """JavaScript/TypeScript dependency analyzer."""

    def get_file_patterns(self) -> List[str]:
        """Return patterns for JS/TS files."""
        return ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.mjs", "**/*.cjs"]

    def extract_imports(self, file_path: Path, content: str) -> List[str]:
        """Extract import statements from JavaScript/TypeScript."""
        imports = []

        # ES6 imports: import ... from 'module'
        es6_pattern = r'import\s+(?:.*?\s+from\s+)?[\'"]([^\'"\s]+)[\'"]'
        imports.extend(re.findall(es6_pattern, content))

        # CommonJS: require('module')
        cjs_pattern = r'require\s*\(\s*[\'"]([^\'"\s]+)[\'"]\s*\)'
        imports.extend(re.findall(cjs_pattern, content))

        # Dynamic imports: import('module')
        dynamic_pattern = r'import\s*\(\s*[\'"]([^\'"\s]+)[\'"]\s*\)'
        imports.extend(re.findall(dynamic_pattern, content))

        # TypeScript path imports
        ts_pattern = r'from\s+[\'"]([^\'"\s]+)[\'"]'
        imports.extend(re.findall(ts_pattern, content))

        # Remove duplicates while preserving order
        seen = set()
        unique_imports = []
        for imp in imports:
            if imp not in seen:
                seen.add(imp)
                unique_imports.append(imp)

        return unique_imports

    def resolve_import(self, import_path: str, from_file: Path) -> Optional[Path]:
        """Resolve JS/TS import to actual file."""
        # Skip external modules (not relative or absolute paths)
        if not import_path.startswith(".") and not import_path.startswith("/"):
            return None

        base_dir = from_file.parent

        # Handle different import styles
        if import_path.startswith("."):
            # Relative import
            target = base_dir / import_path
        else:
            # Absolute import (rare in JS)
            target = Path(import_path)

        # Try different extensions and index files
        extensions = ["", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
        index_files = ["/index.js", "/index.ts", "/index.jsx", "/index.tsx"]

        # Try exact match first
        for ext in extensions:
            candidate = Path(str(target) + ext)
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()

        # Try index files
        for index in index_files:
            candidate = Path(str(target) + index)
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()

        return None


class JavaScriptTestPerformanceAnalyzer(TestPerformanceAnalyzer):
    """JavaScript test performance analyzer."""

    def get_history_location(self) -> Path:
        """Get test history location."""
        return Path.home() / '.qrs' / "test_execution_history.json"

    def parse_test_history(self, history_data: Dict[str, Any]) -> List[TestPerformanceData]:
        """Parse test execution history into performance data."""
        test_performances = {}

        # Aggregate data from all sessions
        for session in history_data.get("sessions", []):
            session_tests = session.get("tests", {})

            for test_path, test_data in session_tests.items():
                # Skip if no timing data
                duration = test_data.get("duration", 0)
                if duration <= 0:
                    continue

                # Initialize or update test data
                if test_path not in test_performances:
                    test_performances[test_path] = {
                        "durations": [],
                        "file_path": test_path,
                        "test_type": self._infer_test_type(test_path),
                    }

                test_performances[test_path]["durations"].append(duration)

        # Calculate statistics
        results = []
        for test_path, perf_data in test_performances.items():
            durations = perf_data["durations"]
            if durations:
                results.append(
                    TestPerformanceData(
                        test_name=Path(test_path).name,
                        file_path=test_path,
                        average_time=sum(durations) / len(durations),
                        max_time=max(durations),
                        min_time=min(durations),
                        run_count=len(durations),
                        test_type=perf_data["test_type"],
                    )
                )

        return results

    def _infer_test_type(self, test_path: str) -> str:
        """Infer test type from file path."""
        path_lower = test_path.lower()

        if "e2e" in path_lower or "end-to-end" in path_lower:
            return "e2e"
        elif "integration" in path_lower or "integ" in path_lower:
            return "integration"
        elif "unit" in path_lower or "spec" in path_lower:
            return "unit"

        # Check file name patterns
        filename = Path(test_path).name.lower()
        if filename.endswith(".spec.js") or filename.endswith(".spec.ts"):
            return "unit"
        elif filename.endswith(".e2e.js") or filename.endswith(".e2e.ts"):
            return "e2e"
        elif filename.endswith(".integration.test.js") or filename.endswith(".integration.test.ts"):
            return "integration"
        elif filename.endswith(".test.js") or filename.endswith(".test.ts"):
            # Only default to unit if in known source directories
            if "/components/" in path_lower or "/utils/" in path_lower or "/src/" in path_lower:
                return "unit"

        return "unknown"

    def get_optimization_suggestions(self, test: TestPerformanceData) -> List[str]:
        """Get JS-specific optimization suggestions."""
        suggestions = []
        test_name_lower = test.test_name.lower()

        # Time-based suggestions
        if test.average_time > 10:
            suggestions.append("Split into smaller, focused tests")
            suggestions.append("Review for unnecessary async operations")
        elif test.average_time > 5:
            suggestions.append("Mock external dependencies (APIs, databases)")
            suggestions.append("Use test doubles for heavy computations")
        elif test.average_time > 2:
            suggestions.append("Check for unnecessary setTimeout/setInterval")
            suggestions.append("Optimize test data setup")

        # Type-specific suggestions
        if test.test_type == "e2e":
            suggestions.append("Use page object pattern to optimize selectors")
            suggestions.append("Disable animations and transitions in tests")
            suggestions.append("Run e2e tests in parallel with proper isolation")
        elif test.test_type == "integration":
            suggestions.append("Use in-memory databases or test containers")
            suggestions.append("Mock external service calls")
        else:  # unit tests
            suggestions.append("Avoid testing implementation details")
            suggestions.append("Use shallow rendering for component tests")

        # Pattern-based suggestions
        if "api" in test_name_lower or "http" in test_name_lower:
            suggestions.append("Use MSW or nock for API mocking")

        if "database" in test_name_lower or "db" in test_name_lower:
            suggestions.append("Use transaction rollback or in-memory DB")

        if "component" in test_name_lower or "render" in test_name_lower:
            suggestions.append("Use React Testing Library's async utilities efficiently")

        return suggestions[:5]  # Return top 5 most relevant


# Concrete diagnostic checks using the base classes


class VitestConfigCheck(BaseConfigSyntaxCheck):
    """Vitest configuration validation check."""

    def __init__(self):
        super().__init__(JavaScriptConfigValidator())


class JavaScriptCircularDependencyCheck(BaseCircularDependencyCheck):
    """JavaScript circular dependency check."""

    def __init__(self):
        super().__init__(JavaScriptDependencyAnalyzer())


class JavaScriptSlowTestDetectionCheck(BaseSlowTestDetectionCheck):
    """JavaScript slow test detection check."""

    def __init__(self):
        super().__init__(JavaScriptTestPerformanceAnalyzer())


# Legacy checks for backward compatibility
class CircularDependencyCheck(DiagnosticCheck):
    """Check for circular dependencies in test files."""

    @property
    def name(self) -> str:
        return "Circular Dependency Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.DEPENDENCIES

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        # Find all test files
        test_patterns = ["**/*test*.js", "**/*test*.ts", "**/*spec*.js", "**/*spec*.ts"]
        test_files = []

        for pattern in test_patterns:
            for test_file in Path.cwd().rglob(pattern):
                if self._should_check_file(test_file):
                    test_files.append(test_file)

        if not test_files:
            result.checks_passed += 1
            return result

        # Build dependency graph
        dependency_graph = self._build_dependency_graph(test_files)

        # Detect cycles
        cycles = self._detect_cycles(dependency_graph)

        if cycles:
            for cycle in cycles:
                cycle_str = " -> ".join(cycle) + " -> " + cycle[0]
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Circular dependency detected",
                        details=f"Cycle: {cycle_str}",
                        fix_suggestion="Refactor to remove circular dependencies",
                    )
                )
        else:
            result.checks_passed += 1

        return result

    def _should_check_file(self, path: Path) -> bool:
        """Check if file should be analyzed."""
        skip_dirs = ["node_modules", ".git", "dist", "build", "coverage"]
        return not any(skip_dir in str(path) for skip_dir in skip_dirs)

    def _build_dependency_graph(self, files: List[Path]) -> Dict[str, Set[str]]:
        """Build a dependency graph from import statements."""
        graph = {}

        for file_path in files:
            try:
                content = file_path.read_text()
                imports = self._extract_imports(content)

                # Resolve relative imports
                resolved_imports = set()
                for imp in imports:
                    resolved = self._resolve_import(imp, file_path)
                    if resolved:
                        resolved_imports.add(str(resolved))

                graph[str(file_path)] = resolved_imports

            except Exception:
                continue

        return graph

    def _extract_imports(self, content: str) -> List[str]:
        """Extract import paths from JavaScript/TypeScript content."""
        imports = []

        # ES6 imports
        es6_pattern = r'import\s+.*?\s+from\s+[\'"](.+?)[\'"]'
        imports.extend(re.findall(es6_pattern, content))

        # CommonJS requires
        cjs_pattern = r'require\s*\(\s*[\'"](.+?)[\'"]\s*\)'
        imports.extend(re.findall(cjs_pattern, content))

        # Dynamic imports
        dynamic_pattern = r'import\s*\(\s*[\'"](.+?)[\'"]\s*\)'
        imports.extend(re.findall(dynamic_pattern, content))

        return imports

    def _resolve_import(self, import_path: str, from_file: Path) -> Optional[Path]:
        """Resolve an import path to an actual file."""
        # Skip external modules
        if not import_path.startswith("."):
            return None

        # Try to resolve relative import
        base_dir = from_file.parent

        # Try different extensions
        extensions = ["", ".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts"]

        for ext in extensions:
            resolved = base_dir / (import_path + ext)
            if resolved.exists() and resolved.is_file():
                return resolved.resolve()

        return None

    def _detect_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """Detect cycles in the dependency graph using DFS."""
        cycles = []
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor, path.copy())
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:]
                    # Normalize cycle to start with smallest element
                    min_idx = cycle.index(min(cycle))
                    normalized = cycle[min_idx:] + cycle[:min_idx]
                    cycles.append(normalized)

            path.pop()
            rec_stack.remove(node)

        for node in graph:
            if node not in visited:
                dfs(node, [])

        # Remove duplicate cycles
        unique_cycles = []
        seen = set()
        for cycle in cycles:
            cycle_tuple = tuple(cycle)
            if cycle_tuple not in seen:
                seen.add(cycle_tuple)
                unique_cycles.append(cycle)

        return unique_cycles


class SlowTestDetectionCheck(DiagnosticCheck):
    """Detect and warn about slow tests based on historical data."""

    @property
    def name(self) -> str:
        return "Slow Test Detection"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PERFORMANCE

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        # Load test execution history
        history_path = Path.home() / '.qrs' / "test_execution_history.json"

        if not history_path.exists():
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="No test execution history found",
                    details="Run tests with test to build execution history",
                    fix_suggestion="Start collecting test performance data by running your test suite",
                )
            )
            return result

        try:
            with open(history_path, "r") as f:
                history = json.load(f)

            # Analyze test performance
            slow_tests = self._analyze_performance(history)

            if slow_tests:
                # Group by severity
                very_slow = [t for t in slow_tests if t["avg_time"] > 5.0]
                slow = [t for t in slow_tests if 1.0 < t["avg_time"] <= 5.0]
                moderate = [t for t in slow_tests if 0.5 < t["avg_time"] <= 1.0]

                # Report very slow tests
                for test in very_slow:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message=f"Very slow test: {test['name']}",
                            details=f"Average time: {test['avg_time']:.2f}s (threshold: 5s)",
                            metadata={
                                "test_name": test["name"],
                                "avg_time": test["avg_time"],
                                "run_count": test["runs"],
                            },
                            fix_suggestion=self._get_optimization_suggestion(test),
                        )
                    )

                # Report slow tests
                for test in slow:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message=f"Slow test: {test['name']}",
                            details=f"Average time: {test['avg_time']:.2f}s (threshold: 1s)",
                            metadata={
                                "test_name": test["name"],
                                "avg_time": test["avg_time"],
                                "run_count": test["runs"],
                            },
                            fix_suggestion=self._get_optimization_suggestion(test),
                        )
                    )

                # Info for moderate
                if moderate:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.INFO,
                            message=f"Found {len(moderate)} tests taking 0.5-1s",
                            details="Consider optimizing these tests for better performance",
                            metadata={"test_count": len(moderate)},
                        )
                    )

                # Performance summary
                total_slow = len(slow_tests)
                avg_time_wasted = sum(t["avg_time"] for t in slow_tests) / len(slow_tests)

                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.INFO,
                        message=f"Performance Summary: {total_slow} slow tests identified",
                        details=f"Average time per slow test: {avg_time_wasted:.2f}s",
                        metadata={
                            "total_slow_tests": total_slow,
                            "very_slow_count": len(very_slow),
                            "slow_count": len(slow),
                            "moderate_count": len(moderate),
                        },
                    )
                )
            else:
                result.checks_passed += 1

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Could not analyze test performance",
                    details=str(e),
                )
            )

        return result

    def _analyze_performance(self, history: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze test performance from history."""
        slow_tests = []

        # Aggregate timing data by test
        test_times = {}

        for session in history.get("sessions", []):
            for test, data in session.get("tests", {}).items():
                if test not in test_times:
                    test_times[test] = []

                duration = data.get("duration", 0)
                if duration > 0:
                    test_times[test].append(duration)

        # Calculate averages and identify slow tests
        for test_name, times in test_times.items():
            if times:
                avg_time = sum(times) / len(times)

                # Consider a test slow if average > 0.5s
                if avg_time > 0.5:
                    slow_tests.append(
                        {
                            "name": test_name,
                            "avg_time": avg_time,
                            "max_time": max(times),
                            "min_time": min(times),
                            "runs": len(times),
                        }
                    )

        # Sort by average time descending
        slow_tests.sort(key=lambda x: x["avg_time"], reverse=True)

        return slow_tests

    def _get_optimization_suggestion(self, test_info: Dict[str, Any]) -> str:
        """Get optimization suggestion based on test characteristics."""
        avg_time = test_info["avg_time"]
        test_name = test_info["name"].lower()

        suggestions = []

        # Time-based suggestions
        if avg_time > 10:
            suggestions.append("Consider breaking this test into smaller, focused tests")
        elif avg_time > 5:
            suggestions.append("Look for expensive operations that can be mocked or optimized")

        # Name-based heuristics
        if "integration" in test_name or "e2e" in test_name:
            suggestions.append("Use test doubles for external dependencies")
            suggestions.append("Consider moving to a separate slow test suite")

        if "database" in test_name or "db" in test_name:
            suggestions.append("Use in-memory database or transaction rollback for faster tests")

        if "api" in test_name or "http" in test_name:
            suggestions.append("Mock external API calls instead of making real requests")

        if "file" in test_name or "disk" in test_name:
            suggestions.append("Use in-memory file systems or temp directories")

        # Generic suggestions
        if not suggestions:
            if avg_time > 2:
                suggestions.append("Profile the test to identify bottlenecks")
                suggestions.append("Check for unnecessary setup/teardown operations")
            else:
                suggestions.append("Review test for unnecessary delays or timeouts")
                suggestions.append("Ensure test data is minimal")

        return "; ".join(suggestions[:2])  # Return top 2 suggestions


# Export the main diagnostic checks
__all__ = [
    "VitestConfigCheck",
    "JavaScriptCircularDependencyCheck",
    "JavaScriptSlowTestDetectionCheck",
    "CircularDependencyCheck",  # Legacy
    "SlowTestDetectionCheck",  # Legacy
]
