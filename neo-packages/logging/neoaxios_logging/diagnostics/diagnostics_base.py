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

"""Base diagnostic framework for language-agnostic checks."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
import json

# Import from existing diagnostics module
from .diagnostics import DiagnosticCheck, DiagnosticResult, DiagnosticIssue, DiagnosticLevel


# Import DiagnosticCategory from diagnostics.py and extend it if needed


# Extend the DiagnosticCategory enum with additional values
class DiagnosticCategory(Enum):
    """Extended categories for diagnostics."""

    CONFIGURATION = "configuration"
    PLUGIN = "plugin"
    ENVIRONMENT = "environment"
    FILESYSTEM = "filesystem"
    CODE_QUALITY = "code_quality"
    PERFORMANCE = "performance"
    SYNTAX = "syntax"
    DEPENDENCIES = "dependencies"


@dataclass
class ConfigValidationResult:
    """Result of config file validation."""

    valid: bool
    error_message: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    suggestions: List[str] = None


@dataclass
class DependencyNode:
    """Node in dependency graph."""

    path: Path
    imports: Set[str]
    resolved_imports: Set[Path]


@dataclass
class TestPerformanceData:
    """Performance data for a single test."""

    test_name: str
    file_path: str
    average_time: float
    max_time: float
    min_time: float
    run_count: int
    test_type: str = "unknown"  # unit, integration, e2e


# Abstract Base Classes for Language-Agnostic Diagnostics


class ConfigSyntaxValidator(ABC):
    """Abstract base for configuration file syntax validation."""

    @abstractmethod
    def get_config_patterns(self) -> List[str]:
        """Return glob patterns for config files."""
        pass

    @abstractmethod
    def validate_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate syntax of a config file."""
        pass

    @abstractmethod
    def validate_schema(self, config_path: Path, content: str) -> List[str]:
        """Validate config against schema, return list of issues."""
        pass

    def get_language(self) -> str:
        """Return the language/framework this validator supports."""
        return self.__class__.__name__.replace("ConfigValidator", "").lower()


class DependencyAnalyzer(ABC):
    """Abstract base for dependency analysis."""

    @abstractmethod
    def get_file_patterns(self) -> List[str]:
        """Return glob patterns for files to analyze."""
        pass

    @abstractmethod
    def extract_imports(self, file_path: Path, content: str) -> List[str]:
        """Extract import statements from file content."""
        pass

    @abstractmethod
    def resolve_import(self, import_path: str, from_file: Path) -> Optional[Path]:
        """Resolve an import path to actual file location."""
        pass

    def build_dependency_graph(self, files: List[Path]) -> Dict[str, DependencyNode]:
        """Build dependency graph from files."""
        graph = {}

        for file_path in files:
            try:
                content = file_path.read_text()
                imports = self.extract_imports(file_path, content)

                # Resolve imports
                resolved = set()
                for imp in imports:
                    resolved_path = self.resolve_import(imp, file_path)
                    if resolved_path:
                        resolved.add(resolved_path)

                graph[str(file_path)] = DependencyNode(
                    path=file_path, imports=set(imports), resolved_imports=resolved
                )

            except Exception:
                continue

        return graph

    def detect_circular_dependencies(self, graph: Dict[str, DependencyNode]) -> List[List[str]]:
        """Detect circular dependencies using DFS."""
        cycles = []
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            node_data = graph.get(node)
            if node_data:
                for neighbor in node_data.resolved_imports:
                    neighbor_str = str(neighbor)
                    if neighbor_str not in visited:
                        dfs(neighbor_str, path.copy())
                    elif neighbor_str in rec_stack:
                        # Found a cycle
                        cycle_start = path.index(neighbor_str) if neighbor_str in path else 0
                        cycle = path[cycle_start:]
                        # Normalize cycle
                        if cycle:
                            min_idx = cycle.index(min(cycle))
                            normalized = cycle[min_idx:] + cycle[:min_idx]
                            cycles.append(normalized)

            path.pop()
            rec_stack.remove(node)

        for node in graph:
            if node not in visited:
                dfs(node, [])

        # Remove duplicates
        unique_cycles = []
        seen = set()
        for cycle in cycles:
            cycle_tuple = tuple(cycle)
            if cycle_tuple not in seen:
                seen.add(cycle_tuple)
                unique_cycles.append(cycle)

        return unique_cycles


class TestPerformanceAnalyzer(ABC):
    """Abstract base for test performance analysis."""

    @abstractmethod
    def get_history_location(self) -> Path:
        """Return path to test execution history."""
        pass

    @abstractmethod
    def parse_test_history(self, history_data: Dict[str, Any]) -> List[TestPerformanceData]:
        """Parse history data into performance records."""
        pass

    def get_slow_test_thresholds(self) -> Dict[str, float]:
        """Return thresholds for different test types."""
        return {
            "unit": 0.5,  # Unit tests should be < 0.5s
            "integration": 2.0,  # Integration tests < 2s
            "e2e": 5.0,  # E2E tests < 5s
            "unknown": 1.0,  # Default threshold
        }

    def analyze_slow_tests(
        self, history_path: Path
    ) -> Tuple[List[TestPerformanceData], Dict[str, Any]]:
        """Analyze test performance and identify slow tests."""
        if not history_path.exists():
            return [], {"error": "No history found"}

        try:
            with open(history_path, "r") as f:
                history_data = json.load(f)

            # Parse performance data
            all_tests = self.parse_test_history(history_data)

            # Identify slow tests based on thresholds
            thresholds = self.get_slow_test_thresholds()
            slow_tests = []

            for test in all_tests:
                threshold = thresholds.get(test.test_type, thresholds["unknown"])
                if test.average_time > threshold:
                    slow_tests.append(test)

            # Sort by average time
            slow_tests.sort(key=lambda x: x.average_time, reverse=True)

            # Calculate statistics
            stats = {
                "total_tests": len(all_tests),
                "slow_tests": len(slow_tests),
                "very_slow": len([t for t in slow_tests if t.average_time > 5.0]),
                "categories": {},
            }

            # Group by test type
            for test_type in ["unit", "integration", "e2e", "unknown"]:
                type_tests = [t for t in slow_tests if t.test_type == test_type]
                if type_tests:
                    stats["categories"][test_type] = {
                        "count": len(type_tests),
                        "avg_time": sum(t.average_time for t in type_tests) / len(type_tests),
                    }

            return slow_tests, stats

        except Exception as e:
            return [], {"error": str(e)}

    @abstractmethod
    def get_optimization_suggestions(self, test: TestPerformanceData) -> List[str]:
        """Get optimization suggestions for a slow test."""
        pass


# Base Diagnostic Checks Using Abstract Classes


class BaseConfigSyntaxCheck(DiagnosticCheck):
    """Base class for config syntax checking across languages."""

    def __init__(self, validator: ConfigSyntaxValidator):
        self.validator = validator

    @property
    def name(self) -> str:
        return f"{self.validator.get_language().title()} Config Syntax Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.SYNTAX

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        # Find config files
        config_files = []
        for pattern in self.validator.get_config_patterns():
            config_files.extend(Path.cwd().rglob(pattern))

        # Filter out vendor directories
        config_files = [f for f in config_files if self._should_check_file(f)]

        if not config_files:
            result.checks_passed += 1
            return result

        # Validate each file
        issues_found = False
        for config_path in config_files:
            validation = self.validator.validate_syntax(config_path)

            if not validation.valid:
                issues_found = True
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message=f"Syntax error in {config_path.name}",
                        details=validation.error_message,
                        file_path=config_path,
                        line_number=validation.line_number,
                        fix_suggestion=(
                            validation.suggestions[0] if validation.suggestions else None
                        ),
                    )
                )
            else:
                # Check schema/content
                try:
                    content = config_path.read_text()
                    schema_issues = self.validator.validate_schema(config_path, content)

                    for issue in schema_issues:
                        result.add_issue(
                            DiagnosticIssue(
                                category=self.category,
                                level=DiagnosticLevel.WARNING,
                                message=f"Configuration issue in {config_path.name}",
                                details=issue,
                                file_path=config_path,
                            )
                        )

                except Exception:
                    pass

        if not issues_found:
            result.checks_passed += 1

        return result

    def _should_check_file(self, path: Path) -> bool:
        """Check if file should be validated."""
        skip_dirs = [
            "node_modules",
            "vendor",
            ".git",
            "dist",
            "build",
            ".tox",
            "venv",
            "__pycache__",
        ]
        return not any(skip_dir in str(path) for skip_dir in skip_dirs)


class BaseCircularDependencyCheck(DiagnosticCheck):
    """Base class for circular dependency checking across languages."""

    def __init__(self, analyzer: DependencyAnalyzer):
        self.analyzer = analyzer

    @property
    def name(self) -> str:
        language = self.analyzer.__class__.__name__.replace("DependencyAnalyzer", "")
        return f"{language} Circular Dependency Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.DEPENDENCIES

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        # Find files to analyze
        files = []
        for pattern in self.analyzer.get_file_patterns():
            files.extend(Path.cwd().rglob(pattern))

        # Filter files
        files = [f for f in files if self._should_check_file(f)]

        if not files:
            result.checks_passed += 1
            return result

        # Build dependency graph
        graph = self.analyzer.build_dependency_graph(files)

        # Detect cycles
        cycles = self.analyzer.detect_circular_dependencies(graph)

        if cycles:
            for cycle in cycles:
                # Make paths relative for cleaner output
                try:
                    rel_cycle = []
                    for path_str in cycle:
                        path = Path(path_str)
                        rel_path = path.relative_to(Path.cwd())
                        rel_cycle.append(str(rel_path))
                except:
                    rel_cycle = cycle

                cycle_str = " → ".join(rel_cycle) + " → " + rel_cycle[0]
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Circular dependency detected",
                        details=f"Cycle: {cycle_str}",
                        fix_suggestion="Refactor to break the circular dependency",
                        metadata={"cycle": rel_cycle},
                    )
                )
        else:
            result.checks_passed += 1

        return result

    def _should_check_file(self, path: Path) -> bool:
        """Check if file should be analyzed."""
        skip_dirs = ["node_modules", "vendor", ".git", "dist", "build", "coverage", ".tox", "venv"]
        return not any(skip_dir in str(path) for skip_dir in skip_dirs)


class BaseSlowTestDetectionCheck(DiagnosticCheck):
    """Base class for slow test detection across languages."""

    def __init__(self, analyzer: TestPerformanceAnalyzer):
        self.analyzer = analyzer

    @property
    def name(self) -> str:
        return "Slow Test Detection"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PERFORMANCE

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        # Get history location
        history_path = self.analyzer.get_history_location()

        if not history_path.exists():
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="No test execution history found",
                    details="Run tests with test to build performance history",
                    fix_suggestion="Start collecting test performance data by running your test suite",
                )
            )
            return result

        # Analyze performance
        slow_tests, stats = self.analyzer.analyze_slow_tests(history_path)

        if "error" in stats:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Could not analyze test performance",
                    details=stats["error"],
                )
            )
            return result

        if slow_tests:
            # Report very slow tests (>5s) as errors
            for test in [t for t in slow_tests if t.average_time > 5.0]:
                suggestions = self.analyzer.get_optimization_suggestions(test)
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message=f"Very slow test: {test.test_name}",
                        details=f"Average time: {test.average_time:.2f}s (runs: {test.run_count})",
                        file_path=Path(test.file_path) if test.file_path else None,
                        fix_suggestion=suggestions[0] if suggestions else None,
                        metadata={
                            "test_name": test.test_name,
                            "avg_time": test.average_time,
                            "test_type": test.test_type,
                        },
                    )
                )

            # Report slow tests (1-5s) as warnings
            for test in [t for t in slow_tests if 1.0 < t.average_time <= 5.0]:
                suggestions = self.analyzer.get_optimization_suggestions(test)
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"Slow test: {test.test_name}",
                        details=f"Average time: {test.average_time:.2f}s (runs: {test.run_count})",
                        file_path=Path(test.file_path) if test.file_path else None,
                        fix_suggestion=suggestions[0] if suggestions else None,
                        metadata={
                            "test_name": test.test_name,
                            "avg_time": test.average_time,
                            "test_type": test.test_type,
                        },
                    )
                )

            # Summary
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message=f"Performance Summary: {stats['slow_tests']} slow tests found",
                    details=f"Very slow: {stats['very_slow']}, Categories: {list(stats['categories'].keys())}",
                    metadata=stats,
                )
            )
        else:
            result.checks_passed += 1

        return result
