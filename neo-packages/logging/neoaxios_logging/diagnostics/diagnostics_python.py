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

"""Python specific diagnostics for test."""

import ast
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

from .diagnostics_base import (
    ConfigSyntaxValidator,
    DependencyAnalyzer,
    TestPerformanceAnalyzer,
    ConfigValidationResult,
    TestPerformanceData,
    BaseConfigSyntaxCheck,
    BaseCircularDependencyCheck,
    BaseSlowTestDetectionCheck,
)


class PythonConfigValidator(ConfigSyntaxValidator):
    """Python config file validator."""

    def get_config_patterns(self) -> List[str]:
        """Return patterns for Python config files."""
        return ["pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini", ".coveragerc", "setup.py"]

    def validate_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate Python config syntax."""
        filename = config_path.name.lower()

        # Python files need Python syntax checking
        if filename == "setup.py":
            return self._validate_python_syntax(config_path)

        # TOML files
        if filename == "pyproject.toml":
            return self._validate_toml_syntax(config_path)

        # INI files
        if filename in ["pytest.ini", "setup.cfg", "tox.ini", ".coveragerc"]:
            return self._validate_ini_syntax(config_path)

        return ConfigValidationResult(valid=True)

    def _validate_python_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate Python file syntax."""
        try:
            content = config_path.read_text()
            ast.parse(content)
            return ConfigValidationResult(valid=True)
        except SyntaxError as e:
            return ConfigValidationResult(
                valid=False,
                error_message=f"Syntax error: {e.msg}",
                line_number=e.lineno,
                column_number=e.offset,
                suggestions=["Check Python syntax", "Ensure proper indentation"],
            )
        except Exception as e:
            return ConfigValidationResult(
                valid=False, error_message=str(e), suggestions=["Verify file is valid Python"]
            )

    def _validate_toml_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate TOML file syntax."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return ConfigValidationResult(valid=True)  # Skip if no TOML parser

        try:
            content = config_path.read_text()
            tomllib.loads(content)
            return ConfigValidationResult(valid=True)
        except Exception as e:
            # Try to extract line number from error
            line_match = re.search(r"line (\d+)", str(e))
            return ConfigValidationResult(
                valid=False,
                error_message=str(e),
                line_number=int(line_match.group(1)) if line_match else None,
                suggestions=["Check TOML syntax", "Validate quotes and brackets"],
            )

    def _validate_ini_syntax(self, config_path: Path) -> ConfigValidationResult:
        """Validate INI file syntax."""
        import configparser

        try:
            content = config_path.read_text()
            parser = configparser.ConfigParser()
            parser.read_string(content)
            return ConfigValidationResult(valid=True)
        except configparser.Error as e:
            # Try to extract line number
            line_match = re.search(r"line (\d+)", str(e))
            return ConfigValidationResult(
                valid=False,
                error_message=str(e),
                line_number=int(line_match.group(1)) if line_match else None,
                suggestions=["Check INI syntax", "Ensure sections have [brackets]"],
            )
        except Exception as e:
            return ConfigValidationResult(
                valid=False, error_message=str(e), suggestions=["Verify INI file format"]
            )

    def validate_schema(self, config_path: Path, content: str) -> List[str]:
        """Validate config content for common issues."""
        issues = []
        filename = config_path.name.lower()

        # pytest.ini specific checks
        if filename == "pytest.ini":
            if "[pytest]" not in content:
                issues.append("Missing [pytest] section header")

            if "addopts" in content and "--tb=short" not in content:
                issues.append("Consider adding --tb=short for cleaner output")

        # pyproject.toml checks
        if filename == "pyproject.toml":
            if "[tool.pytest.ini_options]" in content and "[pytest]" in content:
                issues.append("Don't mix [pytest] and [tool.pytest.ini_options]")

            if 'build-backend = "setuptools' in content:
                # Check if setuptools is in the requires list
                if "requires = [" in content and '"setuptools"' not in content:
                    issues.append("Missing setuptools in build requirements")

        # setup.cfg checks
        if filename == "setup.cfg":
            if "[metadata]" not in content:
                issues.append("Missing [metadata] section")

        # Generic checks
        if "python_version" in content or "python_requires" in content:
            if not any(ver in content for ver in ["3.8", "3.9", "3.10", "3.11", "3.12"]):
                issues.append("Python version requirement seems outdated")

        return issues


class PythonDependencyAnalyzer(DependencyAnalyzer):
    """Python dependency analyzer."""

    def get_file_patterns(self) -> List[str]:
        """Return patterns for Python files."""
        return ["**/*.py"]

    def extract_imports(self, file_path: Path, content: str) -> List[str]:
        """Extract import statements from Python."""
        imports = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    # Handle relative imports
                    if node.level > 0:
                        # Add just the dots for the relative level
                        imports.append("." * node.level)
                        # If there's also a module, add the full relative import
                        if node.module:
                            imports.append("." * node.level + node.module)
                    elif node.module:
                        # Non-relative import
                        imports.append(node.module)
        except:
            # Fallback to regex if AST parsing fails
            # Standard imports: import module
            imports.extend(re.findall(r"^\s*import\s+(\S+)", content, re.MULTILINE))

            # From imports: from module import ...
            from_imports = re.findall(r"^\s*from\s+(\S+)\s+import", content, re.MULTILINE)
            imports.extend(from_imports)

        # Remove duplicates while preserving order
        seen = set()
        unique_imports = []
        for imp in imports:
            if imp not in seen:
                seen.add(imp)
                unique_imports.append(imp)

        return unique_imports

    def resolve_import(self, import_path: str, from_file: Path) -> Optional[Path]:
        """Resolve Python import to actual file."""
        # Skip standard library and third-party imports
        if not import_path.startswith("."):
            # Check if it's a local module by looking in the project
            parts = import_path.split(".")

            # Try to find the module in the project
            base_dirs = [from_file.parent, Path.cwd()]

            for base_dir in base_dirs:
                # Try as a module
                module_path = base_dir / Path(*parts[:-1]) / f"{parts[-1]}.py"
                if module_path.exists():
                    return module_path.resolve()

                # Try as a package
                package_path = base_dir / Path(*parts) / "__init__.py"
                if package_path.exists():
                    return package_path.resolve()

            return None

        # Handle relative imports
        level = len(import_path) - len(import_path.lstrip("."))
        module_parts = import_path[level:].split(".") if import_path[level:] else []

        # Go up directories based on level
        current = from_file.parent
        for _ in range(level - 1):  # -1 because we already start at parent
            current = current.parent

        # Try to resolve the module
        if module_parts:
            # Module specified
            module_path = current / Path(*module_parts[:-1]) / f"{module_parts[-1]}.py"
            if module_path.exists():
                return module_path.resolve()

            # Try as package
            package_path = current / Path(*module_parts) / "__init__.py"
            if package_path.exists():
                return package_path.resolve()
        else:
            # Just dots - import from parent package
            init_path = current / "__init__.py"
            if init_path.exists():
                return init_path.resolve()

        return None


class PythonTestPerformanceAnalyzer(TestPerformanceAnalyzer):
    """Python test performance analyzer."""

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

        if "e2e" in path_lower or "end_to_end" in path_lower:
            return "e2e"
        elif "integration" in path_lower or "integ" in path_lower:
            return "integration"
        elif "unit" in path_lower:
            return "unit"

        # Check file name patterns
        filename = Path(test_path).name.lower()
        if filename.startswith("test_") and "_integration" not in filename:
            return "unit"
        elif "_integration" in filename:
            return "integration"

        return "unit"  # Default to unit

    def get_optimization_suggestions(self, test: TestPerformanceData) -> List[str]:
        """Get Python-specific optimization suggestions."""
        suggestions = []
        test_name_lower = test.test_name.lower()

        # Type-specific suggestions (higher priority)
        if test.test_type == "e2e":
            suggestions.append("Use page object pattern for UI tests")
            suggestions.append("Run e2e tests with a distributed test orchestrator for parallelization")
        elif test.test_type == "integration":
            suggestions.append("Use pytest-docker for containerized dependencies")
            suggestions.append("Mock external service calls with responses library")
        else:  # unit tests
            suggestions.append("Use unittest.mock or pytest-mock")
            suggestions.append("Avoid testing private methods directly")

        # Time-based suggestions
        if test.average_time > 10:
            suggestions.append("Split into smaller, focused test methods")
            suggestions.append("Review for expensive setup/teardown")
        elif test.average_time > 5:
            suggestions.append("Mock external dependencies (APIs, databases)")
            suggestions.append("Use pytest fixtures efficiently")
        elif test.average_time > 2:
            suggestions.append("Check for unnecessary file I/O operations")
            suggestions.append("Optimize test data generation")

        # Pattern-based suggestions
        if "api" in test_name_lower or "http" in test_name_lower:
            suggestions.append("Use responses or httpretty for API mocking")

        if "database" in test_name_lower or "db" in test_name_lower:
            suggestions.append("Use pytest-postgresql or similar for test databases")

        if "async" in test_name_lower:
            suggestions.append("Use pytest-asyncio and proper async fixtures")

        return suggestions[:5]  # Return top 5 most relevant


# Concrete diagnostic checks using the base classes


class PytestConfigCheck(BaseConfigSyntaxCheck):
    """Pytest configuration validation check."""

    def __init__(self):
        super().__init__(PythonConfigValidator())


class PythonCircularDependencyCheck(BaseCircularDependencyCheck):
    """Python circular dependency check."""

    def __init__(self):
        super().__init__(PythonDependencyAnalyzer())


class PythonSlowTestDetectionCheck(BaseSlowTestDetectionCheck):
    """Python slow test detection check."""

    def __init__(self):
        super().__init__(PythonTestPerformanceAnalyzer())


# Export the main diagnostic checks
__all__ = ["PytestConfigCheck", "PythonCircularDependencyCheck", "PythonSlowTestDetectionCheck"]
