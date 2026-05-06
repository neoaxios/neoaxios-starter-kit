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

"""Plugin diagnostics for test."""

import os
import subprocess
from pathlib import Path
from typing import Dict, List
import sys

from .diagnostics import (
    DiagnosticCheck,
    DiagnosticResult,
    DiagnosticIssue,
    DiagnosticLevel,
    DiagnosticCategory,
)
from ..plugin_manager import PluginManager, PluginState


class PluginDiscoveryCheck(DiagnosticCheck):
    """Check plugin discovery functionality."""

    @property
    def name(self) -> str:
        return "Plugin Discovery Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PLUGIN

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            manager = PluginManager()
            manager.discover_plugins()  # Discover plugins before listing
            plugins = manager.list_plugins()

            if not plugins:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="No plugins discovered",
                        details="test requires at least one plugin to function",
                        fix_suggestion="Install plugins or check plugin directories",
                    )
                )
            else:
                result.checks_passed += 1

                # Check for discovered but not loaded plugins
                unloaded = [p for p in plugins if p.state == PluginState.DISCOVERED]
                if unloaded:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.INFO,
                            message=f"Found {len(unloaded)} discovered but unloaded plugins",
                            details=f"Plugins: {', '.join(p.name for p in unloaded)}",
                            metadata={"unloaded_plugins": [p.name for p in unloaded]},
                        )
                    )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Plugin discovery failed",
                    details=str(e),
                    fix_suggestion="Check plugin system configuration",
                )
            )

        return result


class PluginLoadingCheck(DiagnosticCheck):
    """Check plugin loading and initialization."""

    @property
    def name(self) -> str:
        return "Plugin Loading Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PLUGIN

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        try:
            manager = PluginManager()
            manager.discover_plugins()  # Discover plugins before listing
            plugins = manager.list_plugins()

            for plugin_info in plugins:
                result.checks_performed += 1

                if plugin_info.state == PluginState.ERROR:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message=f"Plugin '{plugin_info.name}' failed to load",
                            details=plugin_info.error,
                            metadata={
                                "plugin_name": plugin_info.name,
                                "plugin_path": str(plugin_info.path) if plugin_info.path else None,
                            },
                        )
                    )
                elif plugin_info.state == PluginState.DISCOVERED:
                    # Try to load and initialize the plugin
                    try:
                        manager.load_plugin(plugin_info.name)
                        manager.initialize_plugin(plugin_info.name)
                        result.checks_passed += 1
                    except Exception as e:
                        result.add_issue(
                            DiagnosticIssue(
                                category=self.category,
                                level=DiagnosticLevel.ERROR,
                                message=f"Plugin '{plugin_info.name}' failed to load",
                                details=str(e),
                                metadata={"plugin_name": plugin_info.name},
                            )
                        )
                elif plugin_info.state in [
                    PluginState.LOADED,
                    PluginState.INITIALIZED,
                    PluginState.ACTIVE,
                ]:
                    result.checks_passed += 1

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Plugin loading check failed",
                    details=str(e),
                )
            )

        return result


class PluginDependencyCheck(DiagnosticCheck):
    """Check plugin dependencies."""

    @property
    def name(self) -> str:
        return "Plugin Dependency Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PLUGIN

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        try:
            manager = PluginManager()
            manager.discover_plugins()  # Discover plugins before listing
            plugins = manager.list_plugins()

            # Check Python plugin dependencies
            self._check_python_dependencies(result)

            # Check JavaScript plugin dependencies
            self._check_javascript_dependencies(result)

            # Check plugin-specific dependencies
            for plugin_info in plugins:
                result.checks_performed += 1
                try:
                    # Load plugin if needed to check dependencies
                    if (
                        not plugin_info.plugin_instance
                        and plugin_info.state == PluginState.DISCOVERED
                    ):
                        manager.load_plugin(plugin_info.name)

                    if plugin_info.name in manager.instances:
                        metadata = manager.instances[plugin_info.name].get_metadata()

                        # Check minimum version
                        if metadata.min_version:
                            from .. import __version__

                            if self._compare_versions(__version__, metadata.min_version) < 0:
                                result.add_issue(
                                    DiagnosticIssue(
                                        category=self.category,
                                        level=DiagnosticLevel.ERROR,
                                        message=f"Plugin '{plugin_info.name}' requires test version {metadata.min_version}",
                                        details=f"Current test version is {__version__}",
                                        fix_suggestion="Update test to the required version",
                                    )
                                )
                            else:
                                result.checks_passed += 1
                        else:
                            result.checks_passed += 1
                    else:
                        # Plugin couldn't be loaded
                        result.add_issue(
                            DiagnosticIssue(
                                category=self.category,
                                level=DiagnosticLevel.WARNING,
                                message=f"Could not load plugin '{plugin_info.name}' to check dependencies",
                                details="Plugin must be loaded to verify dependencies",
                            )
                        )

                except Exception as e:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message=f"Failed to check dependencies for plugin '{plugin_info.name}'",
                            details=str(e),
                        )
                    )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Plugin dependency check failed",
                    details=str(e),
                )
            )

        return result

    def _check_python_dependencies(self, result: DiagnosticResult) -> Dict[str, bool]:
        """Check Python-specific dependencies."""
        deps = {}

        # Check for pytest (needed for Python plugin)
        result.checks_performed += 1
        try:
            import pytest

            deps["pytest"] = True
            result.checks_passed += 1
        except ImportError:
            deps["pytest"] = False
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="pytest not installed",
                    details="The Python plugin requires pytest to run tests",
                    fix_suggestion="pip install pytest",
                    auto_fixable=True,
                    auto_fix_action=lambda: self._install_package("pytest"),
                )
            )

        return deps

    def _check_javascript_dependencies(self, result: DiagnosticResult) -> Dict[str, bool]:
        """Check JavaScript-specific dependencies."""
        deps = {}

        # Check for Node.js
        result.checks_performed += 1
        try:
            node_result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True, timeout=5
            )
            if node_result.returncode == 0:
                deps["node"] = True
                result.checks_passed += 1
            else:
                deps["node"] = False
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="Node.js not available",
                        details="JavaScript plugins require Node.js",
                        fix_suggestion="Install Node.js from https://nodejs.org",
                    )
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            deps["node"] = False
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Node.js not found",
                    details="JavaScript plugins require Node.js to be installed",
                    fix_suggestion="Install Node.js from https://nodejs.org",
                )
            )

        # Check for npm
        result.checks_performed += 1
        try:
            npm_result = subprocess.run(
                ["npm", "--version"], capture_output=True, text=True, timeout=5
            )
            if npm_result.returncode == 0:
                deps["npm"] = True
                result.checks_passed += 1
            else:
                deps["npm"] = False
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="npm not available",
                        details="npm is needed to install JavaScript test framework dependencies",
                        fix_suggestion="npm should come with Node.js installation",
                    )
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            deps["npm"] = False
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="npm not found",
                    details="npm is needed for JavaScript projects",
                    fix_suggestion="Install Node.js which includes npm",
                )
            )

        return deps

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings."""
        # Simple version comparison (could be enhanced)
        v1_parts = [int(x) for x in v1.split(".")]
        v2_parts = [int(x) for x in v2.split(".")]

        for i in range(max(len(v1_parts), len(v2_parts))):
            p1 = v1_parts[i] if i < len(v1_parts) else 0
            p2 = v2_parts[i] if i < len(v2_parts) else 0

            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1

        return 0

    def _install_package(self, package: str) -> bool:
        """Attempt to install a Python package."""
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                check=True,
                capture_output=True,
                timeout=60,
            )
            return True
        except Exception:
            return False


class PluginCompatibilityCheck(DiagnosticCheck):
    """Check plugin compatibility with current project."""

    @property
    def name(self) -> str:
        return "Plugin Compatibility Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PLUGIN

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        try:
            manager = PluginManager()
            manager.discover_plugins()  # Discover plugins before listing
            # Initialize plugins first
            for plugin_info in manager.list_plugins():
                if plugin_info.state == PluginState.DISCOVERED:
                    try:
                        manager.load_plugin(plugin_info.name)
                        manager.initialize_plugin(plugin_info.name)
                    except Exception:
                        pass  # Will be handled by other checks

            # Consider INITIALIZED plugins as active
            active_plugins = [
                p
                for p in manager.list_plugins()
                if p.state in (PluginState.INITIALIZED, PluginState.ACTIVE)
            ]

            # Detect project type
            project_files = self._detect_project_type()

            if not project_files:
                result.checks_performed += 1
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.INFO,
                        message="Could not detect project type",
                        details="No recognizable project files found",
                        fix_suggestion="Ensure you're in a project directory with test files",
                    )
                )
                return result

            # Check if we have appropriate plugins for detected project types
            for project_type, files in project_files.items():
                result.checks_performed += 1

                # Check if any active plugin supports this project type
                has_plugin = False
                for p in active_plugins:
                    if p.name in manager.instances:
                        metadata = manager.instances[p.name].get_metadata()
                        if project_type in metadata.supported_frameworks:
                            has_plugin = True
                            break

                if has_plugin:
                    result.checks_passed += 1
                else:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message=f"No active plugin found for {project_type} project",
                            details=f"Found {project_type} files but no compatible plugin is active",
                            metadata={"project_type": project_type, "files": files},
                            fix_suggestion=f"Enable or install a plugin that supports {project_type}",
                        )
                    )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Plugin compatibility check failed",
                    details=str(e),
                )
            )

        return result

    def _detect_project_type(self) -> Dict[str, List[str]]:
        """Detect project type based on files present."""
        project_types = {}

        # Python project indicators
        python_files = []
        if Path("setup.py").exists():
            python_files.append("setup.py")
        if Path("pyproject.toml").exists():
            python_files.append("pyproject.toml")
        if Path("requirements.txt").exists():
            python_files.append("requirements.txt")
        if any(Path(".").glob("**/*.py")):
            python_files.append("*.py files")

        if python_files:
            project_types["python"] = python_files

        # JavaScript project indicators
        js_files = []
        if Path("package.json").exists():
            js_files.append("package.json")
        if Path("vite.config.js").exists() or Path("vite.config.ts").exists():
            js_files.append("vite.config.*")
        if Path("vitest.config.js").exists() or Path("vitest.config.ts").exists():
            js_files.append("vitest.config.*")
        if any(Path(".").glob("**/*.js")) or any(Path(".").glob("**/*.ts")):
            js_files.append("*.js/*.ts files")

        if js_files:
            project_types["javascript"] = js_files

        return project_types


class PluginPermissionsCheck(DiagnosticCheck):
    """Check plugin file permissions and accessibility."""

    @property
    def name(self) -> str:
        return "Plugin Permissions Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PLUGIN

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check plugin directories
        plugin_dirs = [Path.home() / '.qrs' / "plugins", Path('.qrs') / "plugins"]

        for plugin_dir in plugin_dirs:
            result.checks_performed += 1

            if plugin_dir.exists():
                if not os.access(plugin_dir, os.R_OK):
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message=f"Plugin directory not readable: {plugin_dir}",
                            details="Cannot read plugins from this directory",
                            file_path=plugin_dir,
                            fix_suggestion=f"Fix permissions: chmod 755 {plugin_dir}",
                        )
                    )
                elif not os.access(plugin_dir, os.X_OK):
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message=f"Plugin directory not executable: {plugin_dir}",
                            details="Cannot list plugins in this directory",
                            file_path=plugin_dir,
                            fix_suggestion=f"Fix permissions: chmod 755 {plugin_dir}",
                        )
                    )
                else:
                    result.checks_passed += 1
            else:
                # Directory doesn't exist, which is okay
                result.checks_passed += 1

        return result


def get_plugin_diagnostics() -> List[DiagnosticCheck]:
    """Get all plugin diagnostic checks."""
    return [
        PluginDiscoveryCheck(),
        PluginLoadingCheck(),
        PluginDependencyCheck(),
        PluginCompatibilityCheck(),
        PluginPermissionsCheck(),
    ]
