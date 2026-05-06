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

"""Environment diagnostics for test."""

import os
import sys
import subprocess
import platform
from pathlib import Path
from typing import List
import shutil

from .diagnostics import (
    DiagnosticCheck,
    DiagnosticResult,
    DiagnosticIssue,
    DiagnosticLevel,
    DiagnosticCategory,
)


class PythonVersionCheck(DiagnosticCheck):
    """Check Python version compatibility."""

    @property
    def name(self) -> str:
        return "Python Version Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        current_version = sys.version_info
        min_version = (3, 8)  # Minimum Python version for test

        if current_version < min_version:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message=f"Python version {current_version.major}.{current_version.minor} is not supported",
                    details=f"test requires Python {min_version[0]}.{min_version[1]} or higher",
                    fix_suggestion=f"Upgrade to Python {min_version[0]}.{min_version[1]} or higher",
                    metadata={
                        "current_version": f"{current_version.major}.{current_version.minor}.{current_version.micro}",
                        "required_version": f"{min_version[0]}.{min_version[1]}",
                    },
                )
            )
        else:
            result.checks_passed += 1

            # Check for deprecated Python versions
            if current_version.major == 3 and current_version.minor < 9:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"Python {current_version.major}.{current_version.minor} is approaching end-of-life",
                        details="Consider upgrading to a newer Python version for better performance and security",
                        fix_suggestion="Upgrade to Python 3.10 or higher",
                    )
                )

        return result


class GitCheck(DiagnosticCheck):
    """Check Git installation and repository status."""

    @property
    def name(self) -> str:
        return "Git Installation Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check Git installation
        result.checks_performed += 1
        git_path = shutil.which("git")

        if not git_path:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Git is not installed or not in PATH",
                    details="Git is recommended for tracking test changes over time",
                    fix_suggestion="Install Git from https://git-scm.com",
                )
            )
        else:
            result.checks_passed += 1

            # Check if we're in a Git repository
            result.checks_performed += 1
            try:
                git_result = subprocess.run(
                    ["git", "rev-parse", "--git-dir"], capture_output=True, text=True, timeout=5
                )
                if git_result.returncode == 0:
                    result.checks_passed += 1
                else:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.INFO,
                            message="Not in a Git repository",
                            details="Version control helps track test metrics over time",
                            fix_suggestion="Run 'git init' to initialize a repository",
                        )
                    )
            except Exception as e:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="Failed to check Git repository status",
                        details=str(e),
                    )
                )

        return result


class FileSystemPermissionsCheck(DiagnosticCheck):
    """Check file system permissions for test operations."""

    @property
    def name(self) -> str:
        return "File System Permissions Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check current directory permissions
        current_dir = Path.cwd()
        result.checks_performed += 1

        if not os.access(current_dir, os.R_OK):
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Cannot read from current directory",
                    details=f"No read permission for {current_dir}",
                    file_path=current_dir,
                    fix_suggestion=f"Check directory permissions: chmod 755 {current_dir}",
                )
            )
        elif not os.access(current_dir, os.W_OK):
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Cannot write to current directory",
                    details="test needs write permission to create registry and cache files",
                    file_path=current_dir,
                    fix_suggestion=f"Check directory permissions: chmod 755 {current_dir}",
                )
            )
        else:
            result.checks_passed += 1

        # Check .qrs directory
        qrs_dir = current_dir / ".qrs"
        if qrs_dir.exists():
            result.checks_performed += 1
            if not os.access(qrs_dir, os.R_OK | os.W_OK):
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message=".qrs directory is not accessible",
                        details="test requires read/write access to .qrs directory",
                        file_path=qrs_dir,
                        fix_suggestion=f"Fix permissions: chmod 755 {qrs_dir}",
                    )
                )
            else:
                result.checks_passed += 1

        # Check home directory test config
        home_qrs = Path.home() / ".qrs"
        if home_qrs.exists():
            result.checks_performed += 1
            if not os.access(home_qrs, os.R_OK):
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="Cannot read from home .qrs directory",
                        details="Global plugins and configurations may not be accessible",
                        file_path=home_qrs,
                        fix_suggestion=f"Fix permissions: chmod 755 {home_qrs}",
                    )
                )
            else:
                result.checks_passed += 1

        return result


class SystemResourcesCheck(DiagnosticCheck):
    """Check system resources (CPU, memory, disk space)."""

    @property
    def name(self) -> str:
        return "System Resources Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check CPU count
        result.checks_performed += 1
        cpu_count = os.cpu_count()
        if cpu_count and cpu_count < 2:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Low CPU count detected",
                    details=f"Only {cpu_count} CPU core(s) available. Parallel test execution may be limited",
                    metadata={"cpu_count": cpu_count},
                )
            )
        else:
            result.checks_passed += 1

        # Check available disk space
        result.checks_performed += 1
        try:
            if hasattr(os, "statvfs"):  # Unix-like systems
                stat = os.statvfs(".")
                free_space_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
                if free_space_mb < 100:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message="Low disk space",
                            details=f"Only {free_space_mb:.1f} MB free. Test execution may fail",
                            fix_suggestion="Free up disk space",
                            metadata={"free_space_mb": free_space_mb},
                        )
                    )
                else:
                    result.checks_passed += 1
            else:
                # Windows or unsupported platform
                result.checks_passed += 1
        except Exception:
            # Skip disk space check if it fails
            result.checks_passed += 1

        # Check memory (if psutil is available)
        result.checks_performed += 1
        try:
            import psutil

            memory = psutil.virtual_memory()
            available_mb = memory.available / (1024 * 1024)
            if available_mb < 512:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="Low available memory",
                        details=f"Only {available_mb:.1f} MB available. Large test suites may fail",
                        metadata={"available_memory_mb": available_mb},
                    )
                )
            else:
                result.checks_passed += 1
        except ImportError:
            # psutil not available, skip memory check
            result.checks_passed += 1
        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="Could not check memory usage",
                    details=str(e),
                )
            )

        return result


class NetworkConnectivityCheck(DiagnosticCheck):
    """Check network connectivity for plugin downloads and telemetry."""

    @property
    def name(self) -> str:
        return "Network Connectivity Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.CONNECTIVITY

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check basic network connectivity
        result.checks_performed += 1
        try:
            import urllib.request

            # Try to connect to a reliable host
            with urllib.request.urlopen("https://pypi.org", timeout=5) as response:
                if response.status == 200:
                    result.checks_passed += 1
                else:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message="Network connectivity issue",
                            details=f"PyPI returned status {response.status}",
                            fix_suggestion="Check your internet connection",
                        )
                    )
        except Exception:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="Cannot reach PyPI",
                    details="Plugin installation may not work",
                    fix_suggestion="Check network connection or proxy settings",
                )
            )

        # Check proxy settings
        result.checks_performed += 1
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

        if http_proxy or https_proxy:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="Proxy configuration detected",
                    details=f"HTTP: {http_proxy}, HTTPS: {https_proxy}",
                    metadata={"http_proxy": http_proxy, "https_proxy": https_proxy},
                )
            )
        else:
            result.checks_passed += 1

        return result


class PlatformCompatibilityCheck(DiagnosticCheck):
    """Check platform-specific compatibility."""

    @property
    def name(self) -> str:
        return "Platform Compatibility Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        system = platform.system()
        machine = platform.machine()

        # Check for known compatible platforms
        compatible_systems = ["Linux", "Darwin", "Windows"]
        if system not in compatible_systems:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message=f"Untested platform: {system}",
                    details=f"test may not be fully tested on {system} {machine}",
                    metadata={
                        "system": system,
                        "machine": machine,
                        "platform": platform.platform(),
                    },
                )
            )
        else:
            result.checks_passed += 1

            # Windows-specific checks
            if system == "Windows":
                result.checks_performed += 1
                # Check for Windows-specific issues
                if not os.environ.get("SYSTEMROOT"):
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message="SYSTEMROOT environment variable not set",
                            details="Some Windows operations may fail",
                        )
                    )
                else:
                    result.checks_passed += 1

        return result


class EnvironmentVariablesCheck(DiagnosticCheck):
    """Check environment variables that affect test."""

    @property
    def name(self) -> str:
        return "Environment Variables Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()

        # Check PATH
        result.checks_performed += 1
        path_var = os.environ.get("PATH", "")
        if not path_var:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="PATH environment variable is empty",
                    details="Cannot find executables without PATH",
                    fix_suggestion="Set the PATH environment variable",
                )
            )
        else:
            result.checks_passed += 1

        # Check for virtual environment
        result.checks_performed += 1
        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="Running in virtual environment",
                    details=f"Virtual environment: {venv}",
                    metadata={"virtual_env": venv},
                )
            )
        else:
            result.checks_passed += 1

        return result


def get_environment_diagnostics() -> List[DiagnosticCheck]:
    """Get all environment diagnostic checks."""
    return [
        PythonVersionCheck(),
        GitCheck(),
        FileSystemPermissionsCheck(),
        SystemResourcesCheck(),
        NetworkConnectivityCheck(),
        PlatformCompatibilityCheck(),
        EnvironmentVariablesCheck(),
    ]
