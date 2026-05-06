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

"""Runtime and filesystem diagnostics for test."""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List
import psutil
import json

from .diagnostics import (
    DiagnosticCheck,
    DiagnosticResult,
    DiagnosticIssue,
    DiagnosticLevel,
    DiagnosticCategory,
)
from ..registry import Registry


class TestDiscoveryCheck(DiagnosticCheck):
    """Validate test discovery functionality."""

    @property
    def name(self) -> str:
        return "Test Discovery Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.CONFIGURATION

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            # Initialize registry
            registry = Registry()

            # Check if discovery works
            discovery_result = registry.discover_incremental()

            if discovery_result["total_discovered"] == 0:
                # Check if we're in a valid project directory
                config_files = [
                    "pyproject.toml",
                    "package.json",
                    "pytest.ini",
                    "vitest.config.js",
                    "jest.config.js",
                ]

                has_config = any(Path(f).exists() for f in config_files)

                if not has_config:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message="No tests discovered",
                            details="No test files found in the current directory",
                            fix_suggestion="Ensure you're in a project directory with tests",
                        )
                    )
                else:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message="Test discovery failed",
                            details="Configuration found but no tests discovered",
                            fix_suggestion="Check test patterns in your project config",
                        )
                    )
            else:
                result.checks_passed += 1

                # Check discovery statistics
                stats = discovery_result.get("statistics", {})
                if stats:
                    cache_hit_rate = (
                        stats.cache_hits / (stats.cache_hits + stats.cache_misses)
                        if (stats.cache_hits + stats.cache_misses) > 0
                        else 0
                    )

                    if cache_hit_rate < 0.5 and stats.total_files > 100:
                        result.add_issue(
                            DiagnosticIssue(
                                category=self.category,
                                level=DiagnosticLevel.INFO,
                                message="Low cache hit rate in test discovery",
                                details=f"Cache hit rate: {cache_hit_rate:.1%}",
                                fix_suggestion="Consider clearing the test cache if discovery is slow",
                            )
                        )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Test discovery check failed",
                    details=str(e),
                    fix_suggestion="Check test installation and configuration",
                )
            )

        return result


class RegistryIntegrityCheck(DiagnosticCheck):
    """Ensure test registry is valid and consistent."""

    @property
    def name(self) -> str:
        return "Registry Integrity Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.CONFIGURATION

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            registry = Registry()

            # Check registry file exists
            if not registry.registry_path.exists():
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.INFO,
                        message="No test registry found",
                        details="Registry will be created on first test discovery",
                        fix_suggestion="Initialize the registry",
                    )
                )
                return result

            # Load and validate registry
            try:
                with open(registry.registry_path, "r") as f:
                    data = json.load(f)

                # Check structure
                required_keys = ["version", "tests", "metadata"]
                missing_keys = [k for k in required_keys if k not in data]

                if missing_keys:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message="Invalid registry structure",
                            details=f"Missing keys: {', '.join(missing_keys)}",
                            fix_suggestion="Clear the test cache to rebuild the registry",
                            auto_fixable=True,
                            auto_fix_action=lambda: registry.clear_cache(),
                        )
                    )
                else:
                    # Check for orphaned tests
                    orphaned_tests = []
                    for test_id, test_data in data.get("tests", {}).items():
                        test_path = Path(test_data.get("path", ""))
                        if not test_path.exists():
                            orphaned_tests.append(test_id)

                    if orphaned_tests:
                        result.add_issue(
                            DiagnosticIssue(
                                category=self.category,
                                level=DiagnosticLevel.WARNING,
                                message=f"Found {len(orphaned_tests)} orphaned test entries",
                                details="Registry contains tests that no longer exist",
                                fix_suggestion="Re-initialize the registry",
                                metadata={"orphaned_count": len(orphaned_tests)},
                            )
                        )
                    else:
                        result.checks_passed += 1

            except json.JSONDecodeError as e:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Corrupted registry file",
                        details=f"JSON decode error: {e}",
                        fix_suggestion="Clear the test cache to rebuild the registry",
                        auto_fixable=True,
                        auto_fix_action=lambda: registry.clear_cache(),
                    )
                )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Registry integrity check failed",
                    details=str(e),
                )
            )

        return result


class CacheValidationCheck(DiagnosticCheck):
    """Verify cache integrity and performance."""

    @property
    def name(self) -> str:
        return "Cache Validation Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.PERFORMANCE

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            # Check cache directory
            cache_dir = Path.home() / '.qrs' / "cache"

            if not cache_dir.exists():
                result.checks_passed += 1
                return result

            # Calculate cache size
            cache_size = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
            cache_size_mb = cache_size / (1024 * 1024)

            # Check cache size
            if cache_size_mb > 100:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"Large cache size: {cache_size_mb:.1f} MB",
                        details="Cache is consuming significant disk space",
                        fix_suggestion="Clear the test cache to remove old entries",
                        metadata={"cache_size_mb": cache_size_mb},
                    )
                )

            # Check for stale cache entries
            import time

            current_time = time.time()
            stale_count = 0
            stale_threshold = 30 * 24 * 60 * 60  # 30 days

            for cache_file in cache_dir.rglob("*.json"):
                try:
                    mtime = cache_file.stat().st_mtime
                    if current_time - mtime > stale_threshold:
                        stale_count += 1
                except:
                    pass

            if stale_count > 50:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.INFO,
                        message=f"Found {stale_count} stale cache entries",
                        details="Cache contains entries older than 30 days",
                        fix_suggestion="Consider clearing the test cache periodically",
                        metadata={"stale_count": stale_count},
                    )
                )

            # Check cache permissions
            try:
                test_file = cache_dir / ".test_write"
                test_file.write_text("test")
                test_file.unlink()
                result.checks_passed += 1
            except Exception as e:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Cache directory not writable",
                        details=str(e),
                        fix_suggestion=f"Check permissions on {cache_dir}",
                    )
                )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Cache validation failed",
                    details=str(e),
                )
            )

        return result


class DiskSpaceCheck(DiagnosticCheck):
    """Ensure adequate disk space for operations."""

    @property
    def name(self) -> str:
        return "Disk Space Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.FILESYSTEM

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            # Get disk usage for current directory
            stat = shutil.disk_usage(Path.cwd())

            # Calculate percentages
            free_gb = stat.free / (1024**3)
            total_gb = stat.total / (1024**3)
            used_percent = (stat.used / stat.total) * 100

            # Check thresholds
            if free_gb < 0.1:  # Less than 100MB free
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.CRITICAL,
                        message="Critical: Very low disk space",
                        details=f"Only {free_gb:.2f} GB free",
                        fix_suggestion="Free up disk space immediately",
                        metadata={"free_gb": free_gb, "used_percent": used_percent},
                    )
                )
            elif free_gb < 1.0:  # Less than 1GB free
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Low disk space",
                        details=f"Only {free_gb:.2f} GB free ({used_percent:.1f}% used)",
                        fix_suggestion="Consider freeing up disk space",
                        metadata={"free_gb": free_gb, "used_percent": used_percent},
                    )
                )
            elif free_gb < 5.0:  # Less than 5GB free
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message="Disk space running low",
                        details=f"{free_gb:.1f} GB free ({used_percent:.1f}% used)",
                        fix_suggestion="Monitor disk usage",
                        metadata={"free_gb": free_gb, "used_percent": used_percent},
                    )
                )
            else:
                result.checks_passed += 1

                # Info about available space
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.INFO,
                        message=f"Disk space OK: {free_gb:.1f} GB free",
                        details=f"Total: {total_gb:.1f} GB, Used: {used_percent:.1f}%",
                        metadata={
                            "free_gb": free_gb,
                            "total_gb": total_gb,
                            "used_percent": used_percent,
                        },
                    )
                )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.WARNING,
                    message="Could not check disk space",
                    details=str(e),
                )
            )

        return result


class TempDirectoryCheck(DiagnosticCheck):
    """Verify temp directory access and space."""

    @property
    def name(self) -> str:
        return "Temp Directory Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.FILESYSTEM

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            # Get temp directory
            temp_dir = Path(tempfile.gettempdir())

            # Check if it exists and is a directory
            if not temp_dir.exists():
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Temp directory does not exist",
                        details=f"Path: {temp_dir}",
                        fix_suggestion="Check system temp directory configuration",
                    )
                )
                return result

            if not temp_dir.is_dir():
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Temp path is not a directory",
                        details=f"Path: {temp_dir}",
                        fix_suggestion="Check system temp directory configuration",
                    )
                )
                return result

            # Test write access
            try:
                test_file = temp_dir / f"diag_test_{os.getpid()}.tmp"
                test_file.write_text("temp directory write test")
                test_file.unlink()
            except Exception as e:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Cannot write to temp directory",
                        details=f"Path: {temp_dir}, Error: {e}",
                        fix_suggestion="Check temp directory permissions",
                    )
                )
                return result

            # Check available space in temp
            try:
                stat = shutil.disk_usage(temp_dir)
                free_gb = stat.free / (1024**3)

                if free_gb < 0.1:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.ERROR,
                            message="Very low space in temp directory",
                            details=f"Only {free_gb:.2f} GB free in {temp_dir}",
                            fix_suggestion="Clean up temp directory",
                            metadata={"temp_dir": str(temp_dir), "free_gb": free_gb},
                        )
                    )
                elif free_gb < 1.0:
                    result.add_issue(
                        DiagnosticIssue(
                            category=self.category,
                            level=DiagnosticLevel.WARNING,
                            message="Low space in temp directory",
                            details=f"Only {free_gb:.2f} GB free in {temp_dir}",
                            fix_suggestion="Consider cleaning temp directory",
                            metadata={"temp_dir": str(temp_dir), "free_gb": free_gb},
                        )
                    )
                else:
                    result.checks_passed += 1

            except Exception:
                # Not critical if we can't check space
                result.checks_passed += 1

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.ERROR,
                    message="Temp directory check failed",
                    details=str(e),
                )
            )

        return result


class ProcessCheck(DiagnosticCheck):
    """Check for system resource availability."""

    @property
    def name(self) -> str:
        return "Process and Memory Check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.ENVIRONMENT

    def run(self) -> DiagnosticResult:
        result = DiagnosticResult()
        result.checks_performed += 1

        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"High CPU usage: {cpu_percent}%",
                        details="System is under heavy load",
                        fix_suggestion="Consider running tests when system is less busy",
                        metadata={"cpu_percent": cpu_percent},
                    )
                )

            # Check memory
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"High memory usage: {memory.percent}%",
                        details=f"Available: {memory.available / (1024**3):.1f} GB",
                        fix_suggestion="Close unnecessary applications",
                        metadata={"memory_percent": memory.percent},
                    )
                )
            elif memory.available < 512 * 1024 * 1024:  # Less than 512MB
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.ERROR,
                        message="Very low available memory",
                        details=f"Only {memory.available / (1024**2):.0f} MB available",
                        fix_suggestion="Free up memory before running tests",
                        metadata={"memory_available_mb": memory.available / (1024**2)},
                    )
                )
            else:
                result.checks_passed += 1

            # Check for zombie processes
            zombie_count = 0
            for proc in psutil.process_iter(["pid", "status"]):
                try:
                    if proc.info["status"] == psutil.STATUS_ZOMBIE:
                        zombie_count += 1
                except:
                    pass

            if zombie_count > 10:
                result.add_issue(
                    DiagnosticIssue(
                        category=self.category,
                        level=DiagnosticLevel.WARNING,
                        message=f"Found {zombie_count} zombie processes",
                        details="System has accumulated zombie processes",
                        fix_suggestion="Consider restarting or cleaning up processes",
                        metadata={"zombie_count": zombie_count},
                    )
                )

        except Exception as e:
            result.add_issue(
                DiagnosticIssue(
                    category=self.category,
                    level=DiagnosticLevel.INFO,
                    message="Could not check system resources",
                    details=str(e),
                )
            )

        return result


# Export functions to get diagnostic checks
def get_runtime_diagnostics() -> List[DiagnosticCheck]:
    """Get all runtime diagnostic checks."""
    return [TestDiscoveryCheck(), RegistryIntegrityCheck(), CacheValidationCheck()]


def get_filesystem_diagnostics() -> List[DiagnosticCheck]:
    """Get all filesystem diagnostic checks."""
    return [DiskSpaceCheck(), TempDirectoryCheck()]


def get_system_diagnostics() -> List[DiagnosticCheck]:
    """Get all system diagnostic checks."""
    return [ProcessCheck()]


__all__ = [
    "TestDiscoveryCheck",
    "RegistryIntegrityCheck",
    "CacheValidationCheck",
    "DiskSpaceCheck",
    "TempDirectoryCheck",
    "ProcessCheck",
    "get_runtime_diagnostics",
    "get_filesystem_diagnostics",
    "get_system_diagnostics",
]
