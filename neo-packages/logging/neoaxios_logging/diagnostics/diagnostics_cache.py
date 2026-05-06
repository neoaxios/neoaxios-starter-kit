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

"""Cache health diagnostics for Python and test files."""

import subprocess
from pathlib import Path
from typing import List, Dict
from collections import defaultdict

from .diagnostics import DiagnosticCheck, DiagnosticIssue, DiagnosticLevel, DiagnosticCategory


class OrphanedCacheCheck(DiagnosticCheck):
    """Detect .pyc files without corresponding .py files."""

    @property
    def name(self) -> str:
        return "orphaned_cache_check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.FILESYSTEM

    @property
    def description(self) -> str:
        return "Detect orphaned Python cache files"

    def run(self) -> "DiagnosticResult":
        """Run the diagnostic check."""
        from .diagnostics import DiagnosticResult
        result = DiagnosticResult(checks_performed=1)
        issues = self.run_check({})
        if not issues:
            result.checks_passed = 1
        for issue in issues:
            result.add_issue(issue)
        return result

    def run_check(self, context: Dict) -> List[DiagnosticIssue]:
        """Find .pyc files without corresponding .py files."""
        issues = []
        project_root = Path(context.get("project_root", "."))

        # Find all .pyc files
        pyc_files = list(project_root.rglob("*.pyc"))
        orphaned_files = []

        for pyc_file in pyc_files:
            # Convert .pyc path to expected .py path
            py_file = self._get_source_file_path(pyc_file)

            if not py_file.exists():
                orphaned_files.append(pyc_file)

        if orphaned_files:
            issues.append(
                DiagnosticIssue(
                    category=DiagnosticCategory.FILESYSTEM,
                    level=DiagnosticLevel.WARNING,
                    message=f"Found {len(orphaned_files)} orphaned Python cache files",
                    details="Cache files without corresponding source files:\n"
                    + "\n".join(f"  - {f}" for f in orphaned_files[:10])
                    + (
                        f"\n  ... and {len(orphaned_files) - 10} more"
                        if len(orphaned_files) > 10
                        else ""
                    ),
                    fix_suggestion="Remove orphaned cache files with the diagnostic auto-fix",
                    auto_fixable=True,
                    auto_fix_action=lambda: self._remove_orphaned_cache(orphaned_files),
                    metadata={"orphaned_files": [str(f) for f in orphaned_files]},
                )
            )

        return issues

    def _get_source_file_path(self, pyc_file: Path) -> Path:
        """Convert .pyc file path to expected .py file path."""
        # Handle __pycache__ directory structure
        if "__pycache__" in pyc_file.parts:
            # Example: /path/__pycache__/module.cpython-312.pyc -> /path/module.py
            cache_dir = pyc_file.parent
            parent_dir = cache_dir.parent

            # Extract base name (remove .cpython-xxx.pyc suffix)
            name = pyc_file.stem
            if ".cpython-" in name:
                name = name.split(".cpython-")[0]

            return parent_dir / f"{name}.py"
        else:
            # Direct .pyc file (older Python versions)
            return pyc_file.with_suffix(".py")

    def _remove_orphaned_cache(self, orphaned_files: List[Path]) -> bool:
        """Remove orphaned cache files."""
        try:
            for pyc_file in orphaned_files:
                if pyc_file.exists():
                    pyc_file.unlink()
            return True
        except Exception:
            # Failed to remove cache files - return False to indicate failure
            return False


class DuplicateTestCheck(DiagnosticCheck):
    """Detect duplicate test execution due to cache/import issues."""

    @property
    def name(self) -> str:
        return "duplicate_test_check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.FILESYSTEM

    @property
    def description(self) -> str:
        return "Detect tests being collected multiple times"

    def run(self) -> "DiagnosticResult":
        """Run the diagnostic check."""
        from .diagnostics import DiagnosticResult
        result = DiagnosticResult(checks_performed=1)
        issues = self.run_check({})
        if not issues:
            result.checks_passed = 1
        for issue in issues:
            result.add_issue(issue)
        return result

    def run_check(self, context: Dict) -> List[DiagnosticIssue]:
        """Check for duplicate test collection."""
        issues = []
        project_root = Path(context.get("project_root", "."))

        # Run pytest --collect-only to get test collection
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "--collect-only", "-q"],
                capture_output=True,
                text=True,
                cwd=project_root,
                timeout=30,
            )

            if result.returncode == 0:
                test_lines = [
                    line.strip()
                    for line in result.stdout.split("\n")
                    if "::" in line and not line.startswith("=")
                ]

                # Count test occurrences
                test_counts = defaultdict(int)
                for line in test_lines:
                    test_counts[line] += 1

                # Find duplicates
                duplicates = {test: count for test, count in test_counts.items() if count > 1}

                if duplicates:
                    issues.append(
                        DiagnosticIssue(
                            category=DiagnosticCategory.FILESYSTEM,
                            level=DiagnosticLevel.ERROR,
                            message=f"Found {len(duplicates)} tests being collected multiple times",
                            details="Duplicate test collections:\n"
                            + "\n".join(
                                f"  - {test} ({count}x)" for test, count in duplicates.items()
                            ),
                            fix_suggestion="Clean Python cache with the diagnostic auto-fix",
                            auto_fixable=True,
                            auto_fix_action=self._clean_all_cache,
                            metadata={"duplicates": duplicates},
                        )
                    )

        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            issues.append(
                DiagnosticIssue(
                    category=DiagnosticCategory.FILESYSTEM,
                    level=DiagnosticLevel.WARNING,
                    message="Could not analyze test collection for duplicates",
                    details=f"Error: {e}",
                    fix_suggestion="Try running 'pytest --collect-only' manually",
                )
            )

        return issues

    def _clean_all_cache(self) -> bool:
        """Clean all Python cache files."""
        try:
            # Remove .pyc files
            subprocess.run(["find", ".", "-name", "*.pyc", "-delete"], check=True)

            # Remove __pycache__ directories
            subprocess.run(
                [
                    "find",
                    ".",
                    "-name",
                    "__pycache__",
                    "-type",
                    "d",
                    "-exec",
                    "rm",
                    "-rf",
                    "{}",
                    "+",
                ],
                check=False,
            )  # Don't fail if some directories are already gone

            # Remove pytest cache
            pytest_cache = Path(".pytest_cache")
            if pytest_cache.exists():
                import shutil

                shutil.rmtree(pytest_cache)

            return True
        except Exception:
            # Failed to clean cache - return False to indicate failure
            return False


class CacheConsistencyCheck(DiagnosticCheck):
    """Check for cache consistency issues."""

    @property
    def name(self) -> str:
        return "cache_consistency_check"

    @property
    def category(self) -> DiagnosticCategory:
        return DiagnosticCategory.FILESYSTEM

    @property
    def description(self) -> str:
        return "Check for Python cache consistency issues"

    def run(self) -> "DiagnosticResult":
        """Run the diagnostic check."""
        from .diagnostics import DiagnosticResult
        result = DiagnosticResult(checks_performed=1)
        issues = self.run_check({})
        if not issues:
            result.checks_passed = 1
        for issue in issues:
            result.add_issue(issue)
        return result

    def run_check(self, context: Dict) -> List[DiagnosticIssue]:
        """Check cache consistency."""
        issues = []
        project_root = Path(context.get("project_root", "."))

        # Check for excessive cache files
        py_files = list(project_root.rglob("*.py"))
        pyc_files = list(project_root.rglob("*.pyc"))

        if len(pyc_files) > len(py_files) * 2:  # Heuristic: too many cache files
            issues.append(
                DiagnosticIssue(
                    category=DiagnosticCategory.FILESYSTEM,
                    level=DiagnosticLevel.WARNING,
                    message=f"Excessive cache files detected ({len(pyc_files)} .pyc vs {len(py_files)} .py)",
                    details=f"Found {len(pyc_files)} cache files for {len(py_files)} Python files. "
                    + "This may indicate cache buildup or orphaned files.",
                    fix_suggestion="Clean cache with the diagnostic auto-fix",
                    auto_fixable=True,
                    auto_fix_action=self._clean_excessive_cache,
                    metadata={"pyc_count": len(pyc_files), "py_count": len(py_files)},
                )
            )

        # Check for old cache files
        old_cache_files = []
        for pyc_file in pyc_files:
            # Check if cache is older than source
            py_file = self._get_source_file_for_cache(pyc_file)
            if py_file and py_file.exists():
                if pyc_file.stat().st_mtime < py_file.stat().st_mtime:
                    old_cache_files.append(pyc_file)

        if old_cache_files:
            issues.append(
                DiagnosticIssue(
                    category=DiagnosticCategory.FILESYSTEM,
                    level=DiagnosticLevel.INFO,
                    message=f"Found {len(old_cache_files)} outdated cache files",
                    details="Cache files older than their source files (normal, but can be cleaned)",
                    fix_suggestion="Clean outdated cache with the diagnostic auto-fix",
                    auto_fixable=True,
                    auto_fix_action=lambda: self._remove_old_cache(old_cache_files),
                    metadata={"old_cache_count": len(old_cache_files)},
                )
            )

        return issues

    def _get_source_file_for_cache(self, pyc_file: Path) -> Path:
        """Get the source file for a cache file."""
        if "__pycache__" in pyc_file.parts:
            cache_dir = pyc_file.parent
            parent_dir = cache_dir.parent
            name = pyc_file.stem
            if ".cpython-" in name:
                name = name.split(".cpython-")[0]
            return parent_dir / f"{name}.py"
        else:
            return pyc_file.with_suffix(".py")

    def _clean_excessive_cache(self) -> bool:
        """Clean excessive cache files."""
        try:
            subprocess.run(["find", ".", "-name", "*.pyc", "-delete"], check=True)
            subprocess.run(
                [
                    "find",
                    ".",
                    "-name",
                    "__pycache__",
                    "-type",
                    "d",
                    "-exec",
                    "rm",
                    "-rf",
                    "{}",
                    "+",
                ],
                check=False,
            )
            return True
        except Exception:
            # Failed to clean cache - return False to indicate failure
            return False

    def _remove_old_cache(self, old_files: List[Path]) -> bool:
        """Remove old cache files."""
        try:
            for cache_file in old_files:
                if cache_file.exists():
                    cache_file.unlink()
            return True
        except Exception:
            # Failed to remove old cache files - return False to indicate failure
            return False


def get_cache_diagnostics() -> List[DiagnosticCheck]:
    """Get all cache diagnostic checks."""
    return [OrphanedCacheCheck(), DuplicateTestCheck(), CacheConsistencyCheck()]
