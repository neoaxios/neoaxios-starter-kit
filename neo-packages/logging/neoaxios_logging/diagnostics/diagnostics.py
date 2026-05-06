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

"""Diagnostics system for test."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import json
from pathlib import Path


class DiagnosticLevel(Enum):
    """Severity levels for diagnostic issues."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DiagnosticCategory(Enum):
    """Categories of diagnostic checks."""

    CONFIGURATION = "configuration"
    PLUGIN = "plugin"
    ENVIRONMENT = "environment"
    PERFORMANCE = "performance"
    CONNECTIVITY = "connectivity"
    FILESYSTEM = "filesystem"


@dataclass
class DiagnosticIssue:
    """Represents a single diagnostic issue."""

    category: DiagnosticCategory
    level: DiagnosticLevel
    message: str
    details: Optional[str] = None
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    fix_suggestion: Optional[str] = None
    auto_fixable: bool = False
    auto_fix_action: Optional[Callable[[], bool]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticResult:
    """Result of running diagnostics."""

    issues: List[DiagnosticIssue] = field(default_factory=list)
    checks_performed: int = 0
    checks_passed: int = 0

    @property
    def checks_failed(self) -> int:
        return self.checks_performed - self.checks_passed

    @property
    def has_errors(self) -> bool:
        return any(
            issue.level in [DiagnosticLevel.ERROR, DiagnosticLevel.CRITICAL]
            for issue in self.issues
        )

    @property
    def has_warnings(self) -> bool:
        return any(issue.level == DiagnosticLevel.WARNING for issue in self.issues)

    def add_issue(self, issue: DiagnosticIssue):
        """Add an issue to the result."""
        self.issues.append(issue)

    def merge(self, other: "DiagnosticResult"):
        """Merge another diagnostic result into this one."""
        self.issues.extend(other.issues)
        self.checks_performed += other.checks_performed
        self.checks_passed += other.checks_passed

    def get_issues_by_level(self, level: DiagnosticLevel) -> List[DiagnosticIssue]:
        """Get all issues of a specific level."""
        return [issue for issue in self.issues if issue.level == level]

    def get_issues_by_category(self, category: DiagnosticCategory) -> List[DiagnosticIssue]:
        """Get all issues of a specific category."""
        return [issue for issue in self.issues if issue.category == category]

    def get_fixable_issues(self) -> List[DiagnosticIssue]:
        """Get all auto-fixable issues."""
        return [issue for issue in self.issues if issue.auto_fixable]


class DiagnosticCheck(ABC):
    """Base class for diagnostic checks."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the diagnostic check."""
        pass

    @property
    @abstractmethod
    def category(self) -> DiagnosticCategory:
        """Category of the diagnostic check."""
        pass

    @property
    def description(self) -> str:
        """Description of what this check does."""
        return ""

    @abstractmethod
    def run(self) -> DiagnosticResult:
        """Run the diagnostic check and return results."""
        pass

    def is_applicable(self) -> bool:
        """Check if this diagnostic is applicable in the current context."""
        return True


class DiagnosticRunner:
    """Runs diagnostic checks and collects results."""

    def __init__(self):
        self.checks: List[DiagnosticCheck] = []

    def register_check(self, check: DiagnosticCheck):
        """Register a diagnostic check."""
        self.checks.append(check)

    def register_checks(self, checks: List[DiagnosticCheck]):
        """Register multiple diagnostic checks."""
        self.checks.extend(checks)

    def run_all(self, categories: Optional[List[DiagnosticCategory]] = None) -> DiagnosticResult:
        """Run all registered diagnostic checks."""
        result = DiagnosticResult()

        for check in self.checks:
            # Skip if category filter is specified and check doesn't match
            if categories and check.category not in categories:
                continue

            # Skip if check is not applicable
            if not check.is_applicable():
                continue

            try:
                check_result = check.run()
                result.merge(check_result)
            except Exception as e:
                # If a check fails, record it as a critical issue
                result.add_issue(
                    DiagnosticIssue(
                        category=check.category,
                        level=DiagnosticLevel.CRITICAL,
                        message=f"Diagnostic check '{check.name}' failed to run",
                        details=str(e),
                        metadata={"check_name": check.name},
                    )
                )
                result.checks_performed += 1

        return result

    def auto_fix_issues(self, result: DiagnosticResult, dry_run: bool = False) -> Dict[str, Any]:
        """Attempt to auto-fix issues that support it."""
        fixed_count = 0
        failed_fixes = []

        for issue in result.get_fixable_issues():
            if issue.auto_fix_action:
                try:
                    if dry_run:
                        # In dry run mode, just count what would be fixed
                        fixed_count += 1
                    else:
                        success = issue.auto_fix_action()
                        if success:
                            fixed_count += 1
                        else:
                            failed_fixes.append(
                                {"issue": issue.message, "reason": "Fix action returned False"}
                            )
                except Exception as e:
                    failed_fixes.append({"issue": issue.message, "reason": str(e)})

        return {"fixed_count": fixed_count, "failed_fixes": failed_fixes, "dry_run": dry_run}


class OutputFormatter(ABC):
    """Base class for diagnostic output formatters."""

    @abstractmethod
    def format(self, result: DiagnosticResult, **kwargs) -> str:
        """Format the diagnostic result for output."""
        pass


class TextFormatter(OutputFormatter):
    """Formats diagnostic results as human-readable text."""

    def format(self, result: DiagnosticResult, verbose: bool = False) -> str:
        """Format result as text."""
        lines = []

        # Header
        lines.append("test Diagnostics Report")
        lines.append("=" * 50)
        lines.append("")

        # Summary
        lines.append("Summary:")
        lines.append(f"  Checks performed: {result.checks_performed}")
        lines.append(f"  Checks passed: {result.checks_passed}")
        lines.append(f"  Checks failed: {result.checks_failed}")
        lines.append("")

        # Issues by level
        for level in DiagnosticLevel:
            issues = result.get_issues_by_level(level)
            if issues:
                lines.append(f"{level.value.upper()} ({len(issues)}):")
                for issue in issues:
                    lines.append(f"  [{issue.category.value}] {issue.message}")
                    if verbose and issue.details:
                        lines.append(f"    Details: {issue.details}")
                    if issue.file_path:
                        location = str(issue.file_path)
                        if issue.line_number:
                            location += f":{issue.line_number}"
                            if issue.column_number:
                                location += f":{issue.column_number}"
                        lines.append(f"    Location: {location}")
                    if issue.fix_suggestion:
                        lines.append(f"    Fix: {issue.fix_suggestion}")
                    if issue.auto_fixable:
                        lines.append("    Auto-fixable: Yes")
                lines.append("")

        # Auto-fixable issues summary
        fixable = result.get_fixable_issues()
        if fixable:
            lines.append(f"Auto-fixable issues: {len(fixable)}")
            lines.append("Run with --auto-fix to attempt automatic fixes")
            lines.append("")

        return "\n".join(lines)


class JsonFormatter(OutputFormatter):
    """Formats diagnostic results as JSON."""

    def format(self, result: DiagnosticResult, pretty: bool = True) -> str:
        """Format result as JSON."""
        data = {
            "summary": {
                "checks_performed": result.checks_performed,
                "checks_passed": result.checks_passed,
                "checks_failed": result.checks_failed,
                "has_errors": result.has_errors,
                "has_warnings": result.has_warnings,
            },
            "issues": [
                {
                    "category": issue.category.value,
                    "level": issue.level.value,
                    "message": issue.message,
                    "details": issue.details,
                    "file_path": str(issue.file_path) if issue.file_path else None,
                    "line_number": issue.line_number,
                    "column_number": issue.column_number,
                    "fix_suggestion": issue.fix_suggestion,
                    "auto_fixable": issue.auto_fixable,
                    "metadata": issue.metadata,
                }
                for issue in result.issues
            ],
        }

        if pretty:
            return json.dumps(data, indent=2)
        else:
            return json.dumps(data)


class MarkdownFormatter(OutputFormatter):
    """Formats diagnostic results as Markdown."""

    def format(self, result: DiagnosticResult, **kwargs) -> str:
        """Format result as Markdown."""
        lines = []

        # Header
        lines.append("# test Diagnostics Report")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Checks performed:** {result.checks_performed}")
        lines.append(f"- **Checks passed:** {result.checks_passed}")
        lines.append(f"- **Checks failed:** {result.checks_failed}")
        lines.append("")

        # Issues by level
        for level in DiagnosticLevel:
            issues = result.get_issues_by_level(level)
            if issues:
                emoji = {
                    DiagnosticLevel.INFO: "ℹ️",
                    DiagnosticLevel.WARNING: "⚠️",
                    DiagnosticLevel.ERROR: "❌",
                    DiagnosticLevel.CRITICAL: "🚨",
                }.get(level, "")

                lines.append(f"## {emoji} {level.value.title()} Issues ({len(issues)})")
                lines.append("")

                for issue in issues:
                    lines.append(f"### [{issue.category.value}] {issue.message}")
                    lines.append("")

                    if issue.details:
                        lines.append(f"**Details:** {issue.details}")
                        lines.append("")

                    if issue.file_path:
                        location = f"`{issue.file_path}`"
                        if issue.line_number:
                            location += f" (line {issue.line_number}"
                            if issue.column_number:
                                location += f", column {issue.column_number}"
                            location += ")"
                        lines.append(f"**Location:** {location}")
                        lines.append("")

                    if issue.fix_suggestion:
                        lines.append(f"**Suggested Fix:** {issue.fix_suggestion}")
                        lines.append("")

                    if issue.auto_fixable:
                        lines.append("**Auto-fixable:** ✅ Yes")
                        lines.append("")

        # Auto-fixable issues
        fixable = result.get_fixable_issues()
        if fixable:
            lines.append("## 🔧 Auto-fixable Issues")
            lines.append("")
            lines.append(f"Found {len(fixable)} issues that can be automatically fixed.")
            lines.append("Run with `--auto-fix` to attempt automatic fixes.")
            lines.append("")

        return "\n".join(lines)


def get_formatter(format_type: str) -> OutputFormatter:
    """Get the appropriate formatter for the given format type."""
    formatters = {
        "text": TextFormatter(),
        "json": JsonFormatter(),
        "markdown": MarkdownFormatter(),
        "md": MarkdownFormatter(),  # Alias
    }

    formatter = formatters.get(format_type.lower())
    if not formatter:
        raise ValueError(f"Unknown format type: {format_type}")

    return formatter
