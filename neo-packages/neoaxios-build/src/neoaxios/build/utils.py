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

"""Utility functions for the build system."""

import re
from pathlib import Path
from typing import List, Optional, Tuple, TYPE_CHECKING

from neoaxios.build.ui.build_display import _visual_width, _pad_to_width

if TYPE_CHECKING:
    from neoaxios.build.models import BuildResult


def detect_operations(stdout: str) -> List[str]:
    """Parse build output to detect operations performed.

    Detects the following operations from build script output:
    - "wheel": Wheel package built
    - "contracts-publish": Contracts published
    - "contracts-validate": Contracts validated
    - "types-generate": Types generated

    Args:
        stdout: Standard output from build script

    Returns:
        List of operation names detected
    """
    operations = []

    # Detect wheel build
    if "✅ Wheel built" in stdout or "Successfully built" in stdout:
        operations.append("wheel")

    # Detect contract operations
    if "✅ Contracts published" in stdout or "📝 Publishing contracts" in stdout:
        operations.append("contracts-publish")

    if "✅ Contracts validated" in stdout or "✓ Contracts validated" in stdout:
        operations.append("contracts-validate")

    # Detect type generation
    if "✅ Types generated" in stdout or "✓ Types generated" in stdout:
        operations.append("types-generate")

    return operations


def extract_error_message(stderr: str, stdout: str) -> Optional[str]:
    """Extract first meaningful error message from build output.

    Args:
        stderr: Standard error output
        stdout: Standard output

    Returns:
        First error line or None if no error found
    """
    # Combine stderr and stdout
    combined = stderr + "\n" + stdout

    # Error patterns to look for (in priority order)
    error_patterns = [
        # Custom contract errors
        r"(❌ Error:[^\n]+(?:\n[^\n]+)?)",  # Multi-line contract errors
        # Python exceptions
        r"(ModuleNotFoundError:[^\n]+)",
        r"(ImportError:[^\n]+)",
        r"(FileNotFoundError:[^\n]+)",
        r"(SyntaxError:[^\n]+)",
        r"(TypeError:[^\n]+)",
        r"(ValueError:[^\n]+)",
        r"(AttributeError:[^\n]+)",
        r"(KeyError:[^\n]+)",
        # Build errors
        r"(make\[\d+\]:[^\n]+)",
        r"(ERROR:[^\n]+)",
        r"(error:[^\n]+)",
        r"(FAILED:[^\n]+)",
        # Generic errors
        r"(❌[^\n]+)",
    ]

    for pattern in error_patterns:
        match = re.search(pattern, combined, re.IGNORECASE)
        if match:
            error = match.group(1).strip()
            # Truncate to 200 chars to prevent overflow
            return error[:200]

    # Fallback: first non-empty line from stderr
    for line in stderr.splitlines():
        line = line.strip()
        if line and not line.startswith(("warning:", "Warning:", "note:", "Note:")):
            return line[:200]  # Truncate long lines

    return None


def generate_error_hint(error_message: Optional[str], failure_stage: Optional[str]) -> Optional[str]:
    """Generate actionable hint based on error pattern.

    Args:
        error_message: Error message from build
        failure_stage: Stage where build failed

    Returns:
        Actionable hint or None
    """
    if not error_message:
        return None

    error_lower = error_message.lower()

    # Module/import errors
    if "modulenotfounderror" in error_lower or "importerror" in error_lower:
        # Extract module name
        match = re.search(r"['\"]([^'\"]+)['\"]", error_message)
        if match:
            module = match.group(1)
            # Convert import path to package name
            package = module.split('.')[0].replace('_', '-')
            return f"pip install {package}"
        return "Check dependencies in pyproject.toml"

    # Make target missing or make errors in general
    if "no rule to make target" in error_lower:
        match = re.search(r"target ['\"]([^'\"]+)['\"]", error_message, re.IGNORECASE)
        if match:
            target = match.group(1)
            if failure_stage == "contract-validate":
                return f"Add 'validate' target to Makefile or remove contracts.yaml"
            elif failure_stage == "types-generate":
                return f"Add 'generate' target to Makefile"
            elif failure_stage == "contract-publish":
                return f"Add 'publish' target to Makefile or remove contracts/manifest.yaml"
            return f"Add '{target}' target to Makefile"
        return "Check Makefile for missing targets"

    # Generic make errors
    if "make[" in error_lower and "error" in error_lower:
        if failure_stage == "types-generate":
            return "Add 'generate' target to Makefile or fix type generation script"
        return "Check Makefile targets and build scripts"

    # File not found
    if "filenotfounderror" in error_lower or "no such file" in error_lower:
        if "contracts.yaml" in error_lower:
            return "Create contracts.yaml or update package configuration"
        if "manifest.yaml" in error_lower:
            return "Create contracts/manifest.yaml or update package configuration"
        return "Check file paths in build configuration"

    # Syntax errors
    if "syntaxerror" in error_lower:
        return "Fix syntax error in Python code (check log for line number)"

    # Type errors
    if "typeerror" in error_lower:
        return "Fix type mismatch (check log for details)"

    # Timeout
    if "timeout" in error_lower:
        return "Increase timeout with MAX_WORKERS=N or optimize build"

    # Permission errors
    if "permission denied" in error_lower:
        return "Check file permissions or run with appropriate access"

    # Build tool errors
    if "failed building wheel" in error_lower:
        return "Check pyproject.toml configuration and dependencies"

    # Contract-specific errors
    if "consumer, not a provider" in error_lower or "consumers cannot publish" in error_lower:
        return "Remove contracts/manifest.yaml (this package consumes contracts, doesn't publish)"

    if "provider, not a consumer" in error_lower or "providers cannot validate" in error_lower:
        return "Remove contracts.yaml (this package publishes contracts, doesn't consume)"

    return None


def format_contract_operation(operations: List[str]) -> str:
    """Format contract operation for summary table.

    Args:
        operations: List of operations performed

    Returns:
        Formatted string for table display:
        - "PUB": Contracts published
        - "VAL": Contracts validated
        - "P+V": Both published and validated
        - "-": No contract operations
    """
    has_publish = "contracts-publish" in operations
    has_validate = "contracts-validate" in operations

    if has_publish and has_validate:
        return "P+V"
    elif has_publish:
        return "PUB"
    elif has_validate:
        return "VAL"
    else:
        return "-"


def generate_summary_table(results: List["BuildResult"], dist_dir: Optional[Path] = None) -> str:
    """Generate wheel-build summary table.

    Layout and vocabulary intentionally match the docker-images tables
    rendered by ``BuildDisplay.docker_summary_table`` /
    ``docker_pull_summary_table`` — same ``♻️ hit`` / ``🔨 new`` /
    ``✗ fail`` status labels, same ``Built: N  Cached: N  Failed: N
    │  <dir>`` summary footer — so a reader scanning a ``make build``
    run sees one consistent visual grammar across all three tables
    (wheels, 1st-party images, 3rd-party images).

    Args:
        results: List of build results.
        dist_dir: Optional dist directory path for the summary footer.

    Returns:
        Formatted table string with Unicode box drawing.
    """
    lines = []

    # ANSI color codes
    GREEN = "\033[32m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    RESET = "\033[0m"

    # Section title — matches "Docker Images" / "Third-Party Docker Images"
    lines.append("")
    lines.append("Wheels")
    # Widths: Package=32 │ Status=8 (fits "♻️ hit" visual-6 + pad) │ Wheel=7 │ Contract=10 │ Types=7 │ Time=7
    lines.append("┌" + "─" * 32 + "┬" + "─" * 8 + "┬" + "─" * 7 + "┬" + "─" * 10 + "┬" + "─" * 7 + "┬" + "─" * 7 + "┐")
    lines.append("│ {:30} │ {:6} │ {:5} │ {:8} │ {:5} │ {:5} │".format(
        "Package", "Status", "Wheel", "Contract", "Types", "Time"
    ))
    lines.append("├" + "─" * 32 + "┼" + "─" * 8 + "┼" + "─" * 7 + "┼" + "─" * 10 + "┼" + "─" * 7 + "┼" + "─" * 7 + "┤")

    # Sort by display name (actual package name from pyproject.toml), case-insensitive
    sorted_results = sorted(results, key=lambda r: r.package.display_name.lower())

    for result in sorted_results:
        # Single "Status" column (was previously "Cache" column).  Same
        # vocabulary as the docker tables: ``♻️ hit`` / ``🔨 new`` /
        # ``✗ fail`` — a reader who has learned it on one table recognises
        # it on the others.
        if not result.success:
            status_raw = "✗ fail"
            status = _pad_to_width(f"{RED}{status_raw}{RESET}", 6 + len(RED) + len(RESET))
        elif "cache-hit" in result.operations:
            status_raw = "♻️ hit"
            status = _pad_to_width(f"{CYAN}{status_raw}{RESET}", 6 + len(CYAN) + len(RESET))
        else:
            status = _pad_to_width("🔨 new", 6)

        # Determine status for each column based on failure stage
        if result.success:
            wheel = "✓" if "wheel" in result.operations else "-"
            contract = format_contract_operation(result.operations)
            types = "✓" if "types-generate" in result.operations else "-"
            color = GREEN
        else:
            # Show exactly where failure occurred
            if result.failure_stage == "wheel":
                wheel = f"{RED}✗{RESET}"
                contract = "-"
                types = "-"
            elif result.failure_stage in ("contract-validate", "contract-publish"):
                wheel = "✓"
                contract = f"{RED}✗{RESET}"
                types = "-"
            elif result.failure_stage == "types-generate":
                wheel = "✓"
                contract = format_contract_operation(result.operations)
                types = f"{RED}✗{RESET}"
            else:
                # Timeout or unexpected error
                wheel = f"{RED}✗{RESET}"
                contract = "-"
                types = "-"
            color = RED

        time = f"{result.duration:.1f}s"

        # Row — display_name (pyproject [project].name) not folder name,
        # matching the docker tables and the progress-line naming.
        pkg_name = result.package.display_name[:30].ljust(30)
        contract_padded = f"{contract:4}" if isinstance(contract, str) else contract
        lines.append(
            f"│ {color}{pkg_name}{RESET} │ {status} │  {wheel}    │  {contract_padded}    │  {types}    │ {time:5} │"
        )

    lines.append("└" + "─" * 32 + "┴" + "─" * 8 + "┴" + "─" * 7 + "┴" + "─" * 10 + "┴" + "─" * 7 + "┴" + "─" * 7 + "┘")

    # Summary footer — matches the docker tables' ``Built: N  Cached: N
    # Failed: N  │  <dir>`` line so the three tables read identically.
    cached = sum(1 for r in results if "cache-hit" in r.operations)
    failed = sum(1 for r in results if not r.success)
    built = len(results) - cached - failed
    footer = f"  Built: {built}  Cached: {cached}  Failed: {failed}"
    if dist_dir is not None:
        footer += f"  │  {dist_dir}"
    lines.append(footer)

    return "\n".join(lines)
