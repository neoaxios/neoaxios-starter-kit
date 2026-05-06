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
Repository root detection utility.

This module provides functionality to find the repository root from any
subdirectory by traversing upward and looking for repository markers.

Supports build-from-anywhere via central configurations. Fails explicitly
if not in a repository — no fallback logic.
"""

from pathlib import Path
from typing import Optional

from neoaxios.build._telemetry import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@auto_trace(logger)
def find_repo_root(start_path: Optional[Path] = None) -> Optional[Path]:
    """
    Traverse up from start_path to find repository root.

    Repository root is identified by presence of ALL markers:
    - .git (version control root — file in worktrees, directory otherwise)
    - Makefile with build targets
    - build.yaml (build configuration)

    Args:
        start_path: Starting directory (defaults to cwd)

    Returns:
        Path to repository root, or None if not found

    Examples:
        >>> # From anywhere in repo
        >>> root = find_repo_root()
        >>> root / "Makefile"  # Always points to root Makefile

        >>> # From specific path
        >>> root = find_repo_root(Path("/path/to/packages/logging"))
        >>> root == Path("/path/to")  # Found repository root
    """
    current = start_path or Path.cwd()

    # Traverse up to filesystem root
    for path in [current, *current.parents]:
        # Check for repository markers — all three required
        if (
            (path / ".git").exists() and
            (path / "Makefile").is_file() and
            (path / "build.yaml").is_file()
        ):
            logger.info(
                "Found repository root",
                repo_root=str(path),
                start_path=str(current)
            )
            return path

    logger.warning(
        "Repository root not found",
        start_path=str(current)
    )
    return None


@auto_trace(logger)
def ensure_repo_root(start_path: Optional[Path] = None) -> Path:
    """
    Find repository root or raise error if not in a repository.

    This is the strict version that should be used when repository context
    is mandatory for the operation to succeed.

    Args:
        start_path: Starting directory (defaults to cwd)

    Returns:
        Path to repository root

    Raises:
        RuntimeError: If not in a repository

    Examples:
        >>> # Will succeed if in repo
        >>> root = ensure_repo_root()

        >>> # Will raise if not in repo
        >>> root = ensure_repo_root(Path("/tmp"))  # RuntimeError
    """
    root = find_repo_root(start_path)
    if root is None:
        current = start_path or Path.cwd()
        raise RuntimeError(
            f"Not in a NeoAxios repository. "
            f"Current directory: {current}\n"
            f"Repository markers (.git, Makefile, build.yaml) not found in parent directories."
        )
    return root
