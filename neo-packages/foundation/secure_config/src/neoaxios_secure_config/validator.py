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

"""Permission validation for configuration files.

Validates that configuration files have appropriate permissions
to prevent unauthorized access or modification.

Security Note: Uses file descriptor-based operations to eliminate TOCTOU
(Time-of-Check-Time-of-Use) vulnerabilities. Permission checks are performed
on the open file descriptor, ensuring the check and subsequent read operate
on the same file.
"""

import os
import stat
from pathlib import Path

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_config.errors import ConfigNotFoundError, ConfigPermissionError

logger = get_telemetry(__name__)


@auto_trace(logger)
def validate_file_size_fd(fd: int, path: Path, max_size: int, file_type: str) -> None:
    """Validate file does not exceed maximum size using file descriptor.

    This function eliminates TOCTOU vulnerabilities by checking size
    on an already-opened file descriptor.

    Args:
        fd: Open file descriptor
        path: Path for error messages (not used for validation)
        max_size: Maximum allowed size in bytes
        file_type: Type of file for error message (e.g., "config", "secret")

    Raises:
        ConfigPermissionError: If file exceeds max_size
    """
    size = os.fstat(fd).st_size

    logger.debug(
        "Validating file size",
        extra={
            "path": str(path),
            "size": size,
            "max_size": max_size,
            "file_type": file_type,
        },
    )

    if size > max_size:
        raise ConfigPermissionError(
            f"{file_type} file exceeds maximum size: {size:,} bytes > {max_size:,} bytes. "
            f"Path: {path}",
            path=str(path),
        )


@auto_trace(logger)
def validate_config_permissions_fd(fd: int, path: Path, strict: bool = False) -> None:
    """Validate configuration file permissions using file descriptor.

    This function eliminates TOCTOU vulnerabilities by checking permissions
    on an already-opened file descriptor rather than on a path.

    Args:
        fd: Open file descriptor to validate
        path: Path for error messages (not used for validation)
        strict: If True, also reject world-readable files

    Raises:
        ConfigPermissionError: If file has insecure permissions
    """
    mode = os.fstat(fd).st_mode

    # Must not be world-writable
    if mode & stat.S_IWOTH:
        raise ConfigPermissionError(
            f"Config file is world-writable: {path}. "
            f"Run: chmod o-w {path}",
            path=str(path),
        )

    # In strict mode, also reject world-readable
    if strict and (mode & stat.S_IROTH):
        raise ConfigPermissionError(
            f"Config file is world-readable (strict mode): {path}. "
            f"Run: chmod o-r {path}",
            path=str(path),
        )

    # Warning if world-readable (non-strict mode)
    if mode & stat.S_IROTH:
        logger.warning(
            "Config file is world-readable",
            extra={
                "path": str(path),
                "mode": oct(mode),
                "recommended": "0640 or 0600",
            },
        )

    # Warning if group-writable
    if mode & stat.S_IWGRP:
        logger.warning(
            "Config file is group-writable",
            extra={
                "path": str(path),
                "mode": oct(mode),
                "recommended": "0640 or 0600",
            },
        )

    logger.debug(
        "Config file permissions validated",
        extra={"path": str(path), "mode": oct(mode)},
    )


@auto_trace(logger)
def validate_config_permissions(path: Path, strict: bool = False) -> None:
    """Validate configuration file has appropriate permissions.

    This function provides backward compatibility but opens and checks
    the file using file descriptor operations to prevent TOCTOU attacks.

    Args:
        path: Path to configuration file
        strict: If True, also reject world-readable files

    Raises:
        ConfigNotFoundError: If file doesn't exist
        ConfigPermissionError: If file has insecure permissions
    """
    if not path.exists():
        raise ConfigNotFoundError(str(path))

    if not path.is_file():
        raise ConfigPermissionError(
            f"Config path is not a file: {path}",
            path=str(path),
        )

    # Open file with secure flags and validate on the file descriptor
    # This eliminates TOCTOU by checking permissions on the open fd
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            validate_config_permissions_fd(fd, path, strict)
        finally:
            os.close(fd)
    except OSError as e:
        raise ConfigPermissionError(
            f"Failed to open config file for validation: {path}: {e}",
            path=str(path),
        )


@auto_trace(logger)
def validate_path_safety(path: Path) -> None:
    """Validate path doesn't contain unsafe patterns.

    Args:
        path: Path to validate

    Raises:
        ConfigPermissionError: If path contains unsafe patterns
    """
    # Resolve path to absolute, canonical form
    # This handles symlinks, '.', '..', and relative paths
    resolved_path = path.resolve()

    # Check for path traversal by looking at path components
    # Path.parts normalizes the path and gives us components
    try:
        parts = Path(path).parts
        if ".." in parts:
            raise ConfigPermissionError(
                f"Path contains traversal pattern '..': {path}",
                path=str(path),
            )
    except (ValueError, OSError) as e:
        raise ConfigPermissionError(
            f"Invalid path: {path} ({e})",
            path=str(path),
        )

    # Check for symlink (could point anywhere)
    if path.exists() and path.is_symlink():
        logger.warning(
            "Config file is a symlink",
            extra={
                "path": str(path),
                "target": str(resolved_path),
            },
        )

    logger.debug(
        "Path safety validated",
        extra={
            "original": str(path),
            "resolved": str(resolved_path),
        },
    )
