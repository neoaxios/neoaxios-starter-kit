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

"""Configuration loaders and registry integration for secure_cache.

Provides functions to register, load, and manage secure_cache configuration
using the secure_config registry.

Example:
    ```python
    from neoaxios_secure_cache.config import register_cache_config, get_cache_config

    # Register configuration at app startup
    register_cache_config("/etc/myapp/cache.json")

    # Access configuration anywhere in the app
    config = get_cache_config()

    # Reload configuration (e.g., for secret rotation)
    from neoaxios_secure_cache.config import reload_cache_config
    result = reload_cache_config(drift_policy="warn")
    if result.drifted_fields:
        logger.warning("config_drift_detected", drifted_fields=result.drifted_fields)
    ```
"""

from pathlib import Path
from typing import Optional, Union

from neoaxios_secure_config import (
    ReloadResult,
    get_config,
    get_config_or_none,
    has_previous_config,
    register_config,
    reload_config,
    rollback_config,
)
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_cache.config.schemas import SecureCacheConfig

logger = get_telemetry(__name__)

# Component name for registry
COMPONENT_NAME = "secure_cache"

# Allowed directories for file:// resolution of master_key
ALLOWED_SECRET_DIRS = [
    "/run/secrets",
    "/etc/secrets",
    "/var/secrets",
]


@auto_trace(logger)
def register_cache_config(
    config_path: Union[str, Path],
    *,
    allowed_secret_dirs: Optional[list[str]] = None,
) -> SecureCacheConfig:
    """Register secure_cache configuration from a JSON file.

    Loads and validates configuration, then registers it in the global registry.
    The configuration becomes accessible via get_cache_config().

    Args:
        config_path: Path to JSON configuration file
        allowed_secret_dirs: Additional directories allowed for file:// resolution

    Returns:
        The loaded and validated SecureCacheConfig

    Raises:
        ConfigNotFoundError: If config file doesn't exist
        ConfigValidationError: If validation fails
        ConfigResolutionError: If env:/file:// resolution fails
        ComponentExistsError: If configuration already registered

    Example:
        ```python
        config = register_cache_config("/etc/myapp/cache.json")
        logger.info("cache_config_registered", tenant_id=config.tenant_id)
        ```
    """
    # Merge allowed directories
    dirs = list(ALLOWED_SECRET_DIRS)
    if allowed_secret_dirs:
        dirs.extend(allowed_secret_dirs)

    # Register with the global registry
    config = register_config(
        component_name=COMPONENT_NAME,
        config_path=Path(config_path),
        schema=SecureCacheConfig,
        allowed_base_dirs=dirs,
    )

    logger.info(
        "Registered secure_cache configuration",
        tenant_id=config.tenant_id,
        has_redis=config.redis is not None,
        features=config.features.model_dump() if config.features else None,
    )

    return config


@auto_trace(logger)
def get_cache_config() -> SecureCacheConfig:
    """Get the registered secure_cache configuration.

    Returns:
        The registered SecureCacheConfig

    Raises:
        ComponentNotFoundError: If configuration not registered

    Example:
        ```python
        config = get_cache_config()
        cache = create_secure_cache(config)
        ```
    """
    return get_config(COMPONENT_NAME)


@auto_trace(logger)
def get_cache_config_or_none() -> Optional[SecureCacheConfig]:
    """Get the registered secure_cache configuration, or None if not registered.

    Returns:
        The registered SecureCacheConfig, or None

    Example:
        ```python
        config = get_cache_config_or_none()
        if config is None:
            # Register default configuration
            config = register_cache_config("/etc/myapp/cache.json")
        ```
    """
    return get_config_or_none(COMPONENT_NAME)


@auto_trace(logger)
def reload_cache_config(
    *,
    drift_policy: str = "block",
) -> ReloadResult:
    """Reload secure_cache configuration from disk.

    Use this for secret rotation or configuration updates. Supports drift
    detection to prevent unintended changes to static fields.

    Args:
        drift_policy: How to handle changes to static fields:
            - "block": Raise ConfigDriftError if static fields changed
            - "warn": Log warning but allow changes
            - "allow": Silently allow all changes

    Returns:
        ReloadResult with reload details and any drifted fields

    Raises:
        ComponentNotFoundError: If configuration not registered
        ConfigDriftError: If drift_policy="block" and static fields changed

    Example:
        ```python
        # Reload with drift detection
        result = reload_cache_config(drift_policy="warn")
        if result.drifted_fields:
            logger.warning(f"Config drift detected: {result.drifted_fields}")
        ```
    """
    result = reload_config(COMPONENT_NAME, drift_policy=drift_policy)

    logger.info(
        "Reloaded secure_cache configuration",
        drifted_fields=result.drifted_fields,
        refreshed_fields=result.refreshed_fields,
    )

    return result


@auto_trace(logger)
def rollback_cache_config() -> SecureCacheConfig:
    """Rollback to the previous secure_cache configuration.

    Restores the configuration that was active before the last reload.
    Useful for recovering from bad configuration changes.

    Returns:
        The restored SecureCacheConfig

    Raises:
        ComponentNotFoundError: If configuration not registered
        NoPreviousConfigError: If no previous configuration exists

    Example:
        ```python
        try:
            reload_cache_config()
        except Exception:
            # Rollback on failure
            config = rollback_cache_config()
            logger.info(f"Rolled back to previous config")
        ```
    """
    config = rollback_config(COMPONENT_NAME)

    logger.info(
        "Rolled back secure_cache configuration",
        tenant_id=config.tenant_id,
    )

    return config


@auto_trace(logger)
def has_cache_config_rollback() -> bool:
    """Check if a previous configuration exists for rollback.

    Returns:
        True if rollback_cache_config() can be called

    Example:
        ```python
        if has_cache_config_rollback():
            config = rollback_cache_config()
        else:
            logger.warning("No previous config to rollback to")
        ```
    """
    return has_previous_config(COMPONENT_NAME)
