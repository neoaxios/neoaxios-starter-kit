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

"""Thread-safe component registry for secure configurations.

Provides singleton registry for managing multiple independent
configurations within the same process.

Supports drift detection during reload to catch unexpected changes
to static fields (like tenant_id) while allowing refreshable fields
(like client_secret) to change.
"""

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Optional, Tuple, Type, TypeVar

from pydantic import SecretStr
from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_secure_config.errors import (
    ComponentExistsError,
    ComponentNotFoundError,
    ConfigDriftError,
    NoPreviousConfigError,
)
from neoaxios_secure_config.loader import load_secure_config_with_env
from neoaxios_secure_config.schema import ExtractedEnvVars, SecureSchema

logger = get_telemetry(__name__)

T = TypeVar("T", bound=SecureSchema)

# Type alias for loader callback functions
# Loader returns a tuple of (config instance, extracted env vars)
LoaderCallback = Callable[[], Tuple[SecureSchema, ExtractedEnvVars]]


@dataclass(frozen=True)
class ConfigInfo:
    """Metadata about a component's configuration.

    Attributes:
        component: Component name
        schema_name: Name of the schema class
        schema_class: The actual schema class
        path: Path to the config file (may be None for loader-based configs)
        fields: List of schema field names
        secret_fields: List of schema fields marked as SecretStr
        refreshable_fields: List of fields marked as refreshable
        static_fields: List of fields that are static (not refreshable)
        extracted_env_vars: Container for env vars declared in extract_env_vars
        extracted_env_var_names: List of env var names (uppercase, as declared)
        loader: Optional loader callback for non-file-based configs
    """

    component: str
    schema_name: str
    schema_class: Type[SecureSchema]
    path: Optional[str]
    fields: list[str]
    secret_fields: list[str]
    refreshable_fields: list[str]
    static_fields: list[str]
    extracted_env_vars: ExtractedEnvVars
    extracted_env_var_names: list[str]
    loader: Optional[LoaderCallback] = None


@dataclass(frozen=True)
class ReloadResult:
    """Result of a configuration reload operation.

    Contains the new configuration along with drift detection results.
    Use this to understand what changed during reload.

    Attributes:
        config: The new configuration instance
        previous_config: The configuration before reload
        drift_detected: Dict mapping field names to (old_value, new_value) tuples
                       for static fields that changed (masked for SecretStr)
        refreshed_fields: List of refreshable fields that changed
        policy_applied: The drift policy that was applied
    """

    config: SecureSchema
    previous_config: SecureSchema
    drift_detected: dict[str, tuple[str, str]] = field(default_factory=dict)
    refreshed_fields: list[str] = field(default_factory=list)
    policy_applied: Literal["block", "warn", "allow"] = "block"

    @property
    def has_drift(self) -> bool:
        """Return True if any static fields changed."""
        return len(self.drift_detected) > 0

    @property
    def has_refreshed(self) -> bool:
        """Return True if any refreshable fields changed."""
        return len(self.refreshed_fields) > 0


class SecureConfigRegistry:
    """Thread-safe singleton registry for secure configurations.

    Supports multiple independent configurations within the same process,
    each identified by a unique component name.
    """

    _instance: Optional["SecureConfigRegistry"] = None
    _init_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "SecureConfigRegistry":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._configs: dict[str, SecureSchema] = {}
                    instance._metadata: dict[str, ConfigInfo] = {}
                    instance._previous: dict[str, SecureSchema] = {}
                    instance._lock = threading.RLock()
                    cls._instance = instance
        return cls._instance

    @staticmethod
    def _get_comparable_value(value: Any) -> str:  # notrace: static method handling secret values, no logger context available
        """Get a comparable string representation of a value.

        For SecretStr, returns the actual secret value for comparison.
        For other types, returns str representation.
        """
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return str(value)

    @staticmethod
    def _get_display_value(value: Any) -> str:  # notrace: lightweight static method called frequently during drift detection
        """Get a display-safe string representation of a value.

        For SecretStr, returns masked value.
        For other types, returns str representation.
        """
        if isinstance(value, SecretStr):
            return "***MASKED***"
        return str(value)

    @auto_trace(logger)
    def register(
        self,
        component: str,
        path: Path,
        schema: Type[T],
        strict_permissions: bool = False,
    ) -> T:
        """Register configuration for a named component.

        Each component maintains its own isolated configuration within the
        process. Use a unique component name to identify each configuration.

        The config file may include an `extract_env_vars` section to declare
        environment variables that should be extracted and made available
        via get_config_info().extracted_env_vars.

        Args:
            component: Unique identifier for this component (e.g., "auth", "database")
            path: Path to JSON configuration file
            schema: Pydantic schema class to validate against
            strict_permissions: If True, reject world-readable files

        Returns:
            Validated configuration instance

        Raises:
            ComponentExistsError: If a component with this name is already registered
            ConfigNotFoundError: If file doesn't exist
            ConfigPermissionError: If file has insecure permissions
            ConfigParseError: If JSON parsing fails
            ConfigResolutionError: If value resolution fails or required env vars missing
            ConfigValidationError: If schema validation fails
        """
        with self._lock:
            if component in self._configs:
                raise ComponentExistsError(component)

            logger.info(
                "Registering secure config",
                extra={
                    "component": component,
                    "path": str(path),
                    "schema": schema.__name__,
                },
            )

            loaded = load_secure_config_with_env(
                path=path,
                schema=schema,
                component=component,
                strict_permissions=strict_permissions,
            )

            self._configs[component] = loaded.config
            self._metadata[component] = ConfigInfo(
                component=component,
                schema_name=schema.__name__,
                schema_class=schema,
                path=str(path),
                fields=list(schema.model_fields.keys()),
                secret_fields=schema.get_secret_fields(),
                refreshable_fields=schema.get_refreshable_fields(),
                static_fields=schema.get_static_fields(),
                extracted_env_vars=loaded.extracted_env_vars,
                extracted_env_var_names=loaded.extracted_env_vars.keys(),
            )

            logger.info(
                "Secure config registered",
                extra={
                    "component": component,
                    "fields": list(schema.model_fields.keys()),
                    "secret_fields": schema.get_secret_fields(),
                    "refreshable_fields": schema.get_refreshable_fields(),
                    "static_fields": schema.get_static_fields(),
                    "extracted_env_var_count": len(loaded.extracted_env_vars),
                    "extracted_env_var_names": loaded.extracted_env_vars.keys(),
                },
            )

            return loaded.config

    @auto_trace(logger)
    def register_with_loader(
        self,
        component: str,
        schema: Type[T],
        loader: Callable[[], Tuple[T, ExtractedEnvVars]],
    ) -> T:
        """Register configuration using a custom loader callback.

        Use this for configurations that don't come from files, such as
        environment variable-based configurations. The loader callback
        is stored and used for reload operations.

        Args:
            component: Unique identifier for this component
            schema: Pydantic schema class to validate against
            loader: Callback that loads and returns (config, extracted_env_vars)

        Returns:
            Validated configuration instance

        Raises:
            ComponentExistsError: If a component with this name is already registered
            ConfigResolutionError: If loader fails
            ConfigValidationError: If schema validation fails

        Example:
            ```python
            def load_auth_from_env() -> Tuple[AuthConfig, ExtractedEnvVars]:
                env_vars = extract_env_vars({"TENANT_ID": None, "SECRET": None})
                config = AuthConfig(
                    tenant_id=env_vars.tenant_id.get_secret_value(),
                    secret=env_vars.secret,
                )
                return config, env_vars

            register_config_with_loader("auth", AuthConfig, load_auth_from_env)
            ```
        """
        with self._lock:
            if component in self._configs:
                raise ComponentExistsError(component)

            logger.info(
                "Registering secure config with loader",
                extra={
                    "component": component,
                    "schema": schema.__name__,
                    "loader": loader.__name__ if hasattr(loader, "__name__") else str(loader),
                },
            )

            # Call the loader to get config and env vars
            config, extracted_env_vars = loader()

            self._configs[component] = config
            self._metadata[component] = ConfigInfo(
                component=component,
                schema_name=schema.__name__,
                schema_class=schema,
                path=None,  # No file path for loader-based configs
                fields=list(schema.model_fields.keys()),
                secret_fields=schema.get_secret_fields(),
                refreshable_fields=schema.get_refreshable_fields(),
                static_fields=schema.get_static_fields(),
                extracted_env_vars=extracted_env_vars,
                extracted_env_var_names=extracted_env_vars.keys(),
                loader=loader,  # Store loader for reload
            )

            logger.info(
                "Secure config registered with loader",
                extra={
                    "component": component,
                    "fields": list(schema.model_fields.keys()),
                    "secret_fields": schema.get_secret_fields(),
                    "refreshable_fields": schema.get_refreshable_fields(),
                    "static_fields": schema.get_static_fields(),
                    "extracted_env_var_count": len(extracted_env_vars),
                    "extracted_env_var_names": extracted_env_vars.keys(),
                },
            )

            return config

    @auto_trace(logger)
    def reload_config(
        self,
        component: str,
        path: Optional[Path] = None,
        strict_permissions: bool = False,
        drift_policy: Literal["block", "warn", "allow"] = "block",
    ) -> ReloadResult:
        """Reload configuration for an existing component with drift detection.

        Atomically replaces the configuration with a freshly loaded version.
        Uses the same schema as the original registration.

        Drift Detection:
            Compares old and new configurations to detect changes.
            - Static fields (not marked refreshable): trigger drift detection
            - Refreshable fields: allowed to change without triggering drift

            Mark fields as refreshable in your schema:
                client_secret: SecretStr = Field(
                    description="Client secret",
                    json_schema_extra={"refreshable": True}
                )

        Args:
            component: Name of the component to reload
            path: Optional new path. If None, uses original path.
            strict_permissions: If True, reject world-readable files
            drift_policy: How to handle drift in static fields:
                - "block": Raise ConfigDriftError (default, most secure)
                - "warn": Log warning but allow reload
                - "allow": Silently allow all changes

        Returns:
            ReloadResult containing:
                - config: The new configuration
                - previous_config: The configuration before reload
                - drift_detected: Dict of static fields that changed
                - refreshed_fields: List of refreshable fields that changed
                - policy_applied: The drift policy that was used

        Raises:
            ComponentNotFoundError: If component is not registered
            ConfigDriftError: If drift_policy="block" and static field changed
            ConfigNotFoundError: If file doesn't exist
            ConfigPermissionError: If file has insecure permissions
            ConfigParseError: If JSON parsing fails
            ConfigResolutionError: If value resolution fails or required env vars missing
            ConfigValidationError: If schema validation fails

        Thread Safety:
            This operation is atomic. Other threads will see either the old
            or new configuration, never a partial state.
        """
        with self._lock:
            if component not in self._configs:
                raise ComponentNotFoundError(
                    component=component,
                    available=list(self._configs.keys()),
                )

            # Get current config and metadata
            current_config = self._configs[component]
            metadata = self._metadata[component]
            schema = metadata.schema_class

            # Load new configuration - use loader if available, otherwise file
            if metadata.loader is not None:
                # Loader-based reload
                logger.info(
                    "Reloading secure config with loader",
                    extra={
                        "component": component,
                        "schema": schema.__name__,
                        "drift_policy": drift_policy,
                        "loader": metadata.loader.__name__ if hasattr(metadata.loader, "__name__") else str(metadata.loader),
                    },
                )
                new_config, extracted_env_vars = metadata.loader()
            else:
                # File-based reload
                reload_path = path if path is not None else Path(metadata.path)
                logger.info(
                    "Reloading secure config from file",
                    extra={
                        "component": component,
                        "path": str(reload_path),
                        "schema": schema.__name__,
                        "drift_policy": drift_policy,
                    },
                )
                loaded = load_secure_config_with_env(
                    path=reload_path,
                    schema=schema,
                    component=component,
                    strict_permissions=strict_permissions,
                )
                new_config = loaded.config
                extracted_env_vars = loaded.extracted_env_vars

            # Perform drift detection
            drift_detected: dict[str, tuple[str, str]] = {}
            refreshed_fields: list[str] = []

            # Check static fields for drift
            for field_name in schema.get_static_fields():
                old_value = getattr(current_config, field_name)
                new_value = getattr(new_config, field_name)

                old_comparable = self._get_comparable_value(old_value)
                new_comparable = self._get_comparable_value(new_value)

                if old_comparable != new_comparable:
                    old_display = self._get_display_value(old_value)
                    new_display = self._get_display_value(new_value)
                    drift_detected[field_name] = (old_display, new_display)

            # Check refreshable fields for changes
            for field_name in schema.get_refreshable_fields():
                old_value = getattr(current_config, field_name)
                new_value = getattr(new_config, field_name)

                old_comparable = self._get_comparable_value(old_value)
                new_comparable = self._get_comparable_value(new_value)

                if old_comparable != new_comparable:
                    refreshed_fields.append(field_name)

            # Apply drift policy
            if drift_detected:
                if drift_policy == "block":
                    # Raise error for first drift detected
                    first_field = next(iter(drift_detected))
                    old_val, new_val = drift_detected[first_field]
                    raise ConfigDriftError(
                        component=component,
                        field=first_field,
                        old_value=old_val,
                        new_value=new_val,
                    )
                elif drift_policy == "warn":
                    for field_name, (old_val, new_val) in drift_detected.items():
                        logger.warning(
                            "Configuration drift detected",
                            extra={
                                "component": component,
                                "field": field_name,
                                "old_value": old_val,
                                "new_value": new_val,
                                "policy": "warn",
                            },
                        )

            # Store previous config for rollback (before swap)
            self._previous[component] = current_config

            # Atomically replace configuration
            self._configs[component] = new_config

            # Update metadata (always, to capture new extracted env vars)
            # Preserve loader and path from original metadata
            new_path = str(reload_path) if metadata.loader is None else metadata.path
            self._metadata[component] = ConfigInfo(
                component=component,
                schema_name=schema.__name__,
                schema_class=schema,
                path=new_path,
                fields=list(schema.model_fields.keys()),
                secret_fields=schema.get_secret_fields(),
                refreshable_fields=schema.get_refreshable_fields(),
                static_fields=schema.get_static_fields(),
                extracted_env_vars=extracted_env_vars,
                extracted_env_var_names=extracted_env_vars.keys(),
                loader=metadata.loader,  # Preserve loader for future reloads
            )

            logger.info(
                "Secure config reloaded",
                extra={
                    "component": component,
                    "fields": list(schema.model_fields.keys()),
                    "secret_fields": schema.get_secret_fields(),
                    "refreshable_fields": schema.get_refreshable_fields(),
                    "drift_detected_count": len(drift_detected),
                    "refreshed_field_count": len(refreshed_fields),
                    "policy_applied": drift_policy,
                    "extracted_env_var_count": len(extracted_env_vars),
                    "extracted_env_var_names": extracted_env_vars.keys(),
                    "loader_based": metadata.loader is not None,
                },
            )

            return ReloadResult(
                config=new_config,
                previous_config=current_config,
                drift_detected=drift_detected,
                refreshed_fields=refreshed_fields,
                policy_applied=drift_policy,
            )

    @auto_trace(logger)
    def get(self, component: str) -> SecureSchema:
        """Get the configuration for a registered component.

        Args:
            component: Name of the component

        Returns:
            The component's configuration instance

        Raises:
            ComponentNotFoundError: If component not registered
        """
        with self._lock:
            if component not in self._configs:
                raise ComponentNotFoundError(
                    component=component,
                    available=list(self._configs.keys()),
                )
            return self._configs[component]

    @auto_trace(logger)
    def get_or_none(self, component: str) -> Optional[SecureSchema]:
        """Get the configuration for a component, or None if not registered.

        Args:
            component: Name of the component

        Returns:
            The component's configuration instance, or None if not found
        """
        with self._lock:
            return self._configs.get(component)

    @auto_trace(logger)
    def list_components(self) -> list[str]:
        """List all registered components.

        Returns:
            List of registered component names
        """
        with self._lock:
            return list(self._configs.keys())

    @auto_trace(logger)
    def get_info(self, component: str) -> ConfigInfo:
        """Get metadata about a component's configuration.

        Args:
            component: Name of the component

        Returns:
            Metadata about the component's configuration

        Raises:
            ComponentNotFoundError: If component not registered
        """
        with self._lock:
            if component not in self._metadata:
                raise ComponentNotFoundError(
                    component=component,
                    available=list(self._configs.keys()),
                )
            return self._metadata[component]

    @auto_trace(logger)
    def has_previous(self, component: str) -> bool:
        """Check if a previous configuration exists for rollback.

        Args:
            component: Name of the component

        Returns:
            True if rollback is available
        """
        with self._lock:
            return component in self._previous

    @auto_trace(logger)
    def rollback_config(self, component: str) -> SecureSchema:
        """Rollback to the previous configuration.

        Restores the configuration that was active before the last
        reload_config() call. Only one level of rollback is supported.

        Args:
            component: Name of the component to rollback

        Returns:
            The restored (previous) configuration

        Raises:
            ComponentNotFoundError: If component is not registered
            NoPreviousConfigError: If no previous config exists

        Thread Safety:
            This operation is atomic.
        """
        with self._lock:
            if component not in self._configs:
                raise ComponentNotFoundError(
                    component=component,
                    available=list(self._configs.keys()),
                )

            if component not in self._previous:
                raise NoPreviousConfigError(component)

            previous_config = self._previous[component]
            current_config = self._configs[component]

            logger.info(
                "Rolling back secure config",
                extra={
                    "component": component,
                    "from_config": type(current_config).__name__,
                    "to_config": type(previous_config).__name__,
                },
            )

            # Swap: current becomes rollback target, previous becomes current
            self._configs[component] = previous_config
            del self._previous[component]

            logger.info(
                "Secure config rolled back",
                extra={"component": component},
            )

            return previous_config

    @auto_trace(logger)
    def unregister(self, component: str) -> None:
        """Unregister a component (mainly for testing).

        Args:
            component: Name of the component to unregister

        Raises:
            ComponentNotFoundError: If component is not registered
        """
        with self._lock:
            if component not in self._configs:
                raise ComponentNotFoundError(
                    component=component,
                    available=list(self._configs.keys()),
                )
            del self._configs[component]
            del self._metadata[component]
            # Also clear any previous config for rollback
            self._previous.pop(component, None)

            logger.info("Unregistered secure config", extra={"component": component})

    @auto_trace(logger)
    def clear(self) -> None:
        """Clear all registered components (mainly for testing)."""
        with self._lock:
            self._configs.clear()
            self._metadata.clear()
            self._previous.clear()
            logger.info("Cleared all secure configs")


# Global registry instance
_registry = SecureConfigRegistry()


@auto_trace(logger)
def register_config(
    component: str,
    path: Path,
    schema: Type[T],
    strict_permissions: bool = False,
) -> T:
    """Register configuration for a named component.

    Each component maintains its own isolated configuration within the
    process. Use a unique component name to identify each configuration.

    NOTE: This function is NOT idempotent. It raises ComponentExistsError
    if the component is already registered. Use ensure_registered() for
    idempotent registration.

    Args:
        component: Unique identifier for this component (e.g., "auth", "database")
        path: Path to JSON configuration file
        schema: Pydantic schema class to validate against
        strict_permissions: If True, reject world-readable files

    Returns:
        Validated configuration instance

    Raises:
        ComponentExistsError: If a component with this name is already registered
    """
    return _registry.register(component, path, schema, strict_permissions)


@auto_trace(logger)
def register_config_with_loader(
    component: str,
    schema: Type[T],
    loader: Callable[[], Tuple[T, ExtractedEnvVars]],
) -> T:
    """Register configuration using a custom loader callback.

    Use this for configurations that don't come from files, such as
    environment variable-based configurations. The loader callback
    is stored and used for reload operations.

    NOTE: This function is NOT idempotent. It raises ComponentExistsError
    if the component is already registered. Use ensure_registered_with_loader()
    for idempotent registration.

    Args:
        component: Unique identifier for this component
        schema: Pydantic schema class to validate against
        loader: Callback that loads and returns (config, extracted_env_vars)

    Returns:
        Validated configuration instance

    Raises:
        ComponentExistsError: If a component with this name is already registered
        ConfigResolutionError: If loader fails
        ConfigValidationError: If schema validation fails
    """
    return _registry.register_with_loader(component, schema, loader)


@auto_trace(logger)
def ensure_registered_with_loader(
    component: str,
    schema: Type[T],
    loader: Callable[[], Tuple[T, ExtractedEnvVars]],
) -> T:
    """Ensure configuration is registered using a loader (idempotent).

    If the component is already registered, returns the existing config.
    If not registered, registers it using the loader and returns the new config.

    Thread-safe: Uses registry lock to ensure atomicity.

    Args:
        component: Unique identifier for this component
        schema: Pydantic schema class to validate against
        loader: Callback that loads and returns (config, extracted_env_vars)

    Returns:
        Validated configuration instance (existing or newly loaded)

    Raises:
        ConfigResolutionError: If loader fails
        ConfigValidationError: If schema validation fails
    """
    # Try to get existing config first (fast path)
    existing = _registry.get_or_none(component)
    if existing is not None:
        return existing

    # Not registered - need to register (may race with another thread)
    try:
        return _registry.register_with_loader(component, schema, loader)
    except ComponentExistsError:
        # Another thread registered between our check and register
        return _registry.get(component)


@auto_trace(logger)
def ensure_registered(
    component: str,
    path: Path,
    schema: Type[T],
    strict_permissions: bool = False,
) -> T:
    """Ensure configuration is registered for a component (idempotent).

    If the component is already registered, returns the existing config.
    If not registered, registers it and returns the new config.

    This is the recommended function for application startup where the
    same registration code may run multiple times (e.g., in tests, or
    when modules are re-imported).

    Thread-safe: Uses registry lock to ensure atomicity.

    Args:
        component: Unique identifier for this component
        path: Path to JSON configuration file
        schema: Pydantic schema class to validate against
        strict_permissions: If True, reject world-readable files

    Returns:
        Validated configuration instance (existing or newly loaded)

    Raises:
        ConfigNotFoundError: If file doesn't exist
        ConfigPermissionError: If file has insecure permissions
        ConfigParseError: If JSON parsing fails
        ConfigResolutionError: If value resolution fails
        ConfigValidationError: If schema validation fails
    """
    # Try to get existing config first (fast path)
    existing = _registry.get_or_none(component)
    if existing is not None:
        return existing

    # Not registered - need to register (may race with another thread)
    try:
        return _registry.register(component, path, schema, strict_permissions)
    except ComponentExistsError:
        # Another thread registered between our check and register
        # Return the config they registered
        return _registry.get(component)


@auto_trace(logger)
def get_config(component: str) -> SecureSchema:
    """Get the configuration for a registered component.

    Args:
        component: Name of the component

    Returns:
        The component's configuration instance

    Raises:
        ComponentNotFoundError: If component is not registered
    """
    return _registry.get(component)


@auto_trace(logger)
def get_config_or_none(component: str) -> Optional[SecureSchema]:
    """Get the configuration for a component, or None if not registered.

    Args:
        component: Name of the component

    Returns:
        The component's configuration instance, or None if not found
    """
    return _registry.get_or_none(component)


@auto_trace(logger)
def list_components() -> list[str]:
    """List all registered components.

    Returns:
        List of registered component names
    """
    return _registry.list_components()


@auto_trace(logger)
def get_config_info(component: str) -> ConfigInfo:
    """Get metadata about a component's configuration.

    Args:
        component: Name of the component

    Returns:
        Metadata about the component's configuration

    Raises:
        ComponentNotFoundError: If component is not registered
    """
    return _registry.get_info(component)


@auto_trace(logger)
def get_extracted_env_vars(component: str) -> ExtractedEnvVars:
    """Get extracted environment variables for a component.

    Convenience function that returns the ExtractedEnvVars container
    for a registered component. This is equivalent to:
        get_config_info(component).extracted_env_vars

    Args:
        component: Name of the component

    Returns:
        ExtractedEnvVars container with all env vars declared in the
        component's config file under `extract_env_vars`.

    Raises:
        ComponentNotFoundError: If component is not registered

    Example:
        ```python
        # Config file:
        # {
        #     "timeout": 30,
        #     "extract_env_vars": {
        #         "API_KEY": null,
        #         "LOG_LEVEL": "INFO"
        #     }
        # }

        env = get_extracted_env_vars("myapp")
        api_key = env.api_key.get_secret_value()
        log_level = env.log_level.get_secret_value()
        ```
    """
    return _registry.get_info(component).extracted_env_vars


@auto_trace(logger)
def _clear_registry() -> None:
    """Clear registry (for testing only)."""
    _registry.clear()


@auto_trace(logger)
def _unregister(component: str) -> None:
    """Unregister a component (for testing only).

    Args:
        component: Name of the component to unregister
    """
    _registry.unregister(component)


@auto_trace(logger)
def reload_config(
    component: str,
    path: Optional[Path] = None,
    strict_permissions: bool = False,
    drift_policy: Literal["block", "warn", "allow"] = "block",
) -> ReloadResult:
    """Reload configuration for a component with drift detection.

    Atomically replaces the configuration with a freshly loaded version.
    Uses the same schema as the original registration.

    Drift Detection:
        Compares old and new configurations to detect changes.
        - Static fields (not marked refreshable): trigger drift detection
        - Refreshable fields: allowed to change without triggering drift

    Args:
        component: Name of component to reload
        path: Optional new path. If None, uses original path.
        strict_permissions: If True, reject world-readable files
        drift_policy: How to handle drift in static fields:
            - "block": Raise ConfigDriftError (default, most secure)
            - "warn": Log warning but allow reload
            - "allow": Silently allow all changes

    Returns:
        ReloadResult containing the new config and drift information

    Raises:
        ComponentNotFoundError: If component not registered
        ConfigDriftError: If drift_policy="block" and static field changed
        ConfigNotFoundError: If file doesn't exist
        ConfigPermissionError: If file has insecure permissions
        ConfigParseError: If JSON parsing fails
        ConfigResolutionError: If value resolution fails
        ConfigValidationError: If schema validation fails

    See SecureConfigRegistry.reload_config for details.
    """
    return _registry.reload_config(component, path, strict_permissions, drift_policy)


@auto_trace(logger)
def rollback_config(component: str) -> SecureSchema:
    """Rollback to the previous configuration.

    Restores the configuration that was active before the last
    reload_config() call. Only one level of rollback is supported.

    Args:
        component: Name of the component to rollback

    Returns:
        The restored (previous) configuration

    Raises:
        ComponentNotFoundError: If component is not registered
        NoPreviousConfigError: If no previous config exists

    See SecureConfigRegistry.rollback_config for details.
    """
    return _registry.rollback_config(component)


@auto_trace(logger)
def has_previous_config(component: str) -> bool:
    """Check if a previous configuration exists for rollback.

    Args:
        component: Name of the component

    Returns:
        True if rollback is available for this component
    """
    return _registry.has_previous(component)
