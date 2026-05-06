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

"""SecureSchema base class, ResolvableModel base class, and Field configuration.

Provides:
- SecureSchema: Frozen, registered config singletons with SecretStr masking
- ResolvableModel: Mutable base model with auto-resolved env:/file:// field defaults

Use SecretStr type annotation for fields that should be masked and require
explicit access via .get_secret_value().
"""

from __future__ import annotations

import types
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator
from pydantic.fields import FieldInfo
from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

logger = get_telemetry(__name__)


# =============================================================================
# Shared Utility for Secret Masking (eliminates duplication across packages)
# =============================================================================


@auto_trace(logger)
def mask_secrets_in_model(model: BaseModel) -> Dict[str, Any]:
    """Recursively mask SecretStr fields in a Pydantic model.

    This utility function provides consistent secret masking across all
    packages. Both SecureSchema and external mixins should delegate to
    this function to avoid code duplication.

    Args:
        model: A Pydantic BaseModel instance to mask

    Returns:
        Dictionary with SecretStr values replaced by "***MASKED***"

    Example:
        >>> class MyConfig(BaseModel):
        ...     api_key: SecretStr
        ...     host: str
        >>> config = MyConfig(api_key="secret123", host="localhost")
        >>> mask_secrets_in_model(config)
        {'api_key': '***MASKED***', 'host': 'localhost'}

    """
    result: Dict[str, Any] = {}
    for field_name in model.__class__.model_fields:
        value = getattr(model, field_name)
        if isinstance(value, SecretStr):
            result[field_name] = "***MASKED***"
        elif hasattr(value, "to_safe_dict"):
            # Object has its own to_safe_dict method (e.g., SecureSchema subclass)
            result[field_name] = value.to_safe_dict()
        elif isinstance(value, BaseModel):
            # Recursively mask nested BaseModel
            result[field_name] = mask_secrets_in_model(value)
        elif isinstance(value, list):
            # Handle lists of items
            result[field_name] = [
                item.to_safe_dict() if hasattr(item, "to_safe_dict")
                else mask_secrets_in_model(item) if isinstance(item, BaseModel)
                else item
                for item in value
            ]
        else:
            result[field_name] = value
    return result


class ExtractedEnvVars:
    """Container for environment variables extracted from config declaration.

    Provides attribute-style access to extracted environment variables,
    all wrapped as SecretStr for security.

    Example:
        ```python
        # Config file declares:
        # {
        #     "extract_env_vars": {
        #         "API_KEY": null,
        #         "LOG_LEVEL": "INFO"
        #     }
        # }

        # Access extracted vars:
        config_info = get_config_info("myapp")
        env = config_info.extracted_env_vars

        # Attribute access (lowercase):
        api_key = env.api_key.get_secret_value()
        log_level = env.log_level.get_secret_value()

        # Safe logging (masked):
        print(env.api_key)  # Output: **********

        # Dict-style access:
        env["api_key"]

        # List all extracted vars:
        env.keys()  # ["api_key", "log_level"]
        ```
    """

    def __init__(self, env_vars: dict[str, SecretStr]) -> None:
        """Initialize with extracted environment variables.

        Args:
            env_vars: Dictionary mapping lowercased var names to SecretStr values.
        """
        self._env_vars = env_vars

    def __getattr__(self, name: str) -> SecretStr:
        """Get extracted env var by attribute name.

        Args:
            name: Lowercased environment variable name

        Returns:
            SecretStr wrapping the env var value

        Raises:
            AttributeError: If env var was not extracted
        """
        if name.startswith("_"):
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")
        if name not in self._env_vars:
            available = ", ".join(self._env_vars.keys()) or "(none)"
            raise AttributeError(
                f"Environment variable '{name}' was not declared in extract_env_vars. "
                f"Available: {available}"
            )
        return self._env_vars[name]

    def __getitem__(self, name: str) -> SecretStr:
        """Get extracted env var by dict-style access.

        Args:
            name: Lowercased environment variable name

        Returns:
            SecretStr wrapping the env var value

        Raises:
            KeyError: If env var was not extracted
        """
        if name not in self._env_vars:
            raise KeyError(f"Environment variable '{name}' was not declared in extract_env_vars")
        return self._env_vars[name]

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get(self, name: str, default: Optional[SecretStr] = None) -> Optional[SecretStr]:
        """Get extracted env var with optional default.

        Args:
            name: Lowercased environment variable name
            default: Value to return if var not found

        Returns:
            SecretStr wrapping the env var value, or default
        """
        return self._env_vars.get(name, default)

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def keys(self) -> list[str]:
        """List all extracted environment variable names.

        Returns:
            List of lowercased env var names that were extracted
        """
        return list(self._env_vars.keys())

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def items(self) -> list[tuple[str, SecretStr]]:
        """Get all extracted env vars as key-value pairs.

        Returns:
            List of (name, SecretStr) tuples
        """
        return list(self._env_vars.items())

    def __len__(self) -> int:
        """Return number of extracted env vars."""
        return len(self._env_vars)

    def __bool__(self) -> bool:
        """Return True if any env vars were extracted."""
        return len(self._env_vars) > 0

    def __repr__(self) -> str:
        """Return repr with all values masked."""
        masked = {k: "SecretStr('**********')" for k in self._env_vars}
        return f"ExtractedEnvVars({masked})"

    def __str__(self) -> str:
        """Return string with all values masked."""
        return self.__repr__()

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def to_safe_dict(self) -> dict[str, str]:
        """Return dict with all values masked for logging.

        Returns:
            Dict mapping var names to "***MASKED***"
        """
        return {k: "***MASKED***" for k in self._env_vars}

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get_secret_value(self, name: str) -> str:
        """Get the actual (unwrapped) value of an extracted env var.

        Convenience method that combines lookup and unwrap.

        Args:
            name: Lowercased environment variable name

        Returns:
            The actual string value

        Raises:
            KeyError: If env var was not extracted
        """
        return self[name].get_secret_value()


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def Field(
    default: Any = ...,
    *,
    description: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Create a configuration field.

    For secret fields, use SecretStr type annotation. The type determines
    whether the field is treated as a secret.

    Args:
        default: Default value. Use ... (Ellipsis) for required fields.
        description: Field documentation.
        **kwargs: Additional Pydantic field arguments.

    Returns:
        Pydantic FieldInfo.

    Example:
        class MyConfig(SecureSchema):
            api_key: SecretStr = Field(description="API key")  # Secret
            host: str = Field(default="localhost")              # Not secret

        config = load_secure_config(path, MyConfig)
        # Access secret: config.api_key.get_secret_value()
        # Safe logging: str(config.api_key) -> '**********'
    """
    from pydantic import Field as PydanticField

    return PydanticField(
        default=default,
        description=description,
        **kwargs,
    )


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def _is_secret_str_annotation(annotation: Any) -> bool:
    """Check if a type annotation is or contains SecretStr.

    Handles:
    - SecretStr directly
    - Optional[SecretStr] (Union[SecretStr, None])
    - Union types containing SecretStr

    Args:
        annotation: The type annotation to check.

    Returns:
        True if the annotation is or contains SecretStr.
    """
    if annotation is SecretStr:
        return True
    origin = getattr(annotation, "__origin__", None)
    if origin is not None:
        args = getattr(annotation, "__args__", ())
        return SecretStr in args
    return False


@auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
def _is_optional_annotation(annotation: Any) -> bool:
    """Check if a type annotation is Optional (Union[X, None]).

    Handles both typing.Union (Optional[str]) and types.UnionType (str | None).

    Args:
        annotation: The type annotation to check.

    Returns:
        True if the annotation allows None.
    """
    # Handle types.UnionType (Python 3.10+ str | None syntax)
    if isinstance(annotation, types.UnionType):
        return type(None) in annotation.__args__
    # Handle typing.Union (Optional[str] / Union[str, None])
    origin = getattr(annotation, "__origin__", None)
    if origin is Union:
        args = getattr(annotation, "__args__", ())
        return type(None) in args
    return False


class ResolvableModel(BaseModel):
    """Base model with automatic resolution of env:/file:// field defaults.

    Any Pydantic model that inherits from ResolvableModel gets automatic
    resolution of env:/file:// default values after construction. This
    handles the case where Pydantic field defaults contain value-source
    references that config loaders' dict-walking cannot reach.

    Resolution flow:
    1. Pydantic constructs the model, applying field defaults
    2. model_validator(mode="after") iterates all fields
    3. String fields with env:/file:// prefixes are resolved via resolve_value
    4. SecretStr fields are resolved with wrapping; str fields without

    Important: This class relies on Pydantic's default validate_default=False.
    Without it, SecretStr defaults like "env:MY_SECRET" would be coerced to
    SecretStr("env:MY_SECRET") before the model validator runs, making them
    invisible to isinstance(value, str) and skipping resolution entirely.
    Subclasses must NOT set validate_default=True.

    Unlike SecureSchema, ResolvableModel is:
    - Mutable (not frozen)
    - Not registered in SecureConfigRegistry
    - General-purpose (any model, not just config singletons)

    Example:
        class BrokerConfig(ResolvableModel):
            url: str = Field(default="env:REDIS_URL")
            result_backend: str | None = None

        # REDIS_URL=redis://host:6379
        config = BrokerConfig()
        assert config.url == "redis://host:6379"
    """

    @model_validator(mode="after")
    def _resolve_value_sources(self) -> ResolvableModel:
        """Resolve env:/file:// references in field values after construction."""
        # Lazy import to avoid circular dependency with resolver.py
        from neoaxios_secure_config.errors import ConfigResolutionError
        from neoaxios_secure_config.resolver import resolve_value

        component = type(self).__name__
        resolved_fields: list[str] = []

        for field_name, field_info in type(self).model_fields.items():
            value = getattr(self, field_name)

            # Only resolve string values (including SecretStr-wrapped strings)
            if isinstance(value, SecretStr):
                raw_value = value.get_secret_value()
                value_is_secret = True
            elif isinstance(value, str):
                raw_value = value
                value_is_secret = False
            else:
                continue

            if not (raw_value.startswith("env:") or raw_value.startswith("file://")):
                continue

            annotation = field_info.annotation
            is_secret = _is_secret_str_annotation(annotation) or value_is_secret
            is_optional = _is_optional_annotation(annotation)

            try:
                # For optional fields, pass default=None so missing env vars
                # return None instead of raising. For required fields, omit
                # default so resolve_value raises ConfigResolutionError.
                kwargs: dict[str, Any] = {
                    "value": raw_value,
                    "field_name": field_name,
                    "component": component,
                    "should_wrap_as_secret": is_secret,
                }
                if is_optional:
                    kwargs["default"] = None
                resolved = resolve_value(**kwargs)
                # Use object.__setattr__ instead of self.field = value to:
                # 1. Avoid polluting model_fields_set — resolved defaults should
                #    not appear as user-provided values (affects model_dump(exclude_unset=True))
                # 2. Skip Pydantic's __setattr__ validation, which would re-coerce
                #    SecretStr values that resolve_value already wrapped correctly
                object.__setattr__(self, field_name, resolved)
                resolved_fields.append(field_name)
            except ConfigResolutionError:
                if is_optional:
                    object.__setattr__(self, field_name, None)
                    resolved_fields.append(field_name)
                else:
                    raise

        if resolved_fields:
            logger.debug(
                "Resolved value sources in model",
                extra={
                    "component": component,
                    "resolved_fields": resolved_fields,
                    "count": len(resolved_fields),
                },
            )

        return self


class SecureSchema(BaseModel):
    """Base class for secure configuration schemas.

    Features:
    - Immutable after creation (frozen)
    - SecretStr fields automatically masked in repr/str
    - Strict validation (no extra fields allowed)

    Secret Field Usage:
        Use SecretStr type annotation for sensitive fields:

        class MyConfig(SecureSchema):
            password: SecretStr = Field(description="Database password")
            host: str = Field(description="Database host")

        # Access the secret value explicitly:
        actual_password = config.password.get_secret_value()

        # Safe for logging (automatically masked):
        print(config.password)  # Output: **********
        print(repr(config))     # Output: MyConfig(password=SecretStr('**********'), host='localhost')
    """

    model_config = ConfigDict(
        frozen=True,  # Immutable after creation
        extra="forbid",  # No extra fields allowed
        validate_default=True,  # Validate default values
    )

    def __repr__(self) -> str:
        """Return repr with SecretStr fields masked."""
        field_strs = []
        for name in self.__class__.model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                field_strs.append(f"{name}=SecretStr('**********')")
            else:
                field_strs.append(f"{name}={value!r}")
        return f"{self.__class__.__name__}({', '.join(field_strs)})"

    def __str__(self) -> str:
        """Return string with SecretStr fields masked."""
        return self.__repr__()

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _is_secret_str_field(cls, field_info: FieldInfo) -> bool:
        """Check if a field is typed as SecretStr."""
        return _is_secret_str_annotation(field_info.annotation)

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get_secret_fields(cls) -> list[str]:
        """Get list of field names typed as SecretStr."""
        return [
            name
            for name, field_info in cls.model_fields.items()
            if cls._is_secret_str_field(field_info)
        ]

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def _is_refreshable_field(cls, field_info: FieldInfo) -> bool:
        """Check if a field is marked as refreshable.

        Fields are refreshable if json_schema_extra contains {"refreshable": True}.
        By default, fields are NOT refreshable (static).
        """
        extra = field_info.json_schema_extra
        if extra is None:
            return False
        if isinstance(extra, dict):
            return extra.get("refreshable", False) is True
        return False

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get_refreshable_fields(cls) -> list[str]:
        """Get list of field names marked as refreshable.

        Refreshable fields can change during reload_config() without
        triggering drift detection. Use for secrets that rotate.

        Mark fields as refreshable:
            client_secret: SecretStr = Field(
                description="Client secret",
                json_schema_extra={"refreshable": True}
            )
        """
        return [
            name
            for name, field_info in cls.model_fields.items()
            if cls._is_refreshable_field(field_info)
        ]

    @classmethod
    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get_static_fields(cls) -> list[str]:
        """Get list of field names that are static (not refreshable).

        Static fields trigger drift detection if they change during
        reload_config(). These are identity fields like tenant_id, client_id.
        """
        return [
            name
            for name, field_info in cls.model_fields.items()
            if not cls._is_refreshable_field(field_info)
        ]

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def to_safe_dict(self) -> dict[str, Any]:
        """Return dict with SecretStr fields masked.

        Use this for logging or debugging. Handles nested models and lists.

        Delegates to mask_secrets_in_model() for consistent behavior across
        all packages that use secure_config.
        """
        return mask_secrets_in_model(self)

    @auto_trace(logger, disabled=TraceDisabledReason.TRIVIAL_GETTER)
    def get_secret_value(self, field_name: str) -> Any:
        """Get the actual value of a field, unwrapping SecretStr if needed.

        Args:
            field_name: Name of the field to get

        Returns:
            The actual value (unwrapped from SecretStr if applicable)

        Raises:
            AttributeError: If field doesn't exist
        """
        value = getattr(self, field_name)
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return value
