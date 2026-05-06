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

"""Configuration loaders for identity provider settings.

Provides functions to load configuration from multiple sources:
- YAML files
- Environment variables
- Python dictionaries (for testing)

Supports secrets management via:
- File-based secrets (/run/secrets/*)
- Environment variables
- AWS Secrets Manager format

Usage:
    from neoaxios_fastapi_kit.auth.config import load_config_from_yaml, load_config_from_env

    # Load from YAML
    config = load_config_from_yaml("/etc/auth/config.yaml")

    # Load from environment variables
    config = load_config_from_env()
"""

import os
from pathlib import Path
from typing import Any, Dict, Literal, Optional

import yaml
from pydantic import SecretStr, ValidationError
from neoaxios_secure_config import (
    ConfigResolutionError,
    ConfigPermissionError,
    ExtractedEnvVars,
    ReloadResult,
    ensure_registered_with_loader,
    extract_env_vars,
    get_extracted_env_vars,
    has_previous_config,
    reload_config,
    rollback_config,
)
from neoaxios_secure_config import resolve_value as secure_resolve_value

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.config.schemas import (
    DecoderConfig,
    AzureConfig,
    Auth0Config,
    CacheConfig,
    CognitoConfig,
    GoogleConfig,
    JWTConfig,
    KeycloakConfig,
    OIDCConfig,
    OktaConfig,
)

logger = get_telemetry(__name__)

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Generic configuration loaders
    "load_config_from_yaml",
    "load_config_from_env",
    "load_config_from_dict",
    # Azure-specific loaders
    "load_azure_config",
    "load_azure_config_from_yaml",
    "load_azure_config_from_env",
    "load_azure_config_from_env_extracted",
    "load_azure_config_from_dict",
    # Azure registry-based API (with drift detection and rollback)
    "get_azure_config_registry",
    "reload_azure_config_registry",
    "rollback_azure_config_registry",
    "has_azure_config_rollback",
    "get_azure_env_vars_registry",
    "clear_azure_config_registry",
    "AZURE_CONFIG_COMPONENT",
    # Azure decoder factory
    "create_azure_decoder",
    # Testing utilities
    "add_allowed_secret_dir",
    # Errors
    "ConfigurationError",
]


# =============================================================================
# Security Constants
# =============================================================================

# Allowed directories for file:// secret resolution (path allowlisting)
# Passed explicitly to secure_config.resolve_value() for full traceability
# (no environment variable configuration - allowlist is defined here in code)
ALLOWED_SECRET_DIRS: list[Path] = [
    Path("/run/secrets"),
    Path("/var/run/secrets"),
    Path("/etc/secrets"),
    Path("/var/run/secrets/kubernetes.io"),
    Path("/mnt/secrets-store"),  # Azure Key Vault CSI driver mount
]


@auto_trace(logger)  # Test utility for extending secret dirs
def add_allowed_secret_dir(path: Path) -> None:
    """Add a directory to ALLOWED_SECRET_DIRS for testing purposes.

    This function allows test code to extend the allowed directories
    for file:// secret resolution. Should only be used in test setup.

    Args:
        path: Directory path to add to the allowlist

    Example:
        # In test conftest.py
        from neoaxios_fastapi_kit.auth.config.loaders import add_allowed_secret_dir
        add_allowed_secret_dir(Path("/tmp"))
    """
    resolved = path.resolve()
    if resolved not in ALLOWED_SECRET_DIRS:
        ALLOWED_SECRET_DIRS.append(resolved)
        logger.info(
            "Added directory to secret allowlist",
            extra={"path": str(resolved)},
        )

# Cached production mode detection (environment won't change at runtime)
_CACHED_PRODUCTION_MODE: Optional[bool] = None

# Sensitive fields that should be redacted from error messages
SENSITIVE_FIELDS = frozenset([
    "client_secret",
    "app_client_secret",
    "graph_client_secret",
    "password",
    "token",
    "secret",
    "api_key",
])


@auto_trace(logger)  # Cached environment detection
def _detect_production_environment() -> bool:
    """Detect if running in production environment.

    Uses positive security: explicitly requires dev mode flag for development.
    Default is production mode (fail-secure).

    Results are cached since environment won't change during runtime.

    Returns:
        True if production (default), False if explicit dev mode enabled

    Security:
        - Uses positive security pattern (explicit dev mode, not implicit production)
        - Checks for common production indicators as additional safety
        - Logs warning when dev mode is enabled
        - Cached to avoid repeated environment checks
    """
    global _CACHED_PRODUCTION_MODE

    # Return cached result if available
    if _CACHED_PRODUCTION_MODE is not None:
        return _CACHED_PRODUCTION_MODE

    # Check for explicit dev mode flag (positive security)
    dev_mode = os.getenv("FASTAPI_KIT_DEV_MODE", "").lower()

    if dev_mode in ("true", "1", "yes"):
        logger.warning(
            "DEVELOPMENT MODE ENABLED via FASTAPI_KIT_DEV_MODE. "
            "This allows .env file loading. "
            "DO NOT use in production.",
            extra={"dev_mode": True},
        )
        _CACHED_PRODUCTION_MODE = False
        return False

    # Additional production indicators (defense in depth)
    production_indicators = [
        os.getenv("KUBERNETES_SERVICE_HOST") is not None,
        os.getenv("ECS_CONTAINER_METADATA_URI") is not None,
        os.getenv("GOOGLE_CLOUD_PROJECT") is not None,
        os.getenv("ENVIRONMENT", "").lower() == "production",
        os.getenv("ENV", "").lower() in ("production", "prod"),
        os.path.exists("/var/run/secrets/kubernetes.io"),
    ]

    if any(production_indicators):
        logger.info(
            "Production environment detected",
            extra={"indicators_matched": sum(production_indicators)},
        )

    # Default to production (fail-secure)
    _CACHED_PRODUCTION_MODE = True
    return True


@auto_trace(logger, include_args=False)  # Security: handles secret values in errors
def _sanitize_validation_errors(errors: list) -> list:
    """Remove secret values from Pydantic validation errors.

    Security: Prevents secrets from leaking into error messages or logs.

    Args:
        errors: List of Pydantic validation error dictionaries

    Returns:
        Sanitized errors with sensitive values redacted
    """
    sanitized = []
    for error in errors:
        error_copy = dict(error)
        # Get the field name from the error location
        loc = error.get("loc", ())
        field_name = loc[-1] if loc else None

        # Redact sensitive fields
        if field_name and str(field_name).lower() in SENSITIVE_FIELDS:
            if "input" in error_copy:
                error_copy["input"] = "***REDACTED***"
            if "ctx" in error_copy and isinstance(error_copy["ctx"], dict):
                for key in list(error_copy["ctx"].keys()):
                    if any(s in key.lower() for s in SENSITIVE_FIELDS):
                        error_copy["ctx"][key] = "***REDACTED***"

        sanitized.append(error_copy)
    return sanitized


# Note: _validate_secret_path() and _load_secret_from_file() have been replaced
# by secure_config's TOCTOU-safe file resolution. See resolve_value() in secure_config.
# Path allowlisting is passed explicitly via ALLOWED_SECRET_DIRS (no env var config).


# =============================================================================
# Secret Loading (via secure_config)
# =============================================================================


@auto_trace(logger, include_args=False)
def _resolve_secret(
    value: str,
    field_name: str = "secret",
    component: str = "neoaxios_fastapi_kit"
) -> SecretStr:
    """Resolve secret value using secure_config's TOCTOU-safe resolution.

    Returns SecretStr to prevent accidental logging of sensitive values.
    All resolution methods (env, file, direct) return SecretStr for consistency.

    SECURITY: Arguments are NOT logged by @auto_trace due to sensitivity of secret values.
    This function delegates to secure_config which provides:
    - TOCTOU-safe file descriptor-based operations
    - O_NOFOLLOW symlink protection
    - Path allowlisting via explicit allowed_base_dirs parameter (traceable to code)
    - File permission validation

    Supports three resolution methods:
    - Direct values: "my-secret" (wrapped in SecretStr)
    - File references: "file:///run/secrets/my-secret" (TOCTOU-safe file read)
    - Environment variables: "env:MY_SECRET" (resolved from environment)

    Args:
        value: Secret value or reference string
        field_name: Field name for error messages (default: "secret")
        component: Component name for logging (default: "neoaxios_fastapi_kit")

    Returns:
        SecretStr wrapping the resolved secret value

    Raises:
        ValueError: If resolution fails (env var not set, file not found, etc.)

    Resolved secrets are wrapped in SecretStr to keep them out of logs and
    repr output; this delegates to the secure_config package.
    """
    if not value:
        return SecretStr("")

    # Determine resolution method for logging
    if value.startswith("file://"):
        resolution_method = "file"
    elif value.startswith("env:"):
        resolution_method = "environment"
    else:
        resolution_method = "direct"

    logger.info(
        "ENTRY: _resolve_secret",
        extra={"resolution_method": resolution_method},
    )

    try:
        # Use secure_config's TOCTOU-safe resolution with explicit allowed dirs
        # (no environment variable - allowlist is traceable to ALLOWED_SECRET_DIRS constant)
        resolved = secure_resolve_value(value, field_name, component, ALLOWED_SECRET_DIRS)

        # secure_resolve_value returns SecretStr for env:/file://, raw value for literals
        if isinstance(resolved, SecretStr):
            result = resolved
        else:
            result = SecretStr(str(resolved))

        logger.info(
            "EXIT: _resolve_secret",
            extra={"resolution_method": resolution_method, "status": "success"},
        )
        return result

    except (ConfigResolutionError, ConfigPermissionError) as e:
        logger.log_error(
            e,
            extra={
                "resolution_method": resolution_method,
                "status": "error",
                "field_name": field_name,
            },
        )
        raise ValueError(f"Failed to resolve secret for {field_name}: {e}") from e
    except Exception as e:
        logger.log_error(
            e,
            extra={"resolution_method": resolution_method, "status": "error"},
        )
        raise


# =============================================================================
# YAML Loading
# =============================================================================


@auto_trace(logger)
def load_config_from_yaml(file_path: str) -> DecoderConfig:
    """Load authentication configuration from YAML file.

    Parses YAML, validates structure, and resolves secret references.

    Args:
        file_path: Path to YAML configuration file

    Returns:
        Validated DecoderConfig instance

    Raises:
        FileNotFoundError: If file does not exist
        ValidationError: If configuration is invalid
        yaml.YAMLError: If YAML is malformed

    Example YAML:
        azure:
          tenant_id: "550e8400-e29b-41d4-a716-446655440000"
          client_id: "660e8400-e29b-41d4-a716-446655440000"
          client_secret: "file:///run/secrets/azure-secret"
        cache:
          backend: redis
          ttl_seconds: 300
          redis_url: "redis://localhost:6379/0"
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    logger.info("Loading configuration from YAML", extra={"path": file_path})

    try:
        with path.open("r") as f:
            data = yaml.safe_load(f)

        if data is None:
            data = {}

        # Resolve secrets in configuration
        data = _resolve_secrets_in_dict(data)

        config = load_config_from_dict(data)

        logger.info(
            "Configuration loaded successfully from YAML",
            extra={"path": file_path},
        )

        return config

    except yaml.YAMLError as e:
        logger.log_error(
            Exception(f"Failed to parse YAML: {e}"),
            extra={"path": file_path},
        )
        raise


@auto_trace(logger, include_args=False)  # Security: handles secret values
def _resolve_secrets_in_dict(
    data: Dict[str, Any],
    component: str = "neoaxios_fastapi_kit"
) -> Dict[str, Any]:
    """Recursively resolve secret references in dictionary.

    Uses secure_config for TOCTOU-safe file resolution.

    Args:
        data: Dictionary possibly containing secret references
        component: Component name for logging (default: "neoaxios_fastapi_kit")

    Returns:
        Dictionary with resolved secrets (SecretStr values for env:/file:// refs)
    """
    result = {}

    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _resolve_secrets_in_dict(value, component)
        elif isinstance(value, str) and (
            value.startswith("file://") or value.startswith("env:")
        ):
            # Resolve secret reference with field name for error messages
            result[key] = _resolve_secret(value, field_name=key, component=component)
        else:
            result[key] = value

    return result


# =============================================================================
# Environment Variable Loading
# =============================================================================


@auto_trace(logger)
def load_config_from_env() -> DecoderConfig:
    """Load authentication configuration from environment variables.

    Reads environment variables with standard naming convention:
    - JWT_PUBLIC_KEY_PATH, JWT_ALGORITHM, JWT_ISSUER, JWT_AUDIENCE
    - OIDC_DISCOVERY_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET
    - AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    - COGNITO_REGION, COGNITO_USER_POOL_ID, COGNITO_APP_CLIENT_ID
    - GOOGLE_AUDIENCE, GOOGLE_TENANT_ID, GOOGLE_GCP_PROJECT_ID
    - OKTA_TENANT_ID, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, OKTA_ISSUER
    - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE
    - KEYCLOAK_REALM_NAME, KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET
    - CACHE_BACKEND, CACHE_TTL_SECONDS, REDIS_URL

    Returns:
        Validated DecoderConfig instance

    Raises:
        ValidationError: If configuration is invalid

    Example:
        # Azure AD
        export AZURE_TENANT_ID="550e8400-e29b-41d4-a716-446655440000"
        export AZURE_CLIENT_ID="660e8400-e29b-41d4-a716-446655440000"
        export AZURE_CLIENT_SECRET="file:///run/secrets/azure-secret"

        # Okta
        export OKTA_TENANT_ID="dev-123456"
        export OKTA_CLIENT_ID="0oa2abcdefGHIJKLMN"
        export OKTA_CLIENT_SECRET="env:OKTA_SECRET"

        # Cache
        export CACHE_BACKEND="redis"
        export REDIS_URL="redis://localhost:6379/0"
    """
    logger.info("Loading configuration from environment variables")

    data: Dict[str, Any] = {}

    # JWT configuration
    if os.getenv("JWT_PUBLIC_KEY_PATH"):
        # public_key_path is metadata (a file path), not a secret - unwrap SecretStr
        public_key_path = _resolve_secret(
            os.getenv("JWT_PUBLIC_KEY_PATH", ""),
            field_name="public_key_path"
        ).get_secret_value()
        data["jwt"] = {
            "public_key_path": public_key_path,
            "algorithm": os.getenv("JWT_ALGORITHM", "RS256"),
            "issuer": os.getenv("JWT_ISSUER", ""),
            "audience": os.getenv("JWT_AUDIENCE"),
            "clock_skew_seconds": int(os.getenv("JWT_CLOCK_SKEW_SECONDS", "30")),
        }

    # OIDC configuration
    if os.getenv("OIDC_DISCOVERY_URL") or os.getenv("OIDC_ISSUER"):
        oidc_data = {
            "client_id": os.getenv("OIDC_CLIENT_ID", ""),
            "client_secret": (
                _resolve_secret(
                    os.getenv("OIDC_CLIENT_SECRET", ""),
                    field_name="client_secret"
                )
                if os.getenv("OIDC_CLIENT_SECRET")
                else None
            ),
        }

        # Handle discovery URL if provided (takes precedence)
        if os.getenv("OIDC_DISCOVERY_URL"):
            # Extract issuer from discovery URL (remove /.well-known/openid-configuration)
            discovery_url = os.getenv("OIDC_DISCOVERY_URL", "")
            if "/.well-known/openid-configuration" in discovery_url:
                issuer = discovery_url.replace("/.well-known/openid-configuration", "")
            else:
                # If discovery URL doesn't follow standard pattern, use as-is for issuer
                issuer = discovery_url
            oidc_data["issuer"] = issuer

        # Handle explicit issuer if provided and discovery URL not present
        elif os.getenv("OIDC_ISSUER"):
            oidc_data["issuer"] = os.getenv("OIDC_ISSUER", "")

        # Add optional fields
        if os.getenv("OIDC_AUDIENCE"):
            oidc_data["audience"] = os.getenv("OIDC_AUDIENCE")
        if os.getenv("OIDC_SCOPE"):
            oidc_data["scope"] = os.getenv("OIDC_SCOPE")

        data["oidc"] = oidc_data

    # Azure AD configuration
    if os.getenv("AZURE_TENANT_ID"):
        data["azure"] = {
            "tenant_id": os.getenv("AZURE_TENANT_ID", ""),
            "client_id": os.getenv("AZURE_CLIENT_ID", ""),
            "client_secret": _resolve_secret(
                os.getenv("AZURE_CLIENT_SECRET", ""),
                field_name="client_secret"
            ),
            "validate_audience": os.getenv("AZURE_VALIDATE_AUDIENCE", "true").lower() == "true",
            "validate_issuer": os.getenv("AZURE_VALIDATE_ISSUER", "true").lower() == "true",
        }

    # AWS Cognito configuration
    if os.getenv("COGNITO_REGION"):
        data["cognito"] = {
            "region": os.getenv("COGNITO_REGION", ""),
            "user_pool_id": os.getenv("COGNITO_USER_POOL_ID", ""),
            "app_client_id": os.getenv("COGNITO_APP_CLIENT_ID", ""),
            "app_client_secret": _resolve_secret(
                os.getenv("COGNITO_APP_CLIENT_SECRET", ""),
                field_name="app_client_secret"
            ),
            "tenant_id": os.getenv("COGNITO_TENANT_ID", ""),
            "token_type": os.getenv("COGNITO_TOKEN_TYPE", "id"),
        }

    # Google IAM configuration
    if os.getenv("GOOGLE_AUDIENCE"):
        data["google"] = {
            "audience": os.getenv("GOOGLE_AUDIENCE", ""),
            "allowed_domains": (
                os.getenv("GOOGLE_ALLOWED_DOMAINS", "").split(",")
                if os.getenv("GOOGLE_ALLOWED_DOMAINS")
                else []
            ),
            "tenant_id": os.getenv("GOOGLE_TENANT_ID", ""),
            "gcp_project_id": os.getenv("GOOGLE_GCP_PROJECT_ID"),
        }

    # Okta configuration
    if os.getenv("OKTA_TENANT_ID"):
        data["okta"] = {
            "tenant_id": os.getenv("OKTA_TENANT_ID", ""),
            "issuer": os.getenv("OKTA_ISSUER", ""),
            "client_id": os.getenv("OKTA_CLIENT_ID", ""),
            "client_secret": (
                _resolve_secret(
                    os.getenv("OKTA_CLIENT_SECRET", ""),
                    field_name="client_secret"
                )
                if os.getenv("OKTA_CLIENT_SECRET")
                else None
            ),
            "audience": os.getenv("OKTA_AUDIENCE"),
            "scope": os.getenv("OKTA_SCOPE"),
        }

    # Auth0 configuration
    if os.getenv("AUTH0_DOMAIN"):
        data["auth0"] = {
            "domain": os.getenv("AUTH0_DOMAIN", ""),
            "issuer": os.getenv("AUTH0_ISSUER", ""),
            "client_id": os.getenv("AUTH0_CLIENT_ID", ""),
            "client_secret": (
                _resolve_secret(
                    os.getenv("AUTH0_CLIENT_SECRET", ""),
                    field_name="client_secret"
                )
                if os.getenv("AUTH0_CLIENT_SECRET")
                else None
            ),
            "audience": os.getenv("AUTH0_AUDIENCE"),
            "scope": os.getenv("AUTH0_SCOPE"),
        }

    # Keycloak configuration
    if os.getenv("KEYCLOAK_REALM_NAME"):
        data["keycloak"] = {
            "realm_name": os.getenv("KEYCLOAK_REALM_NAME", ""),
            "issuer": os.getenv("KEYCLOAK_ISSUER", ""),
            "client_id": os.getenv("KEYCLOAK_CLIENT_ID", ""),
            "client_secret": (
                _resolve_secret(
                    os.getenv("KEYCLOAK_CLIENT_SECRET", ""),
                    field_name="client_secret"
                )
                if os.getenv("KEYCLOAK_CLIENT_SECRET")
                else None
            ),
            "audience": os.getenv("KEYCLOAK_AUDIENCE"),
            "scope": os.getenv("KEYCLOAK_SCOPE"),
        }

    # Cache configuration
    data["cache"] = {
        "backend": os.getenv("CACHE_BACKEND", "memory"),
        "ttl_seconds": int(os.getenv("CACHE_TTL_SECONDS", "300")),
        "redis_url": os.getenv("REDIS_URL"),
    }

    # Resolver configuration
    data["resolver_type"] = os.getenv("RESOLVER_TYPE", "local")
    data["resolver_merge_strategy"] = os.getenv("RESOLVER_MERGE_STRATEGY", "union")

    config = load_config_from_dict(data)

    logger.info("Configuration loaded successfully from environment")

    return config


# =============================================================================
# Dictionary Loading
# =============================================================================


@auto_trace(logger, include_args=False)
def load_config_from_dict(data: Dict[str, Any]) -> DecoderConfig:
    """Load authentication configuration from dictionary.

    SECURITY: Arguments are NOT logged by @auto_trace due to sensitivity of configuration data.
    Configuration dictionaries may contain credentials (client_secret, api_key, tokens, etc.)
    that must not be exposed in telemetry logs. Manual logging tracks only provider detection
    and structural validation, never configuration values.

    Validates structure and creates DecoderConfig instance with support for multiple identity
    providers (JWT, OIDC, Azure AD, AWS Cognito, Google IAM) and caching configuration.
    Used by other loaders and for testing.

    Args:
        data: Configuration dictionary containing provider settings and cache config
              (must not contain plaintext secrets; use file:// or env: references)

    Returns:
        Validated DecoderConfig instance with all configured providers

    Raises:
        ValidationError: If any provider configuration is structurally invalid

    Example:
        config = load_config_from_dict({
            "azure": {
                "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
                "client_id": "660e8400-e29b-41d4-a716-446655440000",
                "client_secret": "file:///run/secrets/azure"  # Never plain text!
            },
            "cache": {
                "backend": "memory",
                "ttl_seconds": 300
            }
        })
    """
    logger.info("ENTRY: load_config_from_dict")

    try:
        # Detect which providers are configured (without logging their values)
        providers_detected = []
        if "jwt" in data:
            providers_detected.append("jwt")
        if "oidc" in data:
            providers_detected.append("oidc")
        if "azure" in data:
            providers_detected.append("azure")
        if "cognito" in data:
            providers_detected.append("cognito")
        if "google" in data:
            providers_detected.append("google")
        if "okta" in data:
            providers_detected.append("okta")
        if "auth0" in data:
            providers_detected.append("auth0")
        if "keycloak" in data:
            providers_detected.append("keycloak")

        logger.info(
            "Detected identity providers in configuration",
            extra={"providers": providers_detected, "provider_count": len(providers_detected)},
        )

        # Build nested config objects
        config_dict: Dict[str, Any] = {}

        # JWT
        if "jwt" in data:
            logger.info("Validating JWT provider configuration")
            config_dict["jwt"] = JWTConfig(**data["jwt"])
            logger.info("JWT provider configuration validated successfully")

        # OIDC
        if "oidc" in data:
            logger.info("Validating OIDC provider configuration")
            config_dict["oidc"] = OIDCConfig(**data["oidc"])
            logger.info("OIDC provider configuration validated successfully")

        # Azure AD (using secure AzureConfig with SecretStr)
        if "azure" in data:
            logger.info("Validating Azure AD provider configuration")
            config_dict["azure"] = AzureConfig(**data["azure"])
            logger.info("Azure AD provider configuration validated successfully")

        # AWS Cognito
        if "cognito" in data:
            logger.info("Validating AWS Cognito provider configuration")
            config_dict["cognito"] = CognitoConfig(**data["cognito"])
            logger.info("AWS Cognito provider configuration validated successfully")

        # Google IAM
        if "google" in data:
            logger.info("Validating Google IAM provider configuration")
            config_dict["google"] = GoogleConfig(**data["google"])
            logger.info("Google IAM provider configuration validated successfully")

        # Okta
        if "okta" in data:
            logger.info("Validating Okta provider configuration")
            config_dict["okta"] = OktaConfig(**data["okta"])
            logger.info("Okta provider configuration validated successfully")

        # Auth0
        if "auth0" in data:
            logger.info("Validating Auth0 provider configuration")
            config_dict["auth0"] = Auth0Config(**data["auth0"])
            logger.info("Auth0 provider configuration validated successfully")

        # Keycloak
        if "keycloak" in data:
            logger.info("Validating Keycloak provider configuration")
            config_dict["keycloak"] = KeycloakConfig(**data["keycloak"])
            logger.info("Keycloak provider configuration validated successfully")

        # Cache
        has_cache_config = "cache" in data
        if has_cache_config:
            logger.info("Validating cache configuration")
            config_dict["cache"] = CacheConfig(**data["cache"])
            cache_backend = data.get("cache", {}).get("backend", "unknown")
            logger.info(
                "Cache configuration validated successfully",
                extra={"backend": cache_backend},
            )

        # Resolver settings
        if "resolver_type" in data:
            config_dict["resolver_type"] = data["resolver_type"]
            logger.info(
                "Resolver type configured",
                extra={"resolver_type": data["resolver_type"]},
            )
        if "resolver_merge_strategy" in data:
            config_dict["resolver_merge_strategy"] = data["resolver_merge_strategy"]
            logger.info(
                "Resolver merge strategy configured",
                extra={"merge_strategy": data["resolver_merge_strategy"]},
            )

        # Create final config instance
        config = DecoderConfig(**config_dict)

        logger.info(
            "EXIT: load_config_from_dict",
            extra={
                "status": "success",
                "providers_configured": len(providers_detected),
                "has_cache_config": has_cache_config,
            },
        )

        return config

    except ValidationError as e:
        # Sanitize errors to prevent secret leakage in logs
        sanitized_errors = _sanitize_validation_errors(e.errors())
        logger.log_error(
            Exception("Configuration validation failed"),
            extra={
                "status": "error",
                "error_count": len(e.errors()),
                "error_summary": str(sanitized_errors),  # Sanitized!
            },
        )
        raise

    except Exception as e:
        logger.log_error(
            e,
            extra={"status": "error", "exception_type": type(e).__name__},
        )
        raise


# =============================================================================
# Azure Configuration Loading
# =============================================================================


# Configuration file names to search for (in order of preference)
AZURE_CONFIG_FILE_NAMES = (
    "azure-auth.yaml",
    "azure-auth.yml",
    "azure-config.yaml",
    "azure-config.yml",
    "auth-config.yaml",
    "auth-config.yml",
)

# Environment variable names for Azure configuration
AZURE_ENV_PREFIX = "AZURE_"
AZURE_ENV_VARS = {
    "tenant_id": "AZURE_TENANT_ID",
    "client_id": "AZURE_CLIENT_ID",
    "client_secret": "AZURE_CLIENT_SECRET",
    "authority_url": "AZURE_AUTHORITY_URL",
    "scopes": "AZURE_SCOPES",  # Comma-separated
    "validate_issuer": "AZURE_VALIDATE_ISSUER",
    "validate_audience": "AZURE_VALIDATE_AUDIENCE",
    "clock_skew_seconds": "AZURE_CLOCK_SKEW_SECONDS",
    # Graph API settings
    "graph_api_enabled": "AZURE_GRAPH_API_ENABLED",
    "graph_api_timeout": "AZURE_GRAPH_API_TIMEOUT",
    "graph_api_max_retries": "AZURE_GRAPH_API_MAX_RETRIES",
    "graph_api_cache_ttl": "AZURE_GRAPH_API_CACHE_TTL",
    # Multi-tenant settings
    "multi_tenant_mode": "AZURE_MULTI_TENANT_MODE",
    "expected_tenants": "AZURE_EXPECTED_TENANTS",  # Comma-separated
    "verify_app_id": "AZURE_VERIFY_APP_ID",
    "expected_app_id": "AZURE_EXPECTED_APP_ID",
    # Roles mapping settings
    "roles_source": "AZURE_ROLES_SOURCE",
    "roles_claims_field": "AZURE_ROLES_CLAIMS_FIELD",
    "graph_app_roles": "AZURE_GRAPH_APP_ROLES",
    "graph_directory_roles": "AZURE_GRAPH_DIRECTORY_ROLES",
    "default_roles": "AZURE_DEFAULT_ROLES",  # Comma-separated
}

# =============================================================================
# Environment Variable Specification for extract_env_vars
# =============================================================================
# This specification uses secure_config's extract_env_vars for declarative
# environment variable extraction with SecretStr wrapping and validation.

# Azure AD environment variable spec for extract_env_vars
# Keys: env var names, Values: default (None = required, string = optional with default)
# Note: The extract_env_vars function treats None as "required" and string as "optional with default"
# For optional vars without defaults, we use empty string "" as the default
AZURE_ENV_VAR_SPEC: dict[str, Optional[str]] = {
    # Required - no defaults (None means required)
    "AZURE_TENANT_ID": None,
    "AZURE_CLIENT_ID": None,
    "AZURE_CLIENT_SECRET": None,
    # Optional with defaults (empty string means optional without default)
    "AZURE_AUTHORITY_URL": "",  # Auto-constructed from tenant_id if not set
    "AZURE_SCOPES": ".default",
    "AZURE_VALIDATE_ISSUER": "true",
    "AZURE_VALIDATE_AUDIENCE": "true",
    "AZURE_CLOCK_SKEW_SECONDS": "30",
    # Graph API (optional - empty string means optional)
    "AZURE_GRAPH_API_ENABLED": "",
    "AZURE_GRAPH_API_TIMEOUT": "",
    "AZURE_GRAPH_API_MAX_RETRIES": "",
    "AZURE_GRAPH_API_CACHE_TTL": "",
    # Multi-tenant (optional)
    "AZURE_MULTI_TENANT_MODE": "",
    "AZURE_EXPECTED_TENANTS": "",
    "AZURE_VERIFY_APP_ID": "",
    "AZURE_EXPECTED_APP_ID": "",
    # Roles mapping (optional)
    "AZURE_ROLES_SOURCE": "",
    "AZURE_ROLES_CLAIMS_FIELD": "",
    "AZURE_GRAPH_APP_ROLES": "",
    "AZURE_GRAPH_DIRECTORY_ROLES": "",
    "AZURE_DEFAULT_ROLES": "",
}

# Registry component name for Azure config
AZURE_CONFIG_COMPONENT = "neoaxios_fastapi_kit.auth.azure"


class ConfigurationError(Exception):
    """Error raised when configuration loading or validation fails.

    This exception provides detailed error messages with suggestions for
    resolving configuration issues.

    Attributes:
        message: Human-readable error description
        field: Configuration field that caused the error (if applicable)
        suggestion: Suggested fix for the error
        docs_url: URL to relevant documentation

    Example:
        raise ConfigurationError(
            message="Invalid tenant_id format",
            field="tenant_id",
            suggestion="Use a valid GUID or 'common', 'organizations', 'consumers'",
            docs_url="https://learn.microsoft.com/..."
        )
    """

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        suggestion: Optional[str] = None,
        docs_url: Optional[str] = None,
    ):
        self.message = message
        self.field = field
        self.suggestion = suggestion
        self.docs_url = docs_url

        # Build full error message
        parts = [message]
        if field:
            parts.append(f"Field: {field}")
        if suggestion:
            parts.append(f"Suggestion: {suggestion}")
        if docs_url:
            parts.append(f"Documentation: {docs_url}")

        super().__init__(" | ".join(parts))


@auto_trace(logger)
def load_azure_config_from_yaml(file_path: str) -> "AzureConfig":
    """Load Azure AD configuration from YAML file.

    Parses YAML file, resolves secrets (env:, file://), and validates
    the configuration against AzureConfig schema.

    Args:
        file_path: Path to YAML configuration file

    Returns:
        Validated AzureConfig instance

    Raises:
        FileNotFoundError: If file does not exist
        ConfigurationError: If configuration is invalid
        yaml.YAMLError: If YAML is malformed

    Example YAML:
        tenant_id: "550e8400-e29b-41d4-a716-446655440000"
        client_id: "660e8400-e29b-41d4-a716-446655440000"
        client_secret: "env:AZURE_CLIENT_SECRET"
        scopes:
          - "https://graph.microsoft.com/.default"
        validate_issuer: true
        validate_audience: true
        clock_skew_seconds: 30
        graph_api:
          enabled: true
          timeout_seconds: 15
          max_retries: 3
        multi_tenant:
          mode: "single"
        roles_mapping:
          source: "claims"
          default_roles:
            - "user"
    """
    # Import here to avoid circular imports

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Azure configuration file not found: {file_path}")

    logger.info("Loading Azure configuration from YAML", extra={"path": file_path})

    try:
        with path.open("r") as f:
            data = yaml.safe_load(f)

        if data is None:
            raise ConfigurationError(
                message="YAML file is empty",
                field=None,
                suggestion="Add Azure AD configuration to the file",
                docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
            )

        # Resolve secrets in configuration
        data = _resolve_secrets_in_dict(data)

        # Load configuration
        config = load_azure_config_from_dict(data)

        logger.info(
            "Azure configuration loaded successfully from YAML",
            extra={"path": file_path},
        )

        return config

    except yaml.YAMLError as e:
        logger.log_error(
            Exception(f"Failed to parse YAML: {e}"),
            extra={"path": file_path},
        )
        raise


@auto_trace(logger)
def load_azure_config_from_env() -> "AzureConfig":
    """Load Azure AD configuration from environment variables.

    Reads Azure AD configuration from environment variables with the AZURE_ prefix.
    Supports all AzureConfig fields including nested configurations.

    Environment Variables:
        Required:
            AZURE_TENANT_ID: Azure AD tenant ID (GUID or special value)
            AZURE_CLIENT_ID: Azure AD application (client) ID
            AZURE_CLIENT_SECRET: Client secret (supports env: and file:// prefixes)

        Optional:
            AZURE_AUTHORITY_URL: Custom authority URL (default: auto-constructed)
            AZURE_SCOPES: Comma-separated list of scopes
            AZURE_VALIDATE_ISSUER: "true" or "false" (default: true)
            AZURE_VALIDATE_AUDIENCE: "true" or "false" (default: true)
            AZURE_CLOCK_SKEW_SECONDS: Integer 5-60 (default: 30)

        Graph API:
            AZURE_GRAPH_API_ENABLED: "true" or "false"
            AZURE_GRAPH_API_TIMEOUT: Timeout in seconds
            AZURE_GRAPH_API_MAX_RETRIES: Max retry attempts
            AZURE_GRAPH_API_CACHE_TTL: Cache TTL in seconds

        Multi-Tenant:
            AZURE_MULTI_TENANT_MODE: "single" or "multi"
            AZURE_EXPECTED_TENANTS: Comma-separated tenant IDs
            AZURE_VERIFY_APP_ID: "true" or "false"
            AZURE_EXPECTED_APP_ID: Expected app ID

        Roles Mapping:
            AZURE_ROLES_SOURCE: "claims", "graph", or "both"
            AZURE_ROLES_CLAIMS_FIELD: Claim field name
            AZURE_GRAPH_APP_ROLES: "true" or "false"
            AZURE_GRAPH_DIRECTORY_ROLES: "true" or "false"
            AZURE_DEFAULT_ROLES: Comma-separated default roles

    Returns:
        Validated AzureConfig instance

    Raises:
        ConfigurationError: If required variables are missing or invalid
    """
    # Import here to avoid circular imports

    logger.info("Loading Azure configuration from environment variables")

    # Check required environment variables
    required_vars = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ConfigurationError(
            message=f"Missing required environment variables: {', '.join(missing)}",
            suggestion=f"Set the following environment variables: {', '.join(missing)}",
            docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
        )

    # Build configuration dictionary
    data: Dict[str, Any] = {
        "tenant_id": os.getenv("AZURE_TENANT_ID", ""),
        "client_id": os.getenv("AZURE_CLIENT_ID", ""),
        "client_secret": _resolve_secret(
            os.getenv("AZURE_CLIENT_SECRET", ""),
            field_name="client_secret"
        ),
    }

    # Optional authority URL
    if os.getenv("AZURE_AUTHORITY_URL"):
        data["authority_url"] = os.getenv("AZURE_AUTHORITY_URL")

    # Optional scopes (comma-separated)
    if os.getenv("AZURE_SCOPES"):
        data["scopes"] = [s.strip() for s in os.getenv("AZURE_SCOPES", "").split(",")]

    # Optional validation settings
    if os.getenv("AZURE_VALIDATE_ISSUER"):
        data["validate_issuer"] = os.getenv("AZURE_VALIDATE_ISSUER", "true").lower() == "true"

    if os.getenv("AZURE_VALIDATE_AUDIENCE"):
        data["validate_audience"] = os.getenv("AZURE_VALIDATE_AUDIENCE", "true").lower() == "true"

    if os.getenv("AZURE_CLOCK_SKEW_SECONDS"):
        try:
            data["clock_skew_seconds"] = int(os.getenv("AZURE_CLOCK_SKEW_SECONDS", "30"))
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_CLOCK_SKEW_SECONDS: {os.getenv('AZURE_CLOCK_SKEW_SECONDS')}",
                field="clock_skew_seconds",
                suggestion="Must be an integer between 5 and 60",
            )

    # Graph API configuration
    graph_api_data = _build_graph_api_config_from_env()
    if graph_api_data:
        data["graph_api"] = graph_api_data

    # Multi-tenant configuration
    multi_tenant_data = _build_multi_tenant_config_from_env()
    if multi_tenant_data:
        data["multi_tenant"] = multi_tenant_data

    # Roles mapping configuration
    roles_mapping_data = _build_roles_mapping_config_from_env()
    if roles_mapping_data:
        data["roles_mapping"] = roles_mapping_data

    # Load and validate configuration
    config = load_azure_config_from_dict(data)

    logger.info(
        "Azure configuration loaded successfully from environment",
        extra={"tenant_id": data["tenant_id"], "client_id": data["client_id"]},
    )

    return config


# =============================================================================
# Environment Variable Loading with extract_env_vars
# =============================================================================


@auto_trace(logger)
def _get_non_empty_env(env_vars: ExtractedEnvVars, key: str) -> Optional[str]:
    """Get env var value if set and non-empty.

    Helper function for extracted env vars that may have empty string defaults.

    Args:
        env_vars: ExtractedEnvVars container
        key: Lowercase key name

    Returns:
        The string value if non-empty, None otherwise
    """
    val = env_vars.get(key)
    if val is None:
        return None
    secret_val = val.get_secret_value()
    return secret_val if secret_val else None


@auto_trace(logger)
def load_azure_config_from_env_extracted() -> tuple["AzureConfig", ExtractedEnvVars]:
    """Load Azure AD configuration using secure_config's extract_env_vars.

    This is the recommended approach for loading Azure configuration from
    environment variables. It uses secure_config's declarative extraction
    which provides:
    - Automatic SecretStr wrapping for all values (defense in depth)
    - Configurable size limits and control character validation
    - Clear declaration of which env vars the component uses
    - Early failure if required vars are missing

    Returns:
        Tuple of (AzureConfig, ExtractedEnvVars) where ExtractedEnvVars
        provides secure access to all extracted environment variables.

    Raises:
        ConfigurationError: If required env vars are missing
        ConfigResolutionError: If env var validation fails (size, control chars)

    Example:
        # Load config with extracted env vars
        config, env_vars = load_azure_config_from_env_extracted()

        # Access config normally
        print(config.tenant_id)

        # Access extracted vars (all wrapped in SecretStr)
        api_key = env_vars.azure_client_secret.get_secret_value()
    """
    # Import here to avoid circular imports
    from neoaxios_fastapi_kit.auth.config.schemas import AzureConfig

    logger.info("Loading Azure configuration via extract_env_vars")

    try:
        # Extract all Azure environment variables using secure_config
        # This provides defense-in-depth validation (size limits, control chars)
        env_vars_dict = extract_env_vars(
            AZURE_ENV_VAR_SPEC,
            component=AZURE_CONFIG_COMPONENT,
            treat_empty_as_unset=True,
        )
        env_vars = ExtractedEnvVars(env_vars_dict)

        # Build configuration dictionary from extracted values
        # All values are SecretStr - unwrap for non-secret fields
        # Resolve file:// and env: prefixes for client_secret
        raw_client_secret = env_vars.azure_client_secret.get_secret_value()
        if raw_client_secret.startswith("file://") or raw_client_secret.startswith("env:"):
            resolved_secret = _resolve_secret(raw_client_secret, field_name="client_secret")
        else:
            resolved_secret = env_vars.azure_client_secret

        data: Dict[str, Any] = {
            "tenant_id": env_vars.azure_tenant_id.get_secret_value(),
            "client_id": env_vars.azure_client_id.get_secret_value(),
            "client_secret": resolved_secret,
        }

        # Optional authority URL
        authority_url = _get_non_empty_env(env_vars, "azure_authority_url")
        if authority_url:
            data["authority_url"] = authority_url

        # Scopes (comma-separated)
        scopes_str = _get_non_empty_env(env_vars, "azure_scopes")
        if scopes_str:
            data["scopes"] = [s.strip() for s in scopes_str.split(",") if s.strip()]

        # Validation settings
        validate_issuer_str = _get_non_empty_env(env_vars, "azure_validate_issuer")
        if validate_issuer_str:
            data["validate_issuer"] = validate_issuer_str.lower() == "true"

        validate_audience_str = _get_non_empty_env(env_vars, "azure_validate_audience")
        if validate_audience_str:
            data["validate_audience"] = validate_audience_str.lower() == "true"

        clock_skew_str = _get_non_empty_env(env_vars, "azure_clock_skew_seconds")
        if clock_skew_str:
            try:
                data["clock_skew_seconds"] = int(clock_skew_str)
            except ValueError:
                raise ConfigurationError(
                    message=f"Invalid AZURE_CLOCK_SKEW_SECONDS: {clock_skew_str}",
                    field="clock_skew_seconds",
                    suggestion="Must be an integer between 5 and 60",
                )

        # Build nested configs using helper functions that read from env_vars
        graph_api_data = _build_graph_api_config_from_extracted(env_vars)
        if graph_api_data:
            data["graph_api"] = graph_api_data

        multi_tenant_data = _build_multi_tenant_config_from_extracted(env_vars)
        if multi_tenant_data:
            data["multi_tenant"] = multi_tenant_data

        roles_mapping_data = _build_roles_mapping_config_from_extracted(env_vars)
        if roles_mapping_data:
            data["roles_mapping"] = roles_mapping_data

        # Create AzureConfig instance
        config = AzureConfig(**data)

        logger.info(
            "Azure configuration loaded successfully via extract_env_vars",
            extra={
                "tenant_id": data["tenant_id"],
                "client_id": data["client_id"],
                "env_vars_extracted": len(env_vars_dict),
            },
        )

        return config, env_vars

    except ConfigResolutionError as e:
        # Convert to ConfigurationError for consistent API
        raise ConfigurationError(
            message=str(e),
            field=getattr(e, "field", None),
            suggestion="Check environment variable values and ensure they meet validation requirements",
        ) from e


@auto_trace(logger)  # Builds Graph API config from extracted env vars
def _build_graph_api_config_from_extracted(env_vars: ExtractedEnvVars) -> Optional[Dict[str, Any]]:
    """Build Graph API configuration from extracted environment variables.

    Args:
        env_vars: ExtractedEnvVars container with extracted values

    Returns:
        Dictionary of Graph API configuration, or None if not configured
    """
    # Check if any Graph API settings are present
    graph_enabled = _get_non_empty_env(env_vars, "azure_graph_api_enabled")
    graph_timeout = _get_non_empty_env(env_vars, "azure_graph_api_timeout")
    graph_retries = _get_non_empty_env(env_vars, "azure_graph_api_max_retries")
    graph_cache = _get_non_empty_env(env_vars, "azure_graph_api_cache_ttl")

    if not any([graph_enabled, graph_timeout, graph_retries, graph_cache]):
        return None

    data: Dict[str, Any] = {}

    if graph_enabled:
        data["enabled"] = graph_enabled.lower() == "true"

    if graph_timeout:
        try:
            data["timeout_seconds"] = int(graph_timeout)
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_TIMEOUT: {graph_timeout}",
                field="graph_api.timeout_seconds",
                suggestion="Must be an integer between 1 and 60",
            )

    if graph_retries:
        try:
            data["max_retries"] = int(graph_retries)
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_MAX_RETRIES: {graph_retries}",
                field="graph_api.max_retries",
                suggestion="Must be an integer between 0 and 5",
            )

    if graph_cache:
        try:
            data["cache_ttl_seconds"] = int(graph_cache)
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_CACHE_TTL: {graph_cache}",
                field="graph_api.cache_ttl_seconds",
                suggestion="Must be an integer between 300 and 86400",
            )

    return data if data else None


@auto_trace(logger)  # Builds multi-tenant config from extracted env vars
def _build_multi_tenant_config_from_extracted(env_vars: ExtractedEnvVars) -> Optional[Dict[str, Any]]:
    """Build multi-tenant configuration from extracted environment variables.

    Args:
        env_vars: ExtractedEnvVars container with extracted values

    Returns:
        Dictionary of multi-tenant configuration, or None if not configured
    """
    mode = _get_non_empty_env(env_vars, "azure_multi_tenant_mode")
    expected_tenants = _get_non_empty_env(env_vars, "azure_expected_tenants")
    verify_app_id = _get_non_empty_env(env_vars, "azure_verify_app_id")
    expected_app_id = _get_non_empty_env(env_vars, "azure_expected_app_id")

    if not any([mode, expected_tenants, verify_app_id, expected_app_id]):
        return None

    data: Dict[str, Any] = {}

    if mode:
        mode_value = mode.lower()
        if mode_value not in ("single", "multi"):
            raise ConfigurationError(
                message=f"Invalid AZURE_MULTI_TENANT_MODE: {mode_value}",
                field="multi_tenant.mode",
                suggestion="Must be 'single' or 'multi'",
            )
        data["mode"] = mode_value

    if expected_tenants:
        data["expected_tenants"] = [
            t.strip() for t in expected_tenants.split(",")
            if t.strip()
        ]

    if verify_app_id:
        data["verify_app_id"] = verify_app_id.lower() == "true"

    if expected_app_id:
        data["expected_app_id"] = expected_app_id

    return data if data else None


@auto_trace(logger)  # Builds roles mapping config from extracted env vars
def _build_roles_mapping_config_from_extracted(env_vars: ExtractedEnvVars) -> Optional[Dict[str, Any]]:
    """Build roles mapping configuration from extracted environment variables.

    Args:
        env_vars: ExtractedEnvVars container with extracted values

    Returns:
        Dictionary of roles mapping configuration, or None if not configured
    """
    source = _get_non_empty_env(env_vars, "azure_roles_source")
    claims_field = _get_non_empty_env(env_vars, "azure_roles_claims_field")
    app_roles = _get_non_empty_env(env_vars, "azure_graph_app_roles")
    dir_roles = _get_non_empty_env(env_vars, "azure_graph_directory_roles")
    default_roles = _get_non_empty_env(env_vars, "azure_default_roles")

    if not any([source, claims_field, app_roles, dir_roles, default_roles]):
        return None

    data: Dict[str, Any] = {}

    if source:
        source_value = source.lower()
        if source_value not in ("claims", "graph", "both"):
            raise ConfigurationError(
                message=f"Invalid AZURE_ROLES_SOURCE: {source_value}",
                field="roles_mapping.source",
                suggestion="Must be 'claims', 'graph', or 'both'",
            )
        data["source"] = source_value

    if claims_field:
        data["claims_field"] = claims_field

    if app_roles:
        data["graph_app_roles"] = app_roles.lower() == "true"

    if dir_roles:
        data["graph_directory_roles"] = dir_roles.lower() == "true"

    if default_roles:
        data["default_roles"] = [
            r.strip() for r in default_roles.split(",")
            if r.strip()
        ]

    return data if data else None


@auto_trace(logger)  # Builds Graph API config from env vars
def _build_graph_api_config_from_env() -> Optional[Dict[str, Any]]:
    """Build Graph API configuration from environment variables.

    Returns:
        Dictionary of Graph API configuration, or None if not configured
    """
    # Check if any Graph API settings are present
    graph_env_vars = [
        "AZURE_GRAPH_API_ENABLED",
        "AZURE_GRAPH_API_TIMEOUT",
        "AZURE_GRAPH_API_MAX_RETRIES",
        "AZURE_GRAPH_API_CACHE_TTL",
    ]
    if not any(os.getenv(var) for var in graph_env_vars):
        return None

    data: Dict[str, Any] = {}

    if os.getenv("AZURE_GRAPH_API_ENABLED"):
        data["enabled"] = os.getenv("AZURE_GRAPH_API_ENABLED", "true").lower() == "true"

    if os.getenv("AZURE_GRAPH_API_TIMEOUT"):
        try:
            data["timeout_seconds"] = int(os.getenv("AZURE_GRAPH_API_TIMEOUT", "10"))
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_TIMEOUT: {os.getenv('AZURE_GRAPH_API_TIMEOUT')}",
                field="graph_api.timeout_seconds",
                suggestion="Must be an integer between 1 and 60",
            )

    if os.getenv("AZURE_GRAPH_API_MAX_RETRIES"):
        try:
            data["max_retries"] = int(os.getenv("AZURE_GRAPH_API_MAX_RETRIES", "3"))
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_MAX_RETRIES: {os.getenv('AZURE_GRAPH_API_MAX_RETRIES')}",
                field="graph_api.max_retries",
                suggestion="Must be an integer between 0 and 5",
            )

    if os.getenv("AZURE_GRAPH_API_CACHE_TTL"):
        try:
            data["cache_ttl_seconds"] = int(os.getenv("AZURE_GRAPH_API_CACHE_TTL", "3600"))
        except ValueError:
            raise ConfigurationError(
                message=f"Invalid AZURE_GRAPH_API_CACHE_TTL: {os.getenv('AZURE_GRAPH_API_CACHE_TTL')}",
                field="graph_api.cache_ttl_seconds",
                suggestion="Must be an integer between 300 and 86400",
            )

    return data if data else None


@auto_trace(logger)  # Builds multi-tenant config from env vars
def _build_multi_tenant_config_from_env() -> Optional[Dict[str, Any]]:
    """Build multi-tenant configuration from environment variables.

    Returns:
        Dictionary of multi-tenant configuration, or None if not configured
    """
    # Check if any multi-tenant settings are present
    multi_tenant_env_vars = [
        "AZURE_MULTI_TENANT_MODE",
        "AZURE_EXPECTED_TENANTS",
        "AZURE_VERIFY_APP_ID",
        "AZURE_EXPECTED_APP_ID",
    ]
    if not any(os.getenv(var) for var in multi_tenant_env_vars):
        return None

    data: Dict[str, Any] = {}

    if os.getenv("AZURE_MULTI_TENANT_MODE"):
        mode = os.getenv("AZURE_MULTI_TENANT_MODE", "single").lower()
        if mode not in ("single", "multi"):
            raise ConfigurationError(
                message=f"Invalid AZURE_MULTI_TENANT_MODE: {mode}",
                field="multi_tenant.mode",
                suggestion="Must be 'single' or 'multi'",
            )
        data["mode"] = mode

    if os.getenv("AZURE_EXPECTED_TENANTS"):
        data["expected_tenants"] = [
            t.strip() for t in os.getenv("AZURE_EXPECTED_TENANTS", "").split(",")
            if t.strip()
        ]

    if os.getenv("AZURE_VERIFY_APP_ID"):
        data["verify_app_id"] = os.getenv("AZURE_VERIFY_APP_ID", "false").lower() == "true"

    if os.getenv("AZURE_EXPECTED_APP_ID"):
        data["expected_app_id"] = os.getenv("AZURE_EXPECTED_APP_ID")

    return data if data else None


@auto_trace(logger)  # Builds roles mapping config from env vars
def _build_roles_mapping_config_from_env() -> Optional[Dict[str, Any]]:
    """Build roles mapping configuration from environment variables.

    Returns:
        Dictionary of roles mapping configuration, or None if not configured
    """
    # Check if any roles mapping settings are present
    roles_env_vars = [
        "AZURE_ROLES_SOURCE",
        "AZURE_ROLES_CLAIMS_FIELD",
        "AZURE_GRAPH_APP_ROLES",
        "AZURE_GRAPH_DIRECTORY_ROLES",
        "AZURE_DEFAULT_ROLES",
    ]
    if not any(os.getenv(var) for var in roles_env_vars):
        return None

    data: Dict[str, Any] = {}

    if os.getenv("AZURE_ROLES_SOURCE"):
        source = os.getenv("AZURE_ROLES_SOURCE", "claims").lower()
        if source not in ("claims", "graph", "both"):
            raise ConfigurationError(
                message=f"Invalid AZURE_ROLES_SOURCE: {source}",
                field="roles_mapping.source",
                suggestion="Must be 'claims', 'graph', or 'both'",
            )
        data["source"] = source

    if os.getenv("AZURE_ROLES_CLAIMS_FIELD"):
        data["claims_field"] = os.getenv("AZURE_ROLES_CLAIMS_FIELD")

    if os.getenv("AZURE_GRAPH_APP_ROLES"):
        data["graph_app_roles"] = os.getenv("AZURE_GRAPH_APP_ROLES", "false").lower() == "true"

    if os.getenv("AZURE_GRAPH_DIRECTORY_ROLES"):
        data["graph_directory_roles"] = os.getenv("AZURE_GRAPH_DIRECTORY_ROLES", "false").lower() == "true"

    if os.getenv("AZURE_DEFAULT_ROLES"):
        data["default_roles"] = [
            r.strip() for r in os.getenv("AZURE_DEFAULT_ROLES", "").split(",")
            if r.strip()
        ]

    return data if data else None


@auto_trace(logger, include_args=False)
def load_azure_config_from_dict(data: Dict[str, Any]) -> "AzureConfig":
    """Load Azure AD configuration from dictionary.

    SECURITY: Arguments are NOT logged by @auto_trace due to sensitivity of
    configuration data that may contain credentials.

    Validates dictionary structure and creates AzureConfig instance with nested
    configurations (GraphAPIConfig, MultiTenantConfig, RolesMappingConfig).

    Args:
        data: Configuration dictionary containing Azure AD settings

    Returns:
        Validated AzureConfig instance

    Raises:
        ValidationError: If configuration is invalid
        ConfigurationError: If configuration structure is wrong

    Example:
        config = load_azure_config_from_dict({
            "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
            "client_id": "660e8400-e29b-41d4-a716-446655440000",
            "client_secret": "my-secret",
            "graph_api": {
                "enabled": True,
                "timeout_seconds": 15
            }
        })
    """
    # Import here to avoid circular imports
    from neoaxios_fastapi_kit.auth.config.schemas import (
        AzureConfig,
        GraphAPIConfig,
        MultiTenantConfig,
        RolesMappingConfig,
    )

    logger.info("ENTRY: load_azure_config_from_dict")

    try:
        # Build nested config objects if present in data
        config_data: Dict[str, Any] = {}

        # Required fields
        if "tenant_id" not in data:
            raise ConfigurationError(
                message="Missing required field: tenant_id",
                field="tenant_id",
                suggestion="Provide Azure AD tenant ID (GUID or special value)",
                docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
            )
        config_data["tenant_id"] = data["tenant_id"]

        if "client_id" not in data:
            raise ConfigurationError(
                message="Missing required field: client_id",
                field="client_id",
                suggestion="Provide Azure AD application (client) ID",
                docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
            )
        config_data["client_id"] = data["client_id"]

        if "client_secret" not in data:
            raise ConfigurationError(
                message="Missing required field: client_secret",
                field="client_secret",
                suggestion="Provide Azure AD client secret (use env: or file:// for security)",
                docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
            )
        config_data["client_secret"] = data["client_secret"]

        # Optional fields
        if "authority_url" in data:
            config_data["authority_url"] = data["authority_url"]

        if "scopes" in data:
            config_data["scopes"] = data["scopes"]

        if "validate_issuer" in data:
            config_data["validate_issuer"] = data["validate_issuer"]

        if "validate_audience" in data:
            config_data["validate_audience"] = data["validate_audience"]

        if "clock_skew_seconds" in data:
            config_data["clock_skew_seconds"] = data["clock_skew_seconds"]

        # Nested Graph API configuration
        if "graph_api" in data:
            if isinstance(data["graph_api"], dict):
                logger.info("Validating Graph API configuration")
                config_data["graph_api"] = GraphAPIConfig(**data["graph_api"])
                logger.info("Graph API configuration validated successfully")
            elif isinstance(data["graph_api"], GraphAPIConfig):
                config_data["graph_api"] = data["graph_api"]

        # Nested Multi-Tenant configuration
        if "multi_tenant" in data:
            if isinstance(data["multi_tenant"], dict):
                logger.info("Validating Multi-Tenant configuration")
                config_data["multi_tenant"] = MultiTenantConfig(**data["multi_tenant"])
                logger.info("Multi-Tenant configuration validated successfully")
            elif isinstance(data["multi_tenant"], MultiTenantConfig):
                config_data["multi_tenant"] = data["multi_tenant"]

        # Nested Roles Mapping configuration
        if "roles_mapping" in data:
            if isinstance(data["roles_mapping"], dict):
                logger.info("Validating Roles Mapping configuration")
                config_data["roles_mapping"] = RolesMappingConfig(**data["roles_mapping"])
                logger.info("Roles Mapping configuration validated successfully")
            elif isinstance(data["roles_mapping"], RolesMappingConfig):
                config_data["roles_mapping"] = data["roles_mapping"]

        # Create AzureConfig instance
        config = AzureConfig(**config_data)

        logger.info(
            "EXIT: load_azure_config_from_dict",
            extra={
                "status": "success",
                "tenant_id": config.tenant_id,
                "has_graph_api": config.graph_api is not None,
                "has_multi_tenant": config.multi_tenant is not None,
                "has_roles_mapping": config.roles_mapping is not None,
            },
        )

        return config

    except ValidationError as e:
        logger.log_error(
            Exception(f"Azure configuration validation failed: {e}"),
            extra={
                "status": "error",
                "error_count": len(e.errors()),
                "error_summary": str(e.errors()),
            },
        )
        raise

    except ConfigurationError:
        raise

    except Exception as e:
        logger.log_error(
            e,
            extra={"status": "error", "exception_type": type(e).__name__},
        )
        raise


@auto_trace(logger)
def discover_azure_config_path() -> Optional[str]:
    """Discover Azure configuration file path using hierarchical search.

    Searches for configuration files in the following order (first found wins):
    1. Explicit path via AZURE_CONFIG_PATH environment variable
    2. Current working directory
    3. Project root (directory containing pyproject.toml)
    4. Package root (relative to this module)
    5. User home directory (~/.config/azure/)
    6. System directory (/etc/azure/)

    File names searched (in order):
    - azure-auth.yaml
    - azure-auth.yml
    - azure-config.yaml
    - azure-config.yml
    - auth-config.yaml
    - auth-config.yml

    Returns:
        Path to configuration file, or None if not found
    """
    # Check explicit path first
    explicit_path = os.getenv("AZURE_CONFIG_PATH")
    if explicit_path:
        if Path(explicit_path).exists():
            logger.info(
                "Using explicit Azure config path",
                extra={"path": explicit_path},
            )
            return explicit_path
        else:
            logger.warning(
                "AZURE_CONFIG_PATH is set but file does not exist",
                extra={"path": explicit_path},
            )

    # Define search directories in order of precedence
    search_dirs = [
        Path.cwd(),  # Current working directory
        _find_project_root(),  # Project root
        Path(__file__).parent.parent.parent.parent,  # Package root
        Path.home() / ".config" / "azure",  # User config
        Path("/etc/azure"),  # System config
    ]

    # Search for config files
    for search_dir in search_dirs:
        if search_dir is None:
            continue
        for filename in AZURE_CONFIG_FILE_NAMES:
            config_path = search_dir / filename
            if config_path.exists():
                logger.info(
                    "Discovered Azure config file",
                    extra={"path": str(config_path)},
                )
                return str(config_path)

    logger.info("No Azure configuration file found in search paths")
    return None


@auto_trace(logger)  # Finds project root by looking for pyproject.toml
def _find_project_root() -> Optional[Path]:
    """Find project root by looking for pyproject.toml.

    Returns:
        Path to project root, or None if not found
    """
    current = Path.cwd()
    while current != current.parent:
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    return None


@auto_trace(logger)
def load_azure_config(
    file_path: Optional[str] = None,
    use_env: bool = True,
    use_discovery: bool = False,  # SECURITY: Disabled by default (CWE-426 prevention)
) -> "AzureConfig":
    """Load Azure configuration securely from explicit sources.

    This is the primary entry point for loading Azure configuration.
    It supports multiple sources with clear precedence:

    1. Explicit file path (if provided)
    2. Environment variables (if use_env=True) - RECOMMENDED
    3. Discovered configuration file (if use_discovery=True) - DISABLED BY DEFAULT

    Security:
        - Auto-discovery is DISABLED by default to prevent untrusted search path attacks (CWE-426)
        - Environment variables are the recommended configuration source
        - File paths must be explicit when used

    Args:
        file_path: Explicit path to configuration file (highest priority)
        use_env: Whether to try loading from environment variables (default: True)
        use_discovery: Whether to try discovering configuration file (default: False, INSECURE)

    Returns:
        Validated AzureConfig instance

    Raises:
        ConfigurationError: If no configuration source succeeds

    Example:
        # Load from environment variables (RECOMMENDED)
        config = load_azure_config()

        # Use explicit file
        config = load_azure_config(file_path="/etc/azure/config.yaml")

        # Enable auto-discovery (NOT RECOMMENDED for production)
        config = load_azure_config(use_discovery=True)
    """
    logger.info(
        "Loading Azure configuration",
        extra={
            "file_path": file_path,
            "use_env": use_env,
            "use_discovery": use_discovery,
        },
    )

    # 1. Try explicit file path
    if file_path:
        logger.info("Attempting to load from explicit file path", extra={"path": file_path})
        return load_azure_config_from_yaml(file_path)

    # 2. Try environment variables
    if use_env:
        # Check if required environment variables are set
        required_vars = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
        if all(os.getenv(var) for var in required_vars):
            logger.info("Attempting to load from environment variables")
            return load_azure_config_from_env()

    # 3. Try discovery (DISABLED BY DEFAULT for security)
    if use_discovery:
        logger.warning(
            "Auto-discovery enabled. This is NOT RECOMMENDED for production "
            "due to untrusted search path risk (CWE-426). "
            "Use explicit file_path or environment variables instead.",
            extra={"use_discovery": True},
        )
        discovered_path = discover_azure_config_path()
        if discovered_path:
            logger.info("Attempting to load from discovered file", extra={"path": discovered_path})
            return load_azure_config_from_yaml(discovered_path)

    # No configuration found
    raise ConfigurationError(
        message="No Azure configuration found",
        suggestion=(
            "Provide configuration via one of: "
            "(1) AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET environment variables (RECOMMENDED), "
            "(2) file_path argument with explicit path"
        ),
        docs_url="https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
    )



@auto_trace(logger)
def clear_azure_config_cache() -> None:
    """Clear the cached Azure configuration.

    This is primarily useful for testing to ensure a clean state.
    Delegates to clear_azure_config_registry().

    Example:
        # In test teardown
        clear_azure_config_cache()
    """
    clear_azure_config_registry()


# =============================================================================
# Registry-Based Configuration
# =============================================================================
# These functions use secure_config's registry pattern for centralized
# configuration management with thread-safe, idempotent registration.


@auto_trace(logger)
def get_azure_config_registry() -> "AzureConfig":
    """Get Azure configuration from neoaxios_secure_config registry.

    Uses idempotent, thread-safe configuration loading.
    The first call loads the config from environment variables, subsequent
    calls return the cached instance.

    This is the recommended way to access Azure configuration as it:
    - Provides centralized configuration management
    - Is thread-safe by design
    - Supports configuration reloading via reload_azure_config_registry()
    - Supports rollback via rollback_azure_config_registry()

    Returns:
        AzureConfig instance from registry

    Raises:
        ConfigurationError: If required env vars are missing

    Example:
        # Get config (loads on first call, cached thereafter)
        config = get_azure_config_registry()

        # Access configuration
        print(config.tenant_id)
        print(config.client_secret)  # Masked SecretStr

    """
    from neoaxios_fastapi_kit.auth.config.schemas import AzureConfig

    logger.debug("Getting Azure configuration from registry")

    # Use ensure_registered_with_loader for idempotent, thread-safe registration
    # The loader callback is stored and used for reload operations
    return ensure_registered_with_loader(
        component=AZURE_CONFIG_COMPONENT,
        schema=AzureConfig,
        loader=load_azure_config_from_env_extracted,
    )


@auto_trace(logger)
def get_azure_env_vars_registry() -> ExtractedEnvVars:
    """Get extracted Azure environment variables from neoaxios_secure_config registry.

    Returns the ExtractedEnvVars container with all Azure-related environment
    variables, all wrapped as SecretStr for security.

    Returns:
        ExtractedEnvVars container

    Raises:
        ConfigurationError: If Azure config not yet loaded

    Example:
        # Get extracted env vars
        env_vars = get_azure_env_vars_registry()

        # Access specific var (all SecretStr)
        secret = env_vars.azure_client_secret.get_secret_value()

        # List all vars
        print(env_vars.keys())

    """
    # Ensure config is loaded
    get_azure_config_registry()

    # Get from registry
    env_vars = get_extracted_env_vars(AZURE_CONFIG_COMPONENT)
    if env_vars is None:
        raise ConfigurationError(
            message="Azure configuration not loaded or missing env vars",
            suggestion="Call get_azure_config_registry() first to load configuration",
        )

    return env_vars


@auto_trace(logger)
def reload_azure_config_registry(
    drift_policy: Literal["block", "warn", "allow"] = "warn",
) -> ReloadResult:
    """Reload Azure configuration in the registry with drift detection.

    Reloads configuration from environment variables with drift detection
    and rollback support. Uses secure_config's built-in drift detection
    which compares static vs refreshable fields.

    Args:
        drift_policy: How to handle static field changes:
            - "block": Raise ConfigDriftError if static fields changed
            - "warn": Log warning but allow reload (default)
            - "allow": Silently allow all changes

    Returns:
        ReloadResult with:
            - config: The reloaded AzureConfig instance
            - has_drift: Whether static fields changed
            - drift_detected: Dict of changed static fields
            - has_refreshed: Whether refreshable fields changed
            - refreshed_fields: List of changed refreshable field names
            - previous_config: The config before reload (for rollback)

    Raises:
        ConfigDriftError: If drift_policy="block" and static fields changed
        ConfigurationError: If reload fails or component not registered

    Example:
        # After rotating AZURE_CLIENT_SECRET env var
        result = reload_azure_config_registry()
        if result.has_drift:
            logger.warning(f"Static fields changed: {result.drift_detected}")
        if result.has_refreshed:
            logger.info(f"Refreshed fields: {result.refreshed_fields}")

        # To block on drift (security-sensitive environments)
        result = reload_azure_config_registry(drift_policy="block")

    """
    logger.info(
        "Reloading Azure configuration in registry",
        extra={"drift_policy": drift_policy},
    )

    # Use secure_config's reload_config which now supports loader callbacks
    # The loader was stored during registration and will be used automatically
    result = reload_config(
        component=AZURE_CONFIG_COMPONENT,
        drift_policy=drift_policy,
    )

    logger.info(
        "Azure configuration reloaded in registry",
        extra={
            "tenant_id": result.config.tenant_id,
            "client_id": result.config.client_id,
            "has_drift": result.has_drift,
            "drift_detected": list(result.drift_detected.keys()) if result.drift_detected else [],
            "has_refreshed": result.has_refreshed,
            "refreshed_fields": result.refreshed_fields,
        },
    )

    return result


@auto_trace(logger)
def rollback_azure_config_registry() -> "AzureConfig":
    """Rollback Azure configuration to the previous version.

    Restores the Azure configuration to its state before the last
    successful reload. Only one level of rollback is supported.

    Returns:
        The restored AzureConfig instance

    Raises:
        NoPreviousConfigError: If no previous configuration exists
        ComponentNotFoundError: If Azure config not registered

    Example:
        # After a bad reload
        result = reload_azure_config_registry()
        if result.has_drift:
            # Unexpected drift - rollback
            previous = rollback_azure_config_registry()
            logger.info("Rolled back to previous configuration")

    """
    logger.info("Rolling back Azure configuration in registry")

    config = rollback_config(AZURE_CONFIG_COMPONENT)

    logger.info(
        "Azure configuration rolled back",
        extra={"tenant_id": config.tenant_id, "client_id": config.client_id},
    )

    return config


@auto_trace(logger)
def has_azure_config_rollback() -> bool:
    """Check if Azure configuration rollback is available.

    Returns:
        True if a previous configuration exists for rollback

    Example:
        if has_azure_config_rollback():
            previous = rollback_azure_config_registry()
    """
    return has_previous_config(AZURE_CONFIG_COMPONENT)


@auto_trace(logger)
def clear_azure_config_registry() -> None:
    """Clear Azure configuration from the registry.

    Removes the Azure configuration from secure_config's registry,
    allowing fresh loading on next access.

    Example:
        # In test teardown
        clear_azure_config_registry()
    """
    from neoaxios_secure_config.registry import _unregister
    from neoaxios_secure_config import ComponentNotFoundError

    try:
        _unregister(AZURE_CONFIG_COMPONENT)
        logger.info("Azure configuration cleared from registry")
    except ComponentNotFoundError:
        # Already cleared or never registered - OK for tests
        logger.debug("Azure configuration not in registry, nothing to clear")


# =============================================================================
# Azure Decoder Factory Function
# =============================================================================


@auto_trace(logger)
def create_azure_decoder(
    config: Optional["AzureConfig"] = None,
    file_path: Optional[str] = None,
) -> "BaseDecoder":
    """Factory function to create an Azure AD token decoder.

    Creates a fully configured Azure AD decoder with all components wired:
    - Token validation with issuer/audience checks
    - Optional Graph API client for role/group fetching
    - Multi-tenant support if configured
    - Role mapping from claims and/or Graph API

    This is the recommended way to create an Azure AD decoder, as it ensures
    all configuration is validated before creating the decoder instance.

    Args:
        config: Pre-loaded AzureConfig instance (optional)
        file_path: Path to configuration file (used if config not provided)

    Returns:
        Configured BaseDecoder instance for Azure AD tokens

    Raises:
        ConfigurationError: If configuration is invalid or wiring fails

    Example:
        # Using auto-discovery
        decoder = create_azure_decoder()

        # Using explicit config
        config = load_azure_config_from_yaml("/etc/azure/config.yaml")
        decoder = create_azure_decoder(config=config)

        # Using file path
        decoder = create_azure_decoder(file_path="/etc/azure/config.yaml")

        # Use the decoder
        identity = await decoder.decode(token)
    """
    # Import here to avoid circular imports

    logger.info(
        "Creating Azure AD decoder",
        extra={
            "has_config": config is not None,
            "file_path": file_path,
        },
    )

    # Load configuration if not provided
    if config is None:
        config = load_azure_config(file_path=file_path)

    # Log configuration summary (no secrets)
    logger.info(
        "Azure AD decoder configuration",
        extra={
            "tenant_id": config.tenant_id,
            "client_id": config.client_id,
            "authority_url": config.authority_url,
            "validate_issuer": config.validate_issuer,
            "validate_audience": config.validate_audience,
            "graph_api_enabled": config.graph_api.enabled if config.graph_api else False,
            "multi_tenant_mode": config.multi_tenant.mode if config.multi_tenant else "single",
            "roles_source": config.roles_mapping.source if config.roles_mapping else "claims",
        },
    )

    # Import factory function from azure.py
    from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure import (
        create_azure_decoder as create_azure_decoder_factory,
    )

    # Extract allowed_tenants from multi-tenant configuration
    allowed_tenants = None
    if config.multi_tenant and config.multi_tenant.expected_tenants:
        allowed_tenants = frozenset(
            t.lower() for t in config.multi_tenant.expected_tenants
        )

    # Extract Graph API configuration
    graph_client_id = None
    graph_client_secret = None
    enable_graph_api = False
    graph_cache_ttl_seconds = 3600

    if config.graph_api and config.graph_api.enabled:
        enable_graph_api = True
        graph_client_id = config.graph_api.client_id
        graph_client_secret = config.graph_api.client_secret
        if config.graph_api.token_cache_ttl_seconds:
            graph_cache_ttl_seconds = config.graph_api.token_cache_ttl_seconds

    # Extract custom role mappings
    custom_role_mappings = None
    if config.roles_mapping and config.roles_mapping.directory_role_mappings:
        custom_role_mappings = config.roles_mapping.directory_role_mappings

    # Create and return the decoder using factory
    # Use explicit audience if set, otherwise default to client_id (Azure AD convention)
    audience = config.audience or config.client_id

    decoder = create_azure_decoder_factory(
        tenant_id=config.tenant_id,
        client_id=config.client_id,
        client_secret=config.client_secret.get_secret_value()
        if config.client_secret
        else None,
        audience=audience,
        allowed_tenants=allowed_tenants,
        api_version=config.api_version,
        clock_skew_seconds=config.clock_skew_seconds,
        enable_graph_api=enable_graph_api,
        graph_client_id=graph_client_id,
        graph_client_secret=graph_client_secret.get_secret_value()
        if graph_client_secret
        else None,
        graph_cache_ttl_seconds=graph_cache_ttl_seconds,
        custom_role_mappings=custom_role_mappings,
    )

    logger.info(
        "Azure AD decoder created successfully",
        extra={
            "decoder_type": type(decoder).__name__,
            "tenant_id": config.tenant_id,
            "graph_api_enabled": enable_graph_api,
            "multi_tenant": allowed_tenants is not None,
        },
    )

    return decoder
