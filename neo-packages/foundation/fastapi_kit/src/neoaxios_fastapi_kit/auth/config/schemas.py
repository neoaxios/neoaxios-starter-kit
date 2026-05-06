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

"""Pydantic configuration schemas for identity provider decoders.

Defines configuration models for all supported identity providers:
- JWT: Generic JWT token decoder
- OIDC: Generic OpenID Connect provider
- Azure AD: Microsoft Azure Active Directory (comprehensive configuration)
- Cognito: AWS Cognito
- Google: Google IAM

Each schema includes validation, defaults, and secrets management support.

Azure AD Configuration Features:
- Complete AzureConfig with nested Graph API, Multi-Tenant, and Roles Mapping configs
- SecretStr for client_secret to prevent accidental logging
- GUID validation for tenant_id with support for special values (common, organizations, consumers)
- Automatic authority_url construction from tenant_id
- Comprehensive validators for all security-critical fields

Usage:
    from neoaxios_fastapi_kit.auth.config import DecoderConfig, AzureConfig

    # Azure AD configuration with SecretStr for security
    config = DecoderConfig(
        azure=AzureConfig(
            tenant_id="your-tenant-id",
            client_id="your-client-id",
            client_secret="env:AZURE_CLIENT_SECRET"  # SecretStr from env var
        )
    )

    # Comprehensive Azure configuration with Graph API and multi-tenant support
    from neoaxios_fastapi_kit.auth.config import (
        AzureConfig, GraphAPIConfig, MultiTenantConfig, RolesMappingConfig
    )

    azure_config = AzureConfig(
        tenant_id="550e8400-e29b-41d4-a716-446655440000",
        client_id="660e8400-e29b-41d4-a716-446655440000",
        client_secret="env:AZURE_CLIENT_SECRET",
        scopes=["https://graph.microsoft.com/.default"],
        graph_api=GraphAPIConfig(enabled=True, timeout_seconds=10),
        multi_tenant=MultiTenantConfig(mode="multi", expected_tenants=["tenant1", "tenant2"]),
        roles_mapping=RolesMappingConfig(source="both", graph_app_roles=True)
    )

"""

import math
import re
import unicodedata
from collections import Counter
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Self

from pydantic import Field, SecretStr, field_validator, model_validator

# SecureSchema is the single base class for all secure configuration schemas
# It provides: frozen models, extra="forbid", to_safe_dict(), __repr__/__str__ masking
from neoaxios_secure_config import SecureSchema

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_secure_cache.defaults import CACHE_TTL_LONG, CACHE_TTL_MEDIUM, HTTPX_MAX_RETRIES

from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS

logger = get_telemetry(__name__)


# =============================================================================
# Constants for Azure AD Configuration
# =============================================================================

# GUID regex pattern for Azure AD tenant IDs
AZURE_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Special tenant ID values that Azure AD accepts
AZURE_SPECIAL_TENANT_VALUES = frozenset({
    "common",          # Multi-tenant (any Azure AD tenant + personal Microsoft accounts)
    "organizations",   # Multi-tenant (any Azure AD tenant, no personal accounts)
    "consumers",       # Personal Microsoft accounts only
})

# Default Azure AD authority base URL
AZURE_AUTHORITY_BASE_URL = "https://login.microsoftonline.com"

# Azure AD documentation URLs for error messages
AZURE_DOCS_TENANT_SETUP = "https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app"
AZURE_DOCS_GRAPH_API = "https://learn.microsoft.com/en-us/graph/overview"
AZURE_DOCS_MULTI_TENANT = "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant"

# Security constants
MIN_SECRET_LENGTH = 32  # Minimum length for client secrets
MIN_ENTROPY_BITS = 3.0  # Minimum Shannon entropy per character
WEAK_SECRET_PATTERNS = [
    re.compile(r"^(.)\1+$"),  # All same character (e.g., "aaaa...")
    re.compile(r"^(password|secret|test|demo|example)", re.IGNORECASE),  # Common weak prefixes
    re.compile(r"^(123|abc|qwerty|asdf|zxcv)", re.IGNORECASE),  # Sequential/keyboard patterns
    re.compile(r"^[a-zA-Z]+$"),  # All letters only (low entropy)
    re.compile(r"^[0-9]+$"),  # All digits only (low entropy)
]


@auto_trace(logger, include_args=False)  # Security: operates on secret values
def _calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    Higher entropy indicates more randomness/unpredictability.
    Good secrets should have entropy >= 3.0 bits/char.

    Args:
        s: String to calculate entropy for

    Returns:
        Entropy in bits per character
    """
    if not s:
        return 0.0

    # Count character frequencies
    freq = Counter(s)
    length = len(s)

    # Calculate entropy: -sum(p * log2(p))
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


@auto_trace(logger, include_args=False)  # Security: validates input strings
def _normalize_and_validate_ascii(value: str, field_name: str) -> str:
    """Normalize Unicode and validate string contains only ASCII characters.

    Security: Prevents Unicode lookalike attacks (e.g., Cyrillic 'е' vs ASCII 'e').

    Args:
        value: String to normalize and validate
        field_name: Name of field for error messages

    Returns:
        Normalized lowercase string

    Raises:
        ValueError: If string contains non-ASCII characters after normalization
    """
    # Normalize Unicode (NFKC converts lookalikes to their ASCII equivalents where possible)
    normalized = unicodedata.normalize("NFKC", value)

    # Strip all Unicode whitespace
    normalized = "".join(normalized.split())

    # Verify all characters are ASCII
    if not normalized.isascii():
        raise ValueError(
            f"{field_name} contains non-ASCII characters. "
            f"Only ASCII characters are allowed for security. "
            f"Received: '{value}'"
        )

    return normalized.lower()


# =============================================================================
# JWT Configuration
# =============================================================================


class JWTConfig(SecureSchema):
    """Configuration for JWT token decoder.

    Supports RS256 (RSA) and HS256 (HMAC) algorithms with public key
    or secret validation.

    Attributes:
        public_key_path: Path to RSA public key file (PEM format)
        algorithm: JWT signing algorithm (RS256, HS256, etc.)
        issuer: Expected token issuer (iss claim)
        audience: Expected token audience (aud claim), optional
        clock_skew_seconds: Maximum allowed clock skew for exp/nbf validation
    """

    public_key_path: str
    algorithm: str = "RS256"
    issuer: str
    audience: Optional[str] = None
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS

    @field_validator("public_key_path")
    @classmethod
    def validate_public_key_path(cls, v: str) -> str:
        """Validate public key path is not empty."""
        if not v or not v.strip():
            raise ValueError("public_key_path cannot be empty")
        return v.strip()

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate algorithm is supported."""
        allowed = {"RS256", "RS384", "RS512", "HS256", "HS384", "HS512", "ES256", "ES384", "ES512"}
        if v not in allowed:
            raise ValueError(f"algorithm must be one of {allowed}, got '{v}'")
        return v

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate issuer is not empty."""
        if not v or not v.strip():
            raise ValueError("issuer cannot be empty")
        return v.strip()

    @field_validator("clock_skew_seconds")
    @classmethod
    def validate_clock_skew(cls, v: int) -> int:
        """Validate clock skew is positive."""
        if v < 0:
            raise ValueError("clock_skew_seconds must be non-negative")
        return v


# =============================================================================
# Auth Mode Enum
# =============================================================================

# ALLOWLIST ONLY - environments where unsafe auth modes are permitted
# Security model: fail closed - only explicit allowlist values pass
ALLOWED_DEV_ENVIRONMENTS = frozenset({"development", "local", "dev", "test"})


class AuthMode(str, Enum):
    """Authentication mode selection.

    Determines which authentication provider/decoder is used.

    Values:
        DISABLED: No authentication (testing only, blocked in production)
        DEV_JWT: Development JWT tokens with HS256 (blocked in production)
        AZURE_AD: Production Azure AD authentication
        OIDC: Generic OIDC provider authentication

    Security:
        DEV_JWT and DISABLED modes are only allowed when NEO_ENV is set to
        one of: development, local, dev, test. All other environments are
        blocked to prevent development authentication in production.
    """

    DISABLED = "disabled"
    DEV_JWT = "dev-jwt"
    AZURE_AD = "azure-ad"
    OIDC = "oidc"


# =============================================================================
# Development JWT Configuration
# =============================================================================


class DevJWTConfig(SecureSchema):
    """Configuration for development JWT authentication.

    Provides JWT-based authentication for development/testing that mirrors
    production Azure AD token structure without requiring external identity
    provider setup.

    SECURITY: This configuration is BLOCKED in production environments.
    Only allowed when NEO_ENV is one of: development, local, dev, test.

    Attributes:
        secret_key: HS256 signing secret (SecretStr, min 32 chars, entropy validated)
        algorithm: JWT algorithm (default: HS256)
        issuer: Token issuer claim (default: dev-auth)
        audience: Token audience claim (default: dev)
        clock_skew_seconds: Maximum clock skew for exp/nbf (5-60, default: 30)

    Example:
        config = DevJWTConfig(
            secret_key="env:DEV_JWT_SECRET_KEY",
            issuer="dev-auth",
            audience="dev"
        )

    Claims Structure (Azure AD compatible):
        - iss: Issuer (dev-auth)
        - sub: Subject (user ID)
        - aud: Audience (dev)
        - oid: Object ID (maps to user_id)
        - tid: Tenant ID (maps to tenant_id)
        - roles: Array of role names
        - exp: Expiration timestamp
        - iat: Issued at timestamp
        - nbf: Not before timestamp
    """

    secret_key: SecretStr = Field(json_schema_extra={"refreshable": True})
    algorithm: str = Field(default="HS256", pattern=r"^HS(256|384|512)$")
    issuer: str = Field(default="dev-auth")
    audience: str = Field(default="dev")
    clock_skew_seconds: int = Field(default=DEFAULT_TOKEN_CLOCK_SKEW_SECONDS, ge=5, le=60)

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key_entropy(cls, v: SecretStr) -> SecretStr:
        """Validate secret_key has sufficient entropy.

        Security: Prevents use of weak secrets that could be brute-forced.
        Minimum length is 32 characters with entropy >= 3.0 bits/char.

        Returns:
            Validated SecretStr

        Raises:
            ValueError: If secret is too short or has weak entropy
        """
        secret_value = v.get_secret_value()

        if not secret_value or not secret_value.strip():
            raise ValueError("secret_key cannot be empty")

        # Check minimum length (do not expose actual length in error)
        if len(secret_value) < MIN_SECRET_LENGTH:
            raise ValueError(
                f"secret_key does not meet minimum length requirement of {MIN_SECRET_LENGTH} characters. "
                f"Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        # Check for weak patterns
        for pattern in WEAK_SECRET_PATTERNS:
            if pattern.match(secret_value):
                raise ValueError(
                    "secret_key does not meet complexity requirements. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )

        # Check Shannon entropy (do not expose entropy value in error)
        entropy = _calculate_shannon_entropy(secret_value)
        if entropy < MIN_ENTROPY_BITS:
            raise ValueError(
                "secret_key does not meet entropy requirements. "
                f"Must have at least {MIN_ENTROPY_BITS} bits/char entropy. "
                f"Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        return v

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate issuer is not empty."""
        if not v or not v.strip():
            raise ValueError("issuer cannot be empty")
        return v.strip()

    @field_validator("audience")
    @classmethod
    def validate_audience(cls, v: str) -> str:
        """Validate audience is not empty."""
        if not v or not v.strip():
            raise ValueError("audience cannot be empty")
        return v.strip()

    @model_validator(mode="after")
    def log_initialization(self) -> Self:
        """Log configuration after initialization (no secrets)."""
        import os

        current_env = os.getenv("NEO_ENV", "").lower()

        logger.info(
            "DevJWTConfig initialized",
            extra={
                "algorithm": self.algorithm,
                "issuer": self.issuer,
                "audience": self.audience,
                "clock_skew_seconds": self.clock_skew_seconds,
                "neo_env": current_env or "unset",
                "has_secret_key": True,
            },
        )
        return self


# =============================================================================
# OIDC Configuration
# =============================================================================


class JWKSConfig(SecureSchema):
    """Configuration for JWKS (JSON Web Key Set) endpoint.

    Defines how to fetch and cache public keys for JWT signature verification.

    Attributes:
        uri: JWKS endpoint URL (e.g., https://provider.com/.well-known/jwks.json)
        ttl_seconds: Cache TTL for JWKS keys (default: 86400 = 24 hours)
        algorithm: Expected JWT signing algorithm (default: RS256)
        validate_issuer: Whether to validate issuer claim (default: True)

    Example:
        jwks = JWKSConfig(
            uri="https://login.microsoftonline.com/common/discovery/v2.0/keys",
            ttl_seconds=3600,
            algorithm="RS256"
        )
    """


    uri: str
    ttl_seconds: int = CACHE_TTL_LONG
    algorithm: str = "RS256"
    validate_issuer: bool = True

    @field_validator("uri")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        """Validate JWKS URI is not empty and uses HTTPS."""
        if not v or not v.strip():
            raise ValueError("uri cannot be empty")
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("uri must use HTTPS (no wildcards or http)")
        if "*" in v:
            raise ValueError("uri cannot contain wildcards")
        return v

    @field_validator("ttl_seconds")
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        """Validate TTL is positive."""
        if v <= 0:
            raise ValueError("ttl_seconds must be positive")
        return v

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate algorithm is supported."""
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if v not in allowed:
            raise ValueError(f"algorithm must be one of {allowed}, got '{v}'")
        return v


class OIDCDiscoveryConfig(SecureSchema):
    """Configuration for OIDC Discovery endpoint.

    Defines how to use OpenID Connect Discovery to automatically configure
    the identity provider endpoints.

    Attributes:
        issuer: OIDC issuer URL (required, must be HTTPS)
        auto_discover: Use .well-known/openid-configuration endpoint (default: True)
        timeout_seconds: HTTP timeout for discovery requests (default: 10)

    Example:
        discovery = OIDCDiscoveryConfig(
            issuer="https://accounts.google.com",
            auto_discover=True,
            timeout_seconds=15
        )

    Security:
        - Issuer URL must use HTTPS (no wildcards)
        - Auto-discovery is enabled by default for security
        - Timeout prevents hanging on slow identity providers
    """


    issuer: str
    auto_discover: bool = True
    timeout_seconds: int = 10

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate issuer URL is not empty and uses HTTPS."""
        if not v or not v.strip():
            raise ValueError("issuer cannot be empty")
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("issuer must use HTTPS (no wildcards or http)")
        if "*" in v:
            raise ValueError("issuer cannot contain wildcards")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("timeout_seconds must be positive")
        return v


class OIDCConfig(SecureSchema):
    """Configuration for generic OIDC provider.

    Supports any OpenID Connect compliant identity provider with automatic
    endpoint discovery and JWKS key management.

    Attributes:
        issuer: OIDC issuer URL (optional if discovery provided, will be extracted from discovery document)
        client_id: OAuth2 client ID (required)
        client_secret: OAuth2 client secret as SecretStr (optional for public clients)
        audience: Expected audience claim (optional, validates aud claim)
        discovery: OIDC discovery configuration (auto-created from issuer if provided)
        jwks: JWKS configuration (auto-created from discovery)
        scope: OAuth2 scopes to request (space-separated string)
        claims_mapping: Custom mapping of OIDC claims to IdentityContext fields

    Example:
        # With explicit issuer
        config = OIDCConfig(
            issuer="https://accounts.google.com",
            client_id="123456.apps.googleusercontent.com",
            client_secret="file:///run/secrets/google-client-secret",
            audience="https://api.myapp.com",
            scope="openid profile email",
            claims_mapping={"sub": "user_id", "email": "email"}
        )

        # With discovery URL (issuer will be extracted from discovery document)
        config = OIDCConfig(
            discovery=OIDCDiscoveryConfig(issuer="https://accounts.google.com"),
            client_id="123456.apps.googleusercontent.com",
            client_secret="file:///run/secrets/google-client-secret"
        )

    Security:
        - client_secret supports file:// and env: prefixes (resolved by loaders)
        - Issuer must use HTTPS (no wildcards) when provided
        - Auto-discovery enabled by default for security
        - Audience validation recommended for production

    Note:
        Secret resolution (file://, env:) happens in loaders.py via _resolve_secret().
        This schema documents the format but does not perform the resolution.
        Either issuer OR discovery must be provided (validated in model_validator).
    """


    issuer: Optional[str] = None
    client_id: str
    client_secret: Optional[SecretStr] = None
    audience: Optional[str] = None
    discovery: Optional[OIDCDiscoveryConfig] = None
    jwks: Optional[JWKSConfig] = None
    scope: Optional[str] = None
    claims_mapping: Optional[Dict[str, str]] = None

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: Optional[str]) -> Optional[str]:
        """Validate issuer URL is not empty and uses HTTPS when provided."""
        if v is None:
            return None
        if not v.strip():
            raise ValueError("issuer cannot be empty string (use None if not providing issuer)")
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("issuer must use HTTPS (no wildcards or http)")
        if "*" in v:
            raise ValueError("issuer cannot contain wildcards")
        return v

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        """Validate client ID is not empty."""
        if not v or not v.strip():
            raise ValueError("client_id cannot be empty")
        return v.strip()

    @model_validator(mode="before")
    @classmethod
    def auto_create_discovery(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Auto-create discovery config from issuer if not provided.

        This validator runs before model creation to set computed fields,
        allowing the model to remain frozen after creation.
        """
        if isinstance(data, dict):
            issuer = data.get("issuer")
            discovery = data.get("discovery")

            # Ensure at least one of issuer or discovery is provided
            if issuer is None and discovery is None:
                raise ValueError("Either 'issuer' or 'discovery' must be provided")

            # Auto-create discovery config from issuer if not provided
            if discovery is None and issuer is not None:
                data["discovery"] = {"issuer": issuer}

            # If discovery is provided but issuer is not, extract issuer from discovery
            if issuer is None and discovery is not None:
                if isinstance(discovery, dict):
                    data["issuer"] = discovery.get("issuer")
                elif hasattr(discovery, "issuer"):
                    data["issuer"] = discovery.issuer

        return data

    @model_validator(mode="after")
    def log_initialization(self) -> Self:
        """Log configuration after initialization (without secrets)."""
        logger.info(
            "OIDCConfig initialized",
            extra={
                "issuer": self.issuer,
                "has_client_secret": self.client_secret is not None,
                "has_audience": self.audience is not None,
                "auto_discover": self.discovery.auto_discover if self.discovery else False,
            },
        )
        return self


# =============================================================================
# Azure AD Configuration
# =============================================================================


class GraphAPIConfig(SecureSchema):
    """Configuration for Microsoft Graph API integration.

    Defines how to interact with Microsoft Graph API for fetching user
    profile information, group memberships, and application roles.

    Attributes:
        enabled: Whether Graph API integration is enabled (default: True)
        timeout_seconds: HTTP timeout for Graph API requests (1-60, default: 10)
        max_retries: Maximum retry attempts for failed requests (0-5, default: 3)
        retry_backoff_base: Base multiplier for exponential backoff (0.1-5.0, default: 1.0)
        cache_ttl_seconds: Cache TTL for Graph API responses (300-86400, default: 3600)
        user_agent: User agent string for Graph API requests

    Example:
        graph_api = GraphAPIConfig(
            enabled=True,
            timeout_seconds=15,
            max_retries=3,
            retry_backoff_base=1.5,
            cache_ttl_seconds=3600,
            user_agent="MyApp/1.0"
        )

    Security:
        - Uses HTTPS exclusively for Graph API calls
        - Requires bearer token authentication
        - Caches responses to minimize network exposure

    Reference: https://learn.microsoft.com/en-us/graph/overview
    """


    enabled: bool = True
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_retries: int = Field(default=HTTPX_MAX_RETRIES, ge=0, le=5)
    retry_backoff_base: float = Field(default=1.0, ge=0.1, le=5.0)
    cache_ttl_seconds: int = Field(default=CACHE_TTL_MEDIUM, ge=300, le=86400)
    user_agent: str = "neoaxios-fastapi-kit/1.0"

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout_seconds(cls, v: int) -> int:
        """Validate timeout is within acceptable range (1-60 seconds).

        Graph API calls should complete within reasonable time to prevent
        hanging requests and resource exhaustion.
        """
        if v < 1:
            raise ValueError(
                f"timeout_seconds must be at least 1 second, got {v}. "
                f"See {AZURE_DOCS_GRAPH_API} for Graph API performance guidance."
            )
        if v > 60:
            raise ValueError(
                f"timeout_seconds must be at most 60 seconds, got {v}. "
                f"Consider breaking up slow operations or caching results."
            )
        return v

    @field_validator("max_retries")
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        """Validate max_retries is within acceptable range (0-5)."""
        if v < 0:
            raise ValueError(f"max_retries cannot be negative, got {v}")
        if v > 5:
            raise ValueError(
                f"max_retries must be at most 5, got {v}. "
                f"Excessive retries can cause delays and rate limiting."
            )
        return v

    @field_validator("retry_backoff_base")
    @classmethod
    def validate_retry_backoff_base(cls, v: float) -> float:
        """Validate retry_backoff_base is within acceptable range (0.1-5.0)."""
        if v < 0.1:
            raise ValueError(
                f"retry_backoff_base must be at least 0.1 seconds, got {v}. "
                f"Very short backoff may trigger rate limiting."
            )
        if v > 5.0:
            raise ValueError(
                f"retry_backoff_base must be at most 5.0 seconds, got {v}. "
                f"Long backoff delays can impact user experience."
            )
        return v

    @field_validator("cache_ttl_seconds")
    @classmethod
    def validate_cache_ttl_seconds(cls, v: int) -> int:
        """Validate cache TTL is within acceptable range (300-86400 seconds).

        5 minutes minimum prevents excessive API calls.
        24 hours maximum ensures data freshness.
        """
        if v < 300:
            raise ValueError(
                f"cache_ttl_seconds must be at least 300 (5 minutes), got {v}. "
                f"Short TTL may cause excessive Graph API calls and rate limiting."
            )
        if v > 86400:
            raise ValueError(
                f"cache_ttl_seconds must be at most 86400 (24 hours), got {v}. "
                f"Long TTL may serve stale user data (e.g., removed group memberships)."
            )
        return v

    @field_validator("user_agent")
    @classmethod
    def validate_user_agent(cls, v: str) -> str:
        """Validate user_agent is not empty."""
        if not v or not v.strip():
            raise ValueError("user_agent cannot be empty")
        return v.strip()


class MultiTenantConfig(SecureSchema):
    """Configuration for multi-tenant Azure AD applications.

    Defines how the application handles tokens from multiple Azure AD tenants,
    including tenant validation and claim extraction.

    Attributes:
        mode: Tenant mode - "single" for single-tenant, "multi" for multi-tenant
        tenant_id_claim: JWT claim containing tenant ID (default: "tid")
        expected_tenants: List of allowed tenant IDs for multi-tenant mode
        app_id_claim: JWT claim containing application ID (default: "appid")
        verify_app_id: Whether to verify the appid claim matches expected value
        expected_app_id: Expected application ID if verify_app_id is True

    Example:
        # Single-tenant (default)
        multi_tenant = MultiTenantConfig(mode="single")

        # Multi-tenant with allowed tenant list
        multi_tenant = MultiTenantConfig(
            mode="multi",
            expected_tenants=[
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440001"
            ],
            verify_app_id=True,
            expected_app_id="770e8400-e29b-41d4-a716-446655440002"
        )

    Security:
        - In multi-tenant mode, expected_tenants must be non-empty to prevent
          accepting tokens from any Azure AD tenant
        - verify_app_id prevents token forwarding attacks

    Reference: https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant
    """


    mode: Literal["single", "multi"] = "single"
    tenant_id_claim: str = "tid"
    expected_tenants: Optional[List[str]] = None
    app_id_claim: str = "appid"
    verify_app_id: bool = False
    expected_app_id: Optional[str] = None

    @field_validator("tenant_id_claim")
    @classmethod
    def validate_tenant_id_claim(cls, v: str) -> str:
        """Validate tenant_id_claim is not empty."""
        if not v or not v.strip():
            raise ValueError("tenant_id_claim cannot be empty")
        return v.strip()

    @field_validator("expected_tenants")
    @classmethod
    def validate_expected_tenants(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate expected_tenants list contains valid values."""
        if v is None:
            return None
        if not v:
            # Empty list is invalid - use None instead
            return None
        # Validate each tenant ID is a valid GUID or special value
        validated = []
        for tenant in v:
            if not tenant or not tenant.strip():
                raise ValueError("expected_tenants cannot contain empty strings")
            tenant = tenant.strip()
            # Validate it's either a GUID or special value
            if tenant.lower() not in AZURE_SPECIAL_TENANT_VALUES:
                if not AZURE_GUID_PATTERN.match(tenant):
                    raise ValueError(
                        f"Invalid tenant ID format: '{tenant}'. "
                        f"Must be a valid GUID (e.g., '550e8400-e29b-41d4-a716-446655440000') "
                        f"or special value ({', '.join(AZURE_SPECIAL_TENANT_VALUES)}). "
                        f"See {AZURE_DOCS_MULTI_TENANT}"
                    )
            validated.append(tenant)
        return validated

    @field_validator("app_id_claim")
    @classmethod
    def validate_app_id_claim(cls, v: str) -> str:
        """Validate app_id_claim is not empty."""
        if not v or not v.strip():
            raise ValueError("app_id_claim cannot be empty")
        return v.strip()

    @field_validator("expected_app_id")
    @classmethod
    def validate_expected_app_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate expected_app_id if provided."""
        if v is None:
            return None
        if not v.strip():
            return None
        return v.strip()

    @model_validator(mode="after")
    def validate_multi_tenant_settings(self) -> "MultiTenantConfig":
        """Validate multi-tenant configuration consistency.

        - Multi-tenant mode requires expected_tenants list
        - verify_app_id=True requires expected_app_id
        """
        if self.mode == "multi":
            if not self.expected_tenants:
                raise ValueError(
                    "expected_tenants must be provided for multi-tenant mode. "
                    f"See {AZURE_DOCS_MULTI_TENANT} for multi-tenant configuration guidance."
                )

        if self.verify_app_id and not self.expected_app_id:
            raise ValueError(
                "expected_app_id is required when verify_app_id is True. "
                "Set expected_app_id to the application ID you want to verify against."
            )

        return self


class RolesMappingConfig(SecureSchema):
    """Configuration for mapping Azure AD roles to application permissions.

    Defines how roles are extracted from Azure AD tokens and Graph API,
    and how they map to application-specific permissions.

    Attributes:
        source: Where to get roles from - "claims" (JWT), "graph" (API), or "both"
        claims_field: JWT claim field containing roles (default: "roles")
        graph_app_roles: Fetch app role assignments from Graph API
        graph_directory_roles: Fetch directory role assignments from Graph API
        role_claim_formats: Mapping of role claim names to output formats
        default_roles: Default roles assigned to all authenticated users

    Example:
        # Simple claims-based roles
        roles = RolesMappingConfig(
            source="claims",
            claims_field="roles",
            default_roles=["user"]
        )

        # Combined claims and Graph API roles
        roles = RolesMappingConfig(
            source="both",
            claims_field="roles",
            graph_app_roles=True,
            graph_directory_roles=True,
            role_claim_formats={
                "admin": "Admin.{tenant}",
                "reader": "Reader.{tenant}"
            },
            default_roles=["user"]
        )

    Security:
        - Using "both" source provides defense in depth
        - graph_directory_roles should only be enabled if needed
        - default_roles should be minimal (principle of least privilege)

    Reference: https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps
    """


    source: Literal["claims", "graph", "both"] = "claims"
    claims_field: str = "roles"
    graph_app_roles: bool = False
    graph_directory_roles: bool = False
    role_claim_formats: Dict[str, str] = Field(default_factory=dict)
    default_roles: List[str] = Field(default_factory=list)

    @field_validator("claims_field")
    @classmethod
    def validate_claims_field(cls, v: str) -> str:
        """Validate claims_field is not empty."""
        if not v or not v.strip():
            raise ValueError("claims_field cannot be empty")
        return v.strip()

    @field_validator("default_roles")
    @classmethod
    def validate_default_roles(cls, v: List[str]) -> List[str]:
        """Validate default_roles list contains no empty strings."""
        if any(not role or not role.strip() for role in v):
            raise ValueError("default_roles cannot contain empty strings")
        return [role.strip() for role in v]

    @model_validator(mode="after")
    def validate_graph_settings(self) -> "RolesMappingConfig":
        """Validate Graph API role settings.

        If source is "claims", Graph API settings should not be enabled.
        """
        if self.source == "claims":
            if self.graph_app_roles or self.graph_directory_roles:
                logger.warning(
                    "Graph API roles are configured but source is 'claims'. "
                    "Graph API roles will be ignored. Set source to 'graph' or 'both' "
                    "to enable Graph API role fetching.",
                    extra={
                        "source": self.source,
                        "graph_app_roles": self.graph_app_roles,
                        "graph_directory_roles": self.graph_directory_roles,
                    },
                )
        return self


class AzureConfig(SecureSchema):
    """Comprehensive configuration for Azure AD authentication and authorization.

    This is the primary configuration schema for Azure AD integration,
    providing complete control over authentication, Graph API integration,
    multi-tenant support, and role mapping.

    Attributes:
        tenant_id: Azure AD tenant ID (GUID or special value: common, organizations, consumers)
        client_id: Azure AD application (client) ID (GUID)
        client_secret: Azure AD client secret (SecretStr for security)
        authority_url: Azure AD authority URL (auto-constructed if not provided)
        scopes: OAuth2 scopes to request (default: [".default"])
        validate_issuer: Whether to validate token issuer (default: True)
        validate_audience: Whether to validate token audience (default: True)
        clock_skew_seconds: Maximum allowed clock skew for exp/nbf (5-60, default: 30)
        audience: Expected token audience (default: client_id)
        api_version: Azure AD API version - "v1.0" or "v2.0" (default: "v2.0")
        graph_api: Microsoft Graph API configuration (optional)
        multi_tenant: Multi-tenant configuration (optional)
        roles_mapping: Roles mapping configuration (optional)

    Example:
        # Minimal configuration
        config = AzureConfig(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            client_id="660e8400-e29b-41d4-a716-446655440000",
            client_secret="env:AZURE_CLIENT_SECRET"
        )

        # Full configuration with all options
        config = AzureConfig(
            tenant_id="550e8400-e29b-41d4-a716-446655440000",
            client_id="660e8400-e29b-41d4-a716-446655440000",
            client_secret="file:///run/secrets/azure-secret",
            scopes=["https://graph.microsoft.com/.default"],
            validate_issuer=True,
            validate_audience=True,
            clock_skew_seconds=30,
            graph_api=GraphAPIConfig(
                enabled=True,
                timeout_seconds=15,
                max_retries=3
            ),
            multi_tenant=MultiTenantConfig(
                mode="multi",
                expected_tenants=["tenant1-guid", "tenant2-guid"]
            ),
            roles_mapping=RolesMappingConfig(
                source="both",
                graph_app_roles=True,
                default_roles=["user"]
            )
        )

    Security:
        - client_secret is SecretStr type (never logged)
        - validate_issuer and validate_audience should both be True in production
        - clock_skew_seconds limits replay attack window
        - See Azure AD security best practices at:
          https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices
    """


    # Static fields - drift detection will block changes to these
    tenant_id: str
    client_id: str
    authority_url: Optional[str] = None
    validate_issuer: bool = True
    validate_audience: bool = True
    audience: Optional[str] = None  # Defaults to client_id if not set
    api_version: str = Field(default="v2.0", pattern=r"^v[12]\.0$")  # Azure AD API version

    # Refreshable fields - can change during secret rotation
    client_secret: SecretStr = Field(json_schema_extra={"refreshable": True})
    scopes: List[str] = Field(
        default_factory=lambda: [".default"],
        json_schema_extra={"refreshable": True}
    )
    clock_skew_seconds: int = Field(
        default=DEFAULT_TOKEN_CLOCK_SKEW_SECONDS, ge=5, le=60,
        json_schema_extra={"refreshable": True}
    )

    # Nested configs - refreshable for operational flexibility
    graph_api: Optional[GraphAPIConfig] = Field(
        default=None,
        json_schema_extra={"refreshable": True}
    )
    multi_tenant: Optional[MultiTenantConfig] = Field(
        default=None,
        json_schema_extra={"refreshable": True}
    )
    roles_mapping: Optional[RolesMappingConfig] = Field(
        default=None,
        json_schema_extra={"refreshable": True}
    )

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant_id is a valid GUID or special value.

        Security: Uses Unicode normalization to prevent lookalike attacks
        (e.g., Cyrillic 'е' vs ASCII 'e').

        Azure AD accepts:
        - Standard GUID format (e.g., "550e8400-e29b-41d4-a716-446655440000")
        - Special values: "common", "organizations", "consumers"

        Returns:
            Validated tenant_id string (lowercase, normalized)

        Raises:
            ValueError: If tenant_id is invalid format or contains non-ASCII characters
        """
        if not v or not v.strip():
            raise ValueError(
                "tenant_id cannot be empty. "
                f"See {AZURE_DOCS_TENANT_SETUP} for Azure AD app registration guidance."
            )

        # Normalize Unicode and validate ASCII (prevent Unicode lookalike attacks)
        v = _normalize_and_validate_ascii(v, "tenant_id")

        # Check if it's a special value
        if v in AZURE_SPECIAL_TENANT_VALUES:
            return v

        # Must be a valid GUID
        if not AZURE_GUID_PATTERN.match(v):
            raise ValueError(
                f"Invalid tenant_id format: '{v}'. "
                f"Must be a valid GUID (e.g., '550e8400-e29b-41d4-a716-446655440000') "
                f"or special value ({', '.join(AZURE_SPECIAL_TENANT_VALUES)}). "
                f"See {AZURE_DOCS_TENANT_SETUP}"
            )

        return v

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        """Validate client_id is a valid GUID.

        Security: Uses Unicode normalization to prevent lookalike attacks.

        Azure AD application (client) IDs are always GUIDs.

        Returns:
            Validated client_id string (lowercase, normalized)

        Raises:
            ValueError: If client_id is not a valid GUID or contains non-ASCII characters
        """
        if not v or not v.strip():
            raise ValueError(
                "client_id cannot be empty. "
                f"See {AZURE_DOCS_TENANT_SETUP} for Azure AD app registration guidance."
            )

        # Normalize Unicode and validate ASCII (prevent Unicode lookalike attacks)
        v = _normalize_and_validate_ascii(v, "client_id")

        if not AZURE_GUID_PATTERN.match(v):
            raise ValueError(
                f"Invalid client_id format: '{v}'. "
                f"Azure AD client IDs must be valid GUIDs "
                f"(e.g., '660e8400-e29b-41d4-a716-446655440000'). "
                f"See {AZURE_DOCS_TENANT_SETUP}"
            )

        return v

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret_entropy(cls, v: SecretStr) -> SecretStr:
        """Validate client_secret has sufficient entropy.

        Security: Prevents use of weak secrets that could be brute-forced.
        Minimum length is 32 characters.

        Returns:
            Validated SecretStr

        Raises:
            ValueError: If secret is too short or matches weak patterns
        """
        secret_value = v.get_secret_value()

        if not secret_value or not secret_value.strip():
            raise ValueError("client_secret cannot be empty")

        # Check minimum length (do not expose actual length in error)
        if len(secret_value) < MIN_SECRET_LENGTH:
            raise ValueError(
                f"client_secret does not meet minimum length requirement of {MIN_SECRET_LENGTH} characters. "
                f"Use a cryptographically secure random secret."
            )

        # Check for weak patterns
        for pattern in WEAK_SECRET_PATTERNS:
            if pattern.match(secret_value):
                raise ValueError(
                    "client_secret does not meet complexity requirements. "
                    "Use a cryptographically secure random secret."
                )

        # Check Shannon entropy (do not expose entropy value in error)
        entropy = _calculate_shannon_entropy(secret_value)
        if entropy < MIN_ENTROPY_BITS:
            raise ValueError(
                "client_secret does not meet entropy requirements. "
                f"Must have at least {MIN_ENTROPY_BITS} bits/char entropy. "
                f"Use a cryptographically secure random secret with mixed character types."
            )

        return v

    @field_validator("authority_url")
    @classmethod
    def validate_authority_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate authority_url uses HTTPS (localhost exception for development).

        The authority URL is the Azure AD endpoint used for authentication.
        Must use HTTPS in production (http://localhost allowed for development).

        Returns:
            Validated authority_url or None

        Raises:
            ValueError: If URL is not HTTPS (except localhost)
        """
        if v is None:
            return None

        if not v.strip():
            return None

        v = v.strip()

        # Allow http://localhost for development
        if v.startswith("http://localhost"):
            logger.warning(
                "authority_url uses HTTP (localhost). This is only safe for development.",
                extra={"authority_url": v},
            )
            return v

        # Otherwise require HTTPS
        if not v.startswith("https://"):
            raise ValueError(
                f"authority_url must use HTTPS: '{v}'. "
                f"Use https://login.microsoftonline.com/{{tenant_id}} for Azure AD."
            )

        return v

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: List[str]) -> List[str]:
        """Validate scopes list is not empty and contains valid values."""
        if not v:
            raise ValueError("scopes list cannot be empty")
        if any(not scope or not scope.strip() for scope in v):
            raise ValueError("scopes cannot contain empty strings")
        return [scope.strip() for scope in v]

    @field_validator("clock_skew_seconds")
    @classmethod
    def validate_clock_skew_seconds(cls, v: int) -> int:
        """Validate clock_skew_seconds is within acceptable range (5-60).

        Clock skew allows for small time differences between servers.
        Too small: May reject valid tokens due to minor clock drift.
        Too large: Increases window for replay attacks.
        """
        if v < 5:
            raise ValueError(
                f"clock_skew_seconds must be at least 5 seconds, got {v}. "
                f"Very low clock skew may reject valid tokens due to minor clock drift."
            )
        if v > 60:
            raise ValueError(
                f"clock_skew_seconds must be at most 60 seconds, got {v}. "
                f"High clock skew increases vulnerability to replay attacks."
            )
        return v

    @model_validator(mode="before")
    @classmethod
    def compute_authority_url(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compute authority_url from tenant_id if not provided.

        This validator runs before model creation to set computed fields,
        allowing the model to remain frozen after creation.
        """
        if isinstance(data, dict):
            if data.get("authority_url") is None and data.get("tenant_id") is not None:
                data["authority_url"] = f"{AZURE_AUTHORITY_BASE_URL}/{data['tenant_id']}"
        return data

    @model_validator(mode="after")
    def log_initialization(self) -> Self:
        """Log configuration summary after initialization (no secrets)."""
        logger.info(
            "AzureConfig initialized",
            extra={
                "tenant_id": self.tenant_id,
                "client_id": self.client_id,
                "has_client_secret": self.client_secret is not None,
                "authority_url": self.authority_url,
                "scopes_count": len(self.scopes),
                "validate_issuer": self.validate_issuer,
                "validate_audience": self.validate_audience,
                "clock_skew_seconds": self.clock_skew_seconds,
                "graph_api_enabled": self.graph_api.enabled if self.graph_api else False,
                "multi_tenant_mode": self.multi_tenant.mode if self.multi_tenant else "single",
                "roles_source": self.roles_mapping.source if self.roles_mapping else "claims",
            },
        )
        return self

    @auto_trace(logger)  # Returns unmasked client secret for auth
    def get_secret_value(self) -> str:
        """Get the actual client_secret value.

        SECURITY: Use this method only when the secret value is needed for
        authentication. Never log the returned value.

        Returns:
            The unmasked client secret string

        Note:
            This method exists for compatibility with secret resolution.
            The client_secret may contain prefixes like "env:" or "file://"
            that need to be resolved by the configuration loader.
        """
        return self.client_secret.get_secret_value()


# =============================================================================
# AWS Cognito Configuration
# =============================================================================


class CognitoConfig(SecureSchema):
    """Configuration for AWS Cognito token decoder.

    Supports AWS Cognito User Pools with regional endpoints.

    Attributes:
        region: AWS region (e.g., us-east-1)
        user_pool_id: Cognito User Pool ID
        app_client_id: Cognito App Client ID
        app_client_secret: Cognito App Client Secret as SecretStr
        tenant_id: Tenant ID for multi-tenancy
        token_type: Token type to validate (id or access)
    """


    region: str
    user_pool_id: str
    app_client_id: str
    app_client_secret: SecretStr
    tenant_id: str
    token_type: str = "id"

    @field_validator("region")
    @classmethod
    def validate_region(cls, v: str) -> str:
        """Validate AWS region is not empty."""
        if not v or not v.strip():
            raise ValueError("region cannot be empty")
        return v.strip()

    @field_validator("user_pool_id")
    @classmethod
    def validate_user_pool_id(cls, v: str) -> str:
        """Validate user pool ID is not empty."""
        if not v or not v.strip():
            raise ValueError("user_pool_id cannot be empty")
        return v.strip()

    @field_validator("app_client_id")
    @classmethod
    def validate_app_client_id(cls, v: str) -> str:
        """Validate app client ID is not empty."""
        if not v or not v.strip():
            raise ValueError("app_client_id cannot be empty")
        return v.strip()

    @field_validator("app_client_secret")
    @classmethod
    def validate_app_client_secret(cls, v: SecretStr) -> SecretStr:
        """Validate app client secret is not empty.

        Note: Unlike other string validators, we intentionally do NOT strip
        whitespace from secrets. Secrets may contain leading/trailing whitespace
        as part of their value, and modifying them could break authentication.
        We only check for empty-after-strip to reject whitespace-only values.
        """
        secret_value = v.get_secret_value()
        if not secret_value or not secret_value.strip():
            raise ValueError("app_client_secret is required and cannot be empty")
        return v

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID is not empty."""
        if not v or not v.strip():
            raise ValueError("tenant_id cannot be empty")
        return v.strip()

    @field_validator("token_type")
    @classmethod
    def validate_token_type(cls, v: str) -> str:
        """Validate token type is id or access."""
        if v not in {"id", "access"}:
            raise ValueError("token_type must be 'id' or 'access'")
        return v


# =============================================================================
# Google IAM Configuration
# =============================================================================


class GoogleConfig(SecureSchema):
    """Configuration for Google IAM token decoder.

    Supports Google Identity Platform with domain restrictions.

    Attributes:
        audience: Expected audience claim (your application ID)
        allowed_domains: List of allowed email domains for verification
        tenant_id: Tenant ID for multi-tenancy
        gcp_project_id: Google Cloud Platform project ID (optional)
    """


    audience: str
    allowed_domains: List[str] = Field(default_factory=list)
    tenant_id: str
    gcp_project_id: Optional[str] = None

    @field_validator("audience")
    @classmethod
    def validate_audience(cls, v: str) -> str:
        """Validate audience is not empty."""
        if not v or not v.strip():
            raise ValueError("audience cannot be empty")
        return v.strip()

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID is not empty."""
        if not v or not v.strip():
            raise ValueError("tenant_id cannot be empty")
        return v.strip()

    @field_validator("allowed_domains")
    @classmethod
    def validate_allowed_domains(cls, v: List[str]) -> List[str]:
        """Validate domain list contains no empty strings."""
        if any(not d or not d.strip() for d in v):
            raise ValueError("allowed_domains cannot contain empty strings")
        return [d.strip() for d in v]


# =============================================================================
# Provider-Specific OIDC Configurations
# =============================================================================


class OktaConfig(OIDCConfig):
    """Configuration for Okta identity provider.

    Extends OIDCConfig with Okta-specific settings and validation.

    Attributes:
        tenant_id: Okta tenant/org ID (e.g., "dev-123456" or custom domain)
        issuer: Okta issuer URL (auto-constructed from tenant_id if not provided)
        client_id: Okta application client ID
        client_secret: Okta client secret (supports file://, env: prefixes)
        audience: Expected audience claim (optional)
        discovery: OIDC discovery configuration (auto-created)
        jwks: JWKS configuration (auto-created from discovery)
        scope: OAuth2 scopes (default: "openid profile email")
        claims_mapping: Custom claim mapping (optional)

    Example:
        # Issuer auto-constructed from tenant_id
        config = OktaConfig(
            tenant_id="dev-123456",
            client_id="0oa2abcdefGHIJKLMN",
            client_secret="env:OKTA_CLIENT_SECRET",
            scope="openid profile email groups"
        )
        # issuer will be: https://dev-123456.okta.com

        # Or provide explicit issuer
        config = OktaConfig(
            tenant_id="dev-123456",
            issuer="https://dev-123456.okta.com",
            client_id="0oa2abcdefGHIJKLMN",
            client_secret="env:OKTA_CLIENT_SECRET"
        )

    Note:
        If issuer is not provided (None), it will be auto-constructed as:
        https://{tenant_id}.okta.com
    """

    tenant_id: str
    issuer: str = ""  # Default to empty, will be auto-filled if not provided

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        """Validate tenant ID is not empty."""
        if not v or not v.strip():
            raise ValueError("tenant_id cannot be empty")
        return v.strip()

    @model_validator(mode="before")
    @classmethod
    def compute_issuer_from_tenant(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Auto-construct issuer from tenant_id if not provided."""
        if isinstance(data, dict):
            if not data.get("issuer") and data.get("tenant_id"):
                data["issuer"] = f"https://{data['tenant_id']}.okta.com"
        return data

    @model_validator(mode="after")
    def log_okta_initialization(self) -> Self:
        """Log Okta configuration after initialization."""
        logger.info(
            "OktaConfig initialized",
            extra={
                "tenant_id": self.tenant_id,
                "issuer": self.issuer,
                "has_client_secret": self.client_secret is not None,
            },
        )
        return self


class Auth0Config(OIDCConfig):
    """Configuration for Auth0 identity provider.

    Extends OIDCConfig with Auth0-specific settings and validation.

    Attributes:
        domain: Auth0 domain (e.g., "myapp.auth0.com" or "myapp.us.auth0.com")
        issuer: Auth0 issuer URL (auto-constructed from domain if not provided)
        client_id: Auth0 application client ID
        client_secret: Auth0 client secret (supports file://, env: prefixes)
        audience: Expected audience claim (API identifier, recommended)
        discovery: OIDC discovery configuration (auto-created)
        jwks: JWKS configuration (auto-created from discovery)
        scope: OAuth2 scopes (default: "openid profile email")
        claims_mapping: Custom claim mapping (optional)

    Example:
        # Issuer auto-constructed from domain
        config = Auth0Config(
            domain="myapp.auth0.com",
            client_id="abc123XYZ456",
            client_secret="file:///run/secrets/auth0-secret",
            audience="https://api.myapp.com",
            scope="openid profile email offline_access"
        )
        # issuer will be: https://myapp.auth0.com/

        # Or provide explicit issuer
        config = Auth0Config(
            domain="myapp.auth0.com",
            issuer="https://myapp.auth0.com/",
            client_id="abc123XYZ456",
            client_secret="file:///run/secrets/auth0-secret"
        )

    Note:
        If issuer is not provided (None), it will be auto-constructed as:
        https://{domain}/
    """

    domain: str
    issuer: str = ""  # Default to empty, will be auto-filled if not provided

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain is not empty and looks like a valid domain."""
        if not v or not v.strip():
            raise ValueError("domain cannot be empty")
        v = v.strip()
        # Basic domain validation (no scheme, no path)
        if v.startswith("http://") or v.startswith("https://"):
            raise ValueError("domain should not include http:// or https://")
        if "/" in v:
            raise ValueError("domain should not include path components")
        return v

    @model_validator(mode="before")
    @classmethod
    def compute_issuer_from_domain(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Auto-construct issuer from domain if not provided."""
        if isinstance(data, dict):
            if not data.get("issuer") and data.get("domain"):
                data["issuer"] = f"https://{data['domain']}/"
        return data

    @model_validator(mode="after")
    def log_auth0_initialization(self) -> Self:
        """Log Auth0 configuration after initialization."""
        logger.info(
            "Auth0Config initialized",
            extra={
                "domain": self.domain,
                "issuer": self.issuer,
                "has_client_secret": self.client_secret is not None,
            },
        )
        return self


class KeycloakConfig(OIDCConfig):
    """Configuration for Keycloak identity provider.

    Extends OIDCConfig with Keycloak-specific settings and validation.

    Attributes:
        realm_name: Keycloak realm name (e.g., "master", "myrealm")
        issuer: Keycloak server URL with realm (required)
        client_id: Keycloak client ID
        client_secret: Keycloak client secret (supports file://, env: prefixes)
        audience: Expected audience claim (optional, often same as client_id)
        discovery: OIDC discovery configuration (auto-created)
        jwks: JWKS configuration (auto-created from discovery)
        scope: OAuth2 scopes (default: "openid profile email")
        claims_mapping: Custom claim mapping for Keycloak roles

    Example:
        config = KeycloakConfig(
            realm_name="myrealm",
            issuer="https://keycloak.mycompany.com/realms/myrealm",
            client_id="myclient",
            client_secret="env:KEYCLOAK_CLIENT_SECRET",
            scope="openid profile email",
            claims_mapping={
                "realm_access.roles": "roles",
                "resource_access.myclient.roles": "client_roles"
            }
        )

    Note:
        Keycloak uses nested role structures in realm_access and resource_access
        claims. Use claims_mapping to extract these properly.
    """

    realm_name: str

    @field_validator("realm_name")
    @classmethod
    def validate_realm_name(cls, v: str) -> str:
        """Validate realm name is not empty."""
        if not v or not v.strip():
            raise ValueError("realm_name cannot be empty")
        return v.strip()

    @field_validator("issuer")
    @classmethod
    def validate_keycloak_issuer(cls, v: str) -> str:
        """Validate issuer URL contains /realms/ path."""
        if v is None:
            return v
        if not v.strip():
            raise ValueError("issuer cannot be empty string")
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("issuer must use HTTPS")
        # Keycloak-specific: issuer should contain /realms/
        if "/realms/" not in v:
            logger.warning(
                "Keycloak issuer typically contains /realms/ path",
                extra={"issuer": v},
            )
        return v

    @model_validator(mode="after")
    def validate_realm_and_log(self) -> Self:
        """Validate realm_name matches issuer path and log initialization."""
        # Verify realm_name appears in issuer
        if f"/realms/{self.realm_name}" not in self.issuer:
            logger.warning(
                "realm_name does not match issuer URL path",
                extra={
                    "realm_name": self.realm_name,
                    "issuer": self.issuer,
                },
            )

        logger.info(
            "KeycloakConfig initialized",
            extra={
                "realm_name": self.realm_name,
                "issuer": self.issuer,
                "has_client_secret": self.client_secret is not None,
            },
        )
        return self


# =============================================================================
# Cache Configuration
# =============================================================================


class CacheConfig(SecureSchema):
    """Configuration for cache backend.

    Supports in-memory and Redis caching for token validation results.

    Attributes:
        backend: Cache backend type (memory or redis)
        ttl_seconds: Default TTL for cached values
        redis_url: Redis connection URL (required if backend=redis)
    """


    backend: str = "memory"
    ttl_seconds: int = 300  # 5 minutes
    redis_url: Optional[str] = None

    @field_validator("backend")
    @classmethod
    def validate_backend(cls, v: str) -> str:
        """Validate backend is memory or redis."""
        if v not in {"memory", "redis"}:
            raise ValueError("backend must be 'memory' or 'redis'")
        return v

    @field_validator("ttl_seconds")
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        """Validate TTL is positive."""
        if v <= 0:
            raise ValueError("ttl_seconds must be positive")
        return v

    @model_validator(mode="after")
    def validate_redis_url_required(self) -> Self:
        """Validate redis_url is provided when backend=redis."""
        if self.backend == "redis" and not self.redis_url:
            raise ValueError("redis_url is required when backend='redis'")
        return self


# =============================================================================
# Top-Level Auth Configuration
# =============================================================================


class DecoderConfig(SecureSchema):
    """Top-level identity provider decoder configuration.

    Contains provider-specific decoder configurations and global settings.
    At least one provider decoder must be configured.

    Attributes:
        auth_mode: Authentication mode selection (disabled, dev-jwt, azure-ad, oidc)
        dev_jwt: Development JWT decoder configuration (blocked in production)
        jwt: JWT decoder configuration
        oidc: Generic OIDC provider configuration
        azure: Azure AD configuration
        cognito: AWS Cognito configuration
        google: Google IAM configuration
        okta: Okta provider configuration
        auth0: Auth0 provider configuration
        keycloak: Keycloak provider configuration
        cache: Cache backend configuration
        resolver_type: Privilege resolver type (local, remote, etc.)
        resolver_merge_strategy: Strategy for merging multiple resolvers (union, intersection)

    Example:
        # Development configuration with dev-jwt
        config = DecoderConfig(
            auth_mode=AuthMode.DEV_JWT,
            dev_jwt=DevJWTConfig(
                secret_key="env:DEV_JWT_SECRET_KEY",
                issuer="dev-auth"
            )
        )

        # Production configuration with Azure AD
        config = DecoderConfig(
            auth_mode=AuthMode.AZURE_AD,
            azure=AzureConfig(
                tenant_id="550e8400-e29b-41d4-a716-446655440000",
                client_id="660e8400-e29b-41d4-a716-446655440000",
                client_secret="env:AZURE_CLIENT_SECRET"
            )
        )

        # Multi-provider configuration
        config = DecoderConfig(
            auth_mode=AuthMode.AZURE_AD,
            azure=AzureConfig(
                tenant_id="550e8400-e29b-41d4-a716-446655440000",
                client_id="660e8400-e29b-41d4-a716-446655440000",
                client_secret="env:AZURE_CLIENT_SECRET"
            ),
            okta=OktaConfig(
                tenant_id="dev-123456",
                client_id="0oa2abc",
                client_secret="env:OKTA_SECRET"
            ),
            cache=CacheConfig(backend="redis", redis_url="redis://localhost:6379/0")
        )

    Security:
        auth_mode="dev-jwt" and auth_mode="disabled" are blocked when NEO_ENV
        is not in ALLOWED_DEV_ENVIRONMENTS. This is one of several
        defense-in-depth checks that prevent development auth modes from
        running in production.
    """


    auth_mode: AuthMode = Field(default=AuthMode.AZURE_AD)
    dev_jwt: Optional[DevJWTConfig] = None
    jwt: Optional[JWTConfig] = None
    oidc: Optional[OIDCConfig] = None
    azure: Optional[AzureConfig] = None
    cognito: Optional[CognitoConfig] = None
    google: Optional[GoogleConfig] = None
    okta: Optional[OktaConfig] = None
    auth0: Optional[Auth0Config] = None
    keycloak: Optional[KeycloakConfig] = None
    cache: CacheConfig = Field(default_factory=CacheConfig)
    resolver_type: str = "local"
    resolver_merge_strategy: str = "union"

    @field_validator("resolver_type")
    @classmethod
    def validate_resolver_type(cls, v: str) -> str:
        """Validate resolver type."""
        allowed = {"local", "remote", "hybrid"}
        if v not in allowed:
            raise ValueError(f"resolver_type must be one of {allowed}")
        return v

    @field_validator("resolver_merge_strategy")
    @classmethod
    def validate_merge_strategy(cls, v: str) -> str:
        """Validate merge strategy."""
        allowed = {"union", "intersection", "priority"}
        if v not in allowed:
            raise ValueError(f"resolver_merge_strategy must be one of {allowed}")
        return v

    @model_validator(mode="after")
    def validate_auth_configuration(self) -> Self:
        """Validate auth configuration with production safety checks.

        Production safety checks (one of several defense-in-depth layers):
        - dev-jwt and disabled modes require NEO_ENV in allowlist
        - dev_jwt config required when auth_mode is DEV_JWT
        - At least one provider required for azure-ad/oidc modes
        """
        import os

        current_env = os.getenv("NEO_ENV", "").lower()
        unsafe_modes = {AuthMode.DEV_JWT, AuthMode.DISABLED}

        # === PRODUCTION BLOCK (ALLOWLIST) ===
        if self.auth_mode in unsafe_modes:
            if not current_env:
                raise ValueError(
                    f"auth_mode='{self.auth_mode.value}' requires NEO_ENV to be set. "
                    f"Allowed values: {sorted(ALLOWED_DEV_ENVIRONMENTS)}. "
                    f"Set NEO_ENV=development for local development."
                )
            if current_env not in ALLOWED_DEV_ENVIRONMENTS:
                raise ValueError(
                    f"auth_mode='{self.auth_mode.value}' is BLOCKED in '{current_env}' environment. "
                    f"Only allowed when NEO_ENV is one of: {sorted(ALLOWED_DEV_ENVIRONMENTS)}. "
                    f"Use auth_mode='azure-ad' or 'oidc' for production deployments."
                )

        # Validate dev_jwt config is provided for DEV_JWT mode
        if self.auth_mode == AuthMode.DEV_JWT:
            if self.dev_jwt is None:
                raise ValueError(
                    "dev_jwt configuration is required when auth_mode='dev-jwt'. "
                    "Provide dev_jwt=DevJWTConfig(secret_key='env:DEV_JWT_SECRET_KEY')"
                )

        # Validate at least one provider for production modes
        if self.auth_mode in {AuthMode.AZURE_AD, AuthMode.OIDC}:
            providers = [
                self.jwt,
                self.oidc,
                self.azure,
                self.cognito,
                self.google,
                self.okta,
                self.auth0,
                self.keycloak,
            ]
            if not any(providers):
                raise ValueError(
                    f"At least one identity provider must be configured for auth_mode='{self.auth_mode.value}'. "
                    "Configure azure, oidc, okta, auth0, keycloak, jwt, cognito, or google."
                )

        # Log configured providers (without secrets)
        configured = []
        if self.dev_jwt:
            configured.append("dev_jwt")
        if self.jwt:
            configured.append("jwt")
        if self.oidc:
            configured.append("oidc")
        if self.azure:
            configured.append("azure")
        if self.cognito:
            configured.append("cognito")
        if self.google:
            configured.append("google")
        if self.okta:
            configured.append("okta")
        if self.auth0:
            configured.append("auth0")
        if self.keycloak:
            configured.append("keycloak")

        logger.info(
            "DecoderConfig initialized",
            extra={
                "auth_mode": self.auth_mode.value,
                "neo_env": current_env or "unset",
                "is_dev_environment": current_env in ALLOWED_DEV_ENVIRONMENTS,
                "providers": configured,
                "cache_backend": self.cache.backend,
                "resolver_type": self.resolver_type,
            },
        )
        return self
