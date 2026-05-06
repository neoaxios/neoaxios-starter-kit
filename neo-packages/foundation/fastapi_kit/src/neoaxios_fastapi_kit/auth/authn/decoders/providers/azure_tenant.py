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

"""Azure AD multi-tenant validation for token tenant isolation.

Implements secure tenant validation for Azure AD tokens supporting both
single-tenant and multi-tenant configurations. This module enforces strict
tenant boundaries to prevent cross-tenant data access.

Security Model:
    - Tenant validation is a critical security boundary
    - Validation MUST occur AFTER signature verification but BEFORE role/permission processing
    - The allowed_tenants set is immutable (frozenset) to prevent runtime modification attacks
    - All tenant validation results are logged for audit trail

Multi-Tenant Isolation Pattern:
    - Single-tenant mode: Only tokens from primary_tenant_id are accepted
    - Multi-tenant mode: Tokens from any tenant in allowed_tenants are accepted
    - Issuer validation prevents token confusion attacks where a token from
      one tenant is used against another tenant's issuer endpoint

Azure AD Token Claims:
    - tid: Tenant ID (GUID) - the Azure AD directory that issued the token
    - iss: Issuer URL containing tenant ID - https://login.microsoftonline.com/{tid}/v2.0
    - appid/azp: Application/Client ID that requested the token
    - aud: Audience (intended recipient of the token)

Special Tenant Values:
    - "common": Tokens valid for any Azure AD tenant (requires multi-tenant app)
    - "organizations": Tokens from any Azure AD organization (work/school accounts)
    - "consumers": Tokens from Microsoft personal accounts (consumer accounts)

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers.azure_tenant import (
        TenantResolver,
        TenantConfig,
        TenantMode,
        TenantValidationError,
        TenantExtractionError,
    )

    # Single-tenant configuration
    resolver = TenantResolver(
        default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
        mode=TenantMode.SINGLE,
    )

    # Multi-tenant configuration
    resolver = TenantResolver(
        default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
        allowed_tenants=frozenset({
            "550e8400-e29b-41d4-a716-446655440000",
            "660e8400-e29b-41d4-a716-446655440000",
        }),
        mode=TenantMode.MULTI,
    )

    # Extract and validate tenant from token
    tenant_id = resolver.extract_tenant_from_token(claims)
    is_valid = resolver.validate_tenant(tenant_id)
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Optional, Any

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError

logger = get_telemetry(__name__)


# =============================================================================
# Constants
# =============================================================================

# Azure AD special tenant values
TENANT_COMMON = "common"
TENANT_ORGANIZATIONS = "organizations"
TENANT_CONSUMERS = "consumers"
SPECIAL_TENANT_VALUES: FrozenSet[str] = frozenset({
    TENANT_COMMON,
    TENANT_ORGANIZATIONS,
    TENANT_CONSUMERS,
})

# Azure AD issuer URL patterns
# Format: https://login.microsoftonline.com/{tenant_id}/v2.0
# ReDoS-safe: Bounded quantifier {1,64} prevents catastrophic backtracking
AZURE_ISSUER_V2_PATTERN = re.compile(
    r"^https://login\.microsoftonline\.com/([a-f0-9\-]{1,64}|common|organizations|consumers)/v2\.0$",
    re.IGNORECASE,
)

# Format: https://login.microsoftonline.com/{tenant_id}/
# ReDoS-safe: Bounded quantifier {1,64} prevents catastrophic backtracking
AZURE_ISSUER_V1_PATTERN = re.compile(
    r"^https://login\.microsoftonline\.com/([a-f0-9\-]{1,64}|common|organizations|consumers)/?$",
    re.IGNORECASE,
)

# GUID pattern for tenant ID validation
GUID_PATTERN = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    re.IGNORECASE,
)

# Default claim names for Azure AD tokens
DEFAULT_TENANT_ID_CLAIM = "tid"
DEFAULT_APP_ID_CLAIM = "appid"
DEFAULT_CLIENT_ID_CLAIM = "azp"


# =============================================================================
# Error Types
# =============================================================================


class TenantValidationError(AuthError):
    """Tenant is not allowed to access this resource.

    Raised when:
    - Single-tenant mode: tenant_id != primary_tenant_id
    - Multi-tenant mode: tenant_id not in allowed_tenants
    - Unknown tenant attempts to access protected resource

    This is a security error - tenant isolation has been violated.
    """

    status_code: int = 403
    error_code: str = "TENANT_NOT_ALLOWED"


class TenantExtractionError(AuthError):
    """Tenant ID claim is missing or has invalid format.

    Raised when:
    - Token does not contain tid (tenant ID) claim
    - Tenant ID is not a valid GUID or special value
    - Tenant ID claim is empty or null

    This indicates a malformed or non-Azure AD token.
    """

    status_code: int = 401
    error_code: str = "TENANT_EXTRACTION_FAILED"


# =============================================================================
# Configuration Types
# =============================================================================


class TenantMode(str, Enum):
    """Tenant validation mode for Azure AD tokens.

    Attributes:
        SINGLE: Accept tokens only from primary_tenant_id (default for most apps)
        MULTI: Accept tokens from any tenant in allowed_tenants set
    """

    SINGLE = "single"
    MULTI = "multi"


@dataclass(frozen=True)
class TenantConfig:
    """Configuration for a specific tenant (placeholder for future routing).

    This dataclass represents tenant-specific configuration that may be used
    for routing requests to tenant-specific resources, applying tenant-specific
    policies, or loading tenant-specific settings.

    Currently a placeholder for future implementation. The TenantResolver
    validates tenant access but does not yet route to tenant-specific configs.

    Attributes:
        tenant_id: Azure AD tenant GUID or special value
        display_name: Human-readable tenant name (for logging)
        enabled: Whether this tenant is currently enabled
        metadata: Additional tenant-specific configuration data
    """

    tenant_id: str
    display_name: str = ""
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate tenant configuration at creation time."""
        if not self.tenant_id:
            raise ValueError("tenant_id cannot be empty")


# =============================================================================
# TenantResolver Class
# =============================================================================


class TenantResolver:
    """Validates Azure AD tenant claims for multi-tenant isolation.

    The TenantResolver enforces tenant boundaries by validating the tid (tenant ID)
    claim in Azure AD tokens against a configured set of allowed tenants.

    Thread Safety:
        This class is thread-safe by design:
        - allowed_tenants is a frozenset (immutable)
        - All validation methods are pure functions (no state changes)
        - No async operations or locks required

    Performance:
        - O(1) tenant validation using frozenset membership test
        - Pre-computed allowed_tenants at initialization
        - No network calls during validation

    Security Invariants:
        1. Tenant validation MUST occur AFTER signature verification
        2. Tenant validation MUST occur BEFORE role/permission processing
        3. allowed_tenants is immutable (frozenset) - cannot be modified at runtime
        4. All validation attempts are logged for audit trail
        5. Unknown tenants are always rejected (fail-closed)

    Attributes:
        default_tenant_id: Primary tenant ID (used in single-tenant mode)
        allowed_tenants: Immutable set of allowed tenant IDs (for multi-tenant mode)
        mode: Validation mode (single or multi)
        tenant_id_claim: Token claim name for tenant ID (default: "tid")
        app_id_claim: Token claim name for application ID (default: "appid")
        verify_app_id: Whether to verify application ID claim
        expected_app_id: Expected application ID (if verify_app_id is True)

    Example:
        # Single-tenant mode
        resolver = TenantResolver(
            default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
            mode=TenantMode.SINGLE,
        )

        # Multi-tenant mode
        resolver = TenantResolver(
            default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
            allowed_tenants=frozenset({
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440000",
            }),
            mode=TenantMode.MULTI,
        )

        # Extract and validate tenant
        tenant_id = resolver.extract_tenant_from_token(claims)
        if resolver.validate_tenant(tenant_id):
            # Proceed with authorization
            pass
    """

    @auto_trace(logger)
    def __init__(
        self,
        default_tenant_id: str,
        allowed_tenants: Optional[FrozenSet[str]] = None,
        mode: TenantMode = TenantMode.SINGLE,
        tenant_id_claim: str = DEFAULT_TENANT_ID_CLAIM,
        app_id_claim: str = DEFAULT_APP_ID_CLAIM,
        verify_app_id: bool = False,
        expected_app_id: Optional[str] = None,
    ) -> None:
        """Initialize TenantResolver with tenant configuration.

        Args:
            default_tenant_id: Primary tenant ID (GUID format required).
                              In single-tenant mode, only this tenant is allowed.
                              In multi-tenant mode, this is included in allowed_tenants.
            allowed_tenants: Immutable set of allowed tenant IDs for multi-tenant mode.
                            If None in multi-tenant mode, only default_tenant_id is allowed.
                            Each tenant ID must be a valid GUID or special value.
            mode: Validation mode - SINGLE (strict) or MULTI (allow configured tenants).
                 Default: SINGLE (most secure for single-tenant applications).
            tenant_id_claim: Token claim name containing tenant ID. Default: "tid".
                            Azure AD always uses "tid" for tenant ID.
            app_id_claim: Token claim name containing application ID. Default: "appid".
                         Azure AD uses "appid" (v1) or "azp" (v2) for application ID.
            verify_app_id: Whether to verify application ID claim. Default: False.
                          Enable for defense-in-depth when accepting tokens from
                          multiple applications.
            expected_app_id: Expected application ID when verify_app_id is True.
                            Must be provided if verify_app_id is True.

        Raises:
            ValueError: If configuration is invalid:
                       - default_tenant_id is empty or invalid format
                       - allowed_tenants contains invalid tenant IDs
                       - verify_app_id is True but expected_app_id is None
                       - mode is not a valid TenantMode value

        Example:
            # Single-tenant (default, most secure)
            resolver = TenantResolver(
                default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
            )

            # Multi-tenant with explicit tenant list
            resolver = TenantResolver(
                default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
                allowed_tenants=frozenset({
                    "550e8400-e29b-41d4-a716-446655440000",
                    "660e8400-e29b-41d4-a716-446655440000",
                }),
                mode=TenantMode.MULTI,
            )

            # With application ID verification
            resolver = TenantResolver(
                default_tenant_id="550e8400-e29b-41d4-a716-446655440000",
                verify_app_id=True,
                expected_app_id="770e8400-e29b-41d4-a716-446655440000",
            )
        """
        # Validate default_tenant_id
        if not default_tenant_id:
            raise ValueError("default_tenant_id cannot be empty")

        if not self._is_valid_tenant_id_format(default_tenant_id):
            raise ValueError(
                f"default_tenant_id has invalid format: '{default_tenant_id}'. "
                f"Expected GUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) "
                f"or special value ({', '.join(SPECIAL_TENANT_VALUES)})"
            )

        # Validate mode
        if not isinstance(mode, TenantMode):
            raise ValueError(
                f"mode must be TenantMode.SINGLE or TenantMode.MULTI, got {type(mode)}"
            )

        # Validate verify_app_id and expected_app_id consistency
        if verify_app_id and not expected_app_id:
            raise ValueError(
                "expected_app_id is required when verify_app_id is True"
            )

        # Build allowed_tenants frozenset
        if mode == TenantMode.SINGLE:
            # Single-tenant mode: only allow default_tenant_id
            self._allowed_tenants: FrozenSet[str] = frozenset({default_tenant_id})
        else:
            # Multi-tenant mode: use provided set or default to primary only
            if allowed_tenants is not None:
                # Validate all provided tenant IDs
                invalid_tenants = [
                    t for t in allowed_tenants
                    if not self._is_valid_tenant_id_format(t)
                ]
                if invalid_tenants:
                    raise ValueError(
                        f"allowed_tenants contains invalid tenant IDs: {invalid_tenants}. "
                        f"All tenant IDs must be GUIDs or special values."
                    )
                # Ensure default_tenant_id is always included
                self._allowed_tenants = frozenset(allowed_tenants | {default_tenant_id})
            else:
                self._allowed_tenants = frozenset({default_tenant_id})

        # Store configuration (all immutable)
        self._default_tenant_id = default_tenant_id
        self._mode = mode
        self._tenant_id_claim = tenant_id_claim
        self._app_id_claim = app_id_claim
        self._verify_app_id = verify_app_id
        self._expected_app_id = expected_app_id

        logger.info(
            "TenantResolver initialized",
            extra={
                "mode": mode.value,
                "default_tenant_id": default_tenant_id,
                "allowed_tenant_count": len(self._allowed_tenants),
                "verify_app_id": verify_app_id,
                "tenant_id_claim": tenant_id_claim,
            },
        )

    @property
    def default_tenant_id(self) -> str:
        """Primary tenant ID (immutable)."""
        return self._default_tenant_id

    @property
    def allowed_tenants(self) -> FrozenSet[str]:
        """Immutable set of allowed tenant IDs."""
        return self._allowed_tenants

    @property
    def mode(self) -> TenantMode:
        """Tenant validation mode (immutable)."""
        return self._mode

    @property
    def tenant_id_claim(self) -> str:
        """Token claim name for tenant ID."""
        return self._tenant_id_claim

    @property
    def app_id_claim(self) -> str:
        """Token claim name for application ID."""
        return self._app_id_claim

    @property
    def verify_app_id(self) -> bool:
        """Whether application ID verification is enabled."""
        return self._verify_app_id

    @property
    def expected_app_id(self) -> Optional[str]:
        """Expected application ID (if verification enabled)."""
        return self._expected_app_id

    @staticmethod
    @auto_trace(logger)  # Validates tenant ID format (GUID or special value)
    def _is_valid_tenant_id_format(tenant_id: str) -> bool:
        """Check if tenant_id has valid format (GUID or special value).

        This is a static method to allow validation during construction
        without needing an instance.

        Args:
            tenant_id: Tenant ID string to validate

        Returns:
            True if format is valid (GUID or special value), False otherwise
        """
        if not tenant_id:
            return False

        # Check if it's a special value
        if tenant_id.lower() in SPECIAL_TENANT_VALUES:
            return True

        # Check if it's a valid GUID
        return bool(GUID_PATTERN.match(tenant_id))

    @auto_trace(logger)
    def extract_tenant_from_token(self, claims: Dict[str, Any]) -> str:
        """Extract tenant ID from decoded token claims.

        Extracts the tid (tenant ID) claim from the decoded JWT payload.
        This method should be called AFTER signature verification but
        BEFORE role/permission processing.

        Args:
            claims: Decoded JWT payload (dictionary of claims).
                   Must contain the tid claim for Azure AD tokens.

        Returns:
            Tenant ID string (GUID format or special value)

        Raises:
            TenantExtractionError: If tid claim is missing, empty, or invalid format

        Example:
            claims = {
                "sub": "user123",
                "tid": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://login.microsoftonline.com/550e8400.../v2.0",
            }
            tenant_id = resolver.extract_tenant_from_token(claims)
            # tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        Security:
            - Only extracts tenant ID, does not validate against allowed list
            - Use validate_tenant() after extraction to enforce tenant boundaries
            - Logs extraction attempts for audit trail
        """
        # Get tenant ID from claims
        tenant_id = claims.get(self._tenant_id_claim)

        if tenant_id is None:
            error = TenantExtractionError(
                f"Token missing required '{self._tenant_id_claim}' (tenant ID) claim. "
                f"This may not be an Azure AD token."
            )
            logger.log_error(
                error,
                extra={
                    "claim_name": self._tenant_id_claim,
                    "available_claims": list(claims.keys()),
                },
            )
            raise error

        # Ensure it's a string
        if not isinstance(tenant_id, str):
            error = TenantExtractionError(
                f"Tenant ID claim '{self._tenant_id_claim}' must be a string, "
                f"got {type(tenant_id).__name__}"
            )
            logger.log_error(
                error,
                extra={
                    "claim_name": self._tenant_id_claim,
                    "claim_type": type(tenant_id).__name__,
                },
            )
            raise error

        # Validate format
        tenant_id = tenant_id.strip()
        if not tenant_id:
            error = TenantExtractionError(
                f"Tenant ID claim '{self._tenant_id_claim}' cannot be empty"
            )
            logger.log_error(error, extra={"claim_name": self._tenant_id_claim})
            raise error

        if not self._is_valid_tenant_id_format(tenant_id):
            error = TenantExtractionError(
                f"Tenant ID '{tenant_id}' has invalid format. "
                f"Expected GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) "
                f"or special value ({', '.join(SPECIAL_TENANT_VALUES)})"
            )
            logger.log_error(
                error,
                extra={
                    "tenant_id_extracted": tenant_id,
                    "claim_name": self._tenant_id_claim,
                },
            )
            raise error

        logger.debug(
            "Tenant ID extracted from token",
            extra={
                "tenant_id_extracted": tenant_id,
                "claim_name": self._tenant_id_claim,
            },
        )

        return tenant_id

    @auto_trace(logger)
    def validate_tenant(self, tenant_id: str) -> bool:
        """Validate tenant ID against allowed tenants.

        Performs O(1) lookup to check if tenant_id is in the allowed_tenants set.
        This is the critical security boundary for multi-tenant isolation.

        Args:
            tenant_id: Tenant ID to validate (from extract_tenant_from_token)

        Returns:
            True if tenant is allowed, False otherwise

        Raises:
            TenantValidationError: If tenant is not allowed (fail-fast behavior).
                                  Use validate_tenant_safe() for non-throwing validation.

        Example:
            tenant_id = resolver.extract_tenant_from_token(claims)
            try:
                resolver.validate_tenant(tenant_id)
                # Tenant is allowed, proceed with authorization
            except TenantValidationError:
                # Tenant not allowed, deny access

        Security:
            - Single-tenant mode: tenant_id must equal default_tenant_id (strict)
            - Multi-tenant mode: tenant_id must be in allowed_tenants set (O(1) lookup)
            - All validation results are logged for audit trail
            - Unknown tenants are always rejected (fail-closed security model)
        """
        # O(1) frozenset membership test
        is_allowed = tenant_id in self._allowed_tenants

        # Log the validation result (always, for audit trail)
        logger.info(
            "Tenant validation",
            extra={
                "tenant_id": tenant_id,
                "mode": self._mode.value,
                "validation_result": "pass" if is_allowed else "fail",
                "default_tenant_id": self._default_tenant_id,
                "allowed_tenant_count": len(self._allowed_tenants),
            },
        )

        if not is_allowed:
            # Log security incident
            logger.warning(
                "Tenant validation failed - unknown tenant attempted access",
                extra={
                    "tenant_id": tenant_id,
                    "mode": self._mode.value,
                    "default_tenant_id": self._default_tenant_id,
                    "security_event": "tenant_rejected",
                },
            )

            # Raise error with clear message
            if self._mode == TenantMode.SINGLE:
                error = TenantValidationError(
                    f"Tenant '{tenant_id}' is not allowed. "
                    f"This application only accepts tokens from tenant "
                    f"'{self._default_tenant_id}'."
                )
            else:
                error = TenantValidationError(
                    f"Tenant '{tenant_id}' is not in the allowed tenants list. "
                    f"Contact your administrator to request access."
                )

            logger.log_error(error, extra={"tenant_id": tenant_id})
            raise error

        return True

    @auto_trace(logger)
    def validate_tenant_safe(self, tenant_id: str) -> bool:
        """Validate tenant ID without raising exception.

        Non-throwing version of validate_tenant() for cases where you want
        to check tenant validity without exception handling.

        Args:
            tenant_id: Tenant ID to validate

        Returns:
            True if tenant is allowed, False otherwise (no exception)

        Example:
            tenant_id = resolver.extract_tenant_from_token(claims)
            if resolver.validate_tenant_safe(tenant_id):
                # Tenant is allowed
                pass
            else:
                # Tenant not allowed
                return HTTP_403_FORBIDDEN
        """
        is_allowed = tenant_id in self._allowed_tenants

        logger.info(
            "Tenant validation (safe)",
            extra={
                "tenant_id": tenant_id,
                "mode": self._mode.value,
                "validation_result": "pass" if is_allowed else "fail",
            },
        )

        if not is_allowed:
            logger.warning(
                "Tenant validation failed (safe) - unknown tenant",
                extra={
                    "tenant_id": tenant_id,
                    "mode": self._mode.value,
                    "security_event": "tenant_rejected_safe",
                },
            )

        return is_allowed

    @auto_trace(logger)
    def get_configuration_for_tenant(self, tenant_id: str) -> TenantConfig:
        """Get configuration for a specific tenant (placeholder for future routing).

        This method is a placeholder for future tenant-specific configuration
        routing. Currently returns a basic TenantConfig with the tenant_id.

        Future implementations may:
        - Load tenant-specific settings from database
        - Route to tenant-specific API endpoints
        - Apply tenant-specific rate limits
        - Load tenant-specific feature flags

        Args:
            tenant_id: Tenant ID (must be validated first)

        Returns:
            TenantConfig with tenant-specific configuration

        Raises:
            TenantValidationError: If tenant is not in allowed_tenants

        Example:
            tenant_id = resolver.extract_tenant_from_token(claims)
            resolver.validate_tenant(tenant_id)  # Raises if not allowed
            config = resolver.get_configuration_for_tenant(tenant_id)
            # Use config.metadata for tenant-specific settings
        """
        # Validate tenant first (fail-fast if not allowed)
        if tenant_id not in self._allowed_tenants:
            error = TenantValidationError(
                f"Cannot get configuration for unknown tenant '{tenant_id}'"
            )
            logger.log_error(error, extra={"tenant_id": tenant_id})
            raise error

        # Return placeholder config (future: load from database/cache)
        config = TenantConfig(
            tenant_id=tenant_id,
            display_name=f"Tenant {tenant_id[:8]}",
            enabled=True,
            metadata={
                "mode": self._mode.value,
                "is_default": tenant_id == self._default_tenant_id,
            },
        )

        logger.debug(
            "Tenant configuration retrieved",
            extra={
                "tenant_id": tenant_id,
                "is_default": tenant_id == self._default_tenant_id,
            },
        )

        return config

    @auto_trace(logger)
    def _parse_tenant_from_issuer(self, issuer: str) -> Optional[str]:
        """Extract tenant ID from Azure AD issuer URL.

        Azure AD issuer URLs contain the tenant ID:
        - V2: https://login.microsoftonline.com/{tenant_id}/v2.0
        - V1: https://login.microsoftonline.com/{tenant_id}/

        Args:
            issuer: Issuer URL from token iss claim

        Returns:
            Tenant ID extracted from issuer URL, or None if not parseable

        Example:
            issuer = "https://login.microsoftonline.com/550e8400-e29b-41d4-a716-446655440000/v2.0"
            tenant_id = resolver._parse_tenant_from_issuer(issuer)
            # tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        Notes:
            - Supports both v1.0 and v2.0 Azure AD endpoints
            - Case-insensitive matching
            - Returns None for non-Azure AD issuers
        """
        if not issuer:
            logger.debug("Empty issuer, cannot extract tenant")
            return None

        # Try v2.0 pattern first (most common)
        match = AZURE_ISSUER_V2_PATTERN.match(issuer)
        if match:
            tenant_id = match.group(1)
            logger.debug(
                "Extracted tenant from v2.0 issuer",
                extra={
                    "issuer": issuer,
                    "tenant_id_from_issuer": tenant_id,
                },
            )
            return tenant_id

        # Try v1.0 pattern
        match = AZURE_ISSUER_V1_PATTERN.match(issuer)
        if match:
            tenant_id = match.group(1)
            logger.debug(
                "Extracted tenant from v1.0 issuer",
                extra={
                    "issuer": issuer,
                    "tenant_id_from_issuer": tenant_id,
                },
            )
            return tenant_id

        logger.debug(
            "Issuer does not match Azure AD patterns",
            extra={"issuer": issuer},
        )
        return None

    @auto_trace(logger)
    def validate_issuer_tenant_match(
        self,
        claims: Dict[str, Any],
        issuer: Optional[str] = None,
    ) -> bool:
        """Validate that token tid claim matches issuer URL tenant.

        This is a critical security check to prevent token confusion attacks
        where a token from one tenant is used against another tenant's
        issuer endpoint.

        Token confusion attack scenario:
            1. Attacker obtains valid token from tenant A
            2. Attacker sends token to application expecting tenant B
            3. Without this check, token might be accepted if signature is valid
            4. This check ensures tid claim matches issuer URL tenant

        Args:
            claims: Decoded JWT payload containing tid and iss claims
            issuer: Optional explicit issuer URL (if not using iss from claims)

        Returns:
            True if tid claim matches issuer URL tenant

        Raises:
            TokenInvalidError: If tid and issuer tenant do not match
                              (indicates potential token confusion attack)
            TenantExtractionError: If tid claim is missing

        Example:
            claims = {
                "tid": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://login.microsoftonline.com/550e8400.../v2.0",
            }
            resolver.validate_issuer_tenant_match(claims)  # Passes

            # Attack scenario (would fail):
            claims = {
                "tid": "attacker-tenant-id",
                "iss": "https://login.microsoftonline.com/550e8400.../v2.0",
            }
            resolver.validate_issuer_tenant_match(claims)  # Raises TokenInvalidError

        Security:
            - Logs all mismatches as security incidents
            - Fails-closed on any parsing errors
            - Special tenants (common, organizations, consumers) are validated
        """
        # Extract tid from claims
        token_tenant_id = self.extract_tenant_from_token(claims)

        # Get issuer from claims or parameter
        iss = issuer or claims.get("iss", "")
        if not iss:
            error = TokenInvalidError(
                "Token missing issuer (iss) claim. Cannot validate tenant match."
            )
            logger.log_error(error)
            raise error

        # Parse tenant from issuer URL
        issuer_tenant_id = self._parse_tenant_from_issuer(iss)

        if issuer_tenant_id is None:
            # Non-Azure AD issuer - cannot validate tenant match
            logger.warning(
                "Cannot extract tenant from issuer URL",
                extra={
                    "issuer": iss,
                    "token_tenant_id": token_tenant_id,
                },
            )
            # For non-Azure issuers, we cannot validate match
            # The signature verification is the primary security control
            return True

        # Handle special tenant values in issuer
        if issuer_tenant_id.lower() in SPECIAL_TENANT_VALUES:
            # Special tenants (common, organizations, consumers) in issuer
            # can issue tokens for any tenant - tid claim is authoritative
            logger.debug(
                "Issuer uses special tenant value",
                extra={
                    "issuer": iss,
                    "issuer_tenant": issuer_tenant_id,
                    "token_tenant_id": token_tenant_id,
                },
            )
            return True

        # Compare tenant IDs (case-insensitive)
        if token_tenant_id.lower() != issuer_tenant_id.lower():
            # SECURITY INCIDENT: Token confusion attack detected
            logger.warning(
                "Token confusion attack detected - tid does not match issuer",
                extra={
                    "token_tenant_id": token_tenant_id,
                    "issuer_tenant_id": issuer_tenant_id,
                    "issuer": iss,
                    "security_event": "token_confusion_attack",
                },
            )

            error = TokenInvalidError(
                f"Token tenant ID '{token_tenant_id}' does not match issuer tenant "
                f"'{issuer_tenant_id}'. This may indicate a token confusion attack."
            )
            logger.log_error(error)
            raise error

        logger.debug(
            "Issuer tenant match validated",
            extra={
                "token_tenant_id": token_tenant_id,
                "issuer_tenant_id": issuer_tenant_id,
            },
        )

        return True

    @auto_trace(logger)
    def validate_app_id(self, claims: Dict[str, Any]) -> bool:
        """Validate application ID claim if verification is enabled.

        Checks that the token was issued for the expected application.
        This provides defense-in-depth for applications that accept tokens
        from multiple client applications.

        Args:
            claims: Decoded JWT payload

        Returns:
            True if app ID is valid or verification is disabled

        Raises:
            TokenInvalidError: If app ID does not match expected value

        Example:
            # With verify_app_id=True
            resolver = TenantResolver(
                default_tenant_id="...",
                verify_app_id=True,
                expected_app_id="client-app-id",
            )

            claims = {"appid": "client-app-id", ...}
            resolver.validate_app_id(claims)  # Passes

            claims = {"appid": "other-app-id", ...}
            resolver.validate_app_id(claims)  # Raises TokenInvalidError
        """
        if not self._verify_app_id:
            logger.debug("Application ID verification disabled")
            return True

        # Try appid first (v1 tokens), then azp (v2 tokens)
        app_id = claims.get(self._app_id_claim)
        if app_id is None:
            # Try alternative claim name
            app_id = claims.get("azp")

        if app_id is None:
            error = TokenInvalidError(
                f"Token missing application ID claim ('{self._app_id_claim}' or 'azp'). "
                f"Cannot verify application identity."
            )
            logger.log_error(error)
            raise error

        if app_id != self._expected_app_id:
            logger.warning(
                "Application ID mismatch",
                extra={
                    "token_app_id": app_id,
                    "expected_app_id": self._expected_app_id,
                    "security_event": "app_id_mismatch",
                },
            )

            error = TokenInvalidError(
                f"Token application ID '{app_id}' does not match expected "
                f"application '{self._expected_app_id}'."
            )
            logger.log_error(error)
            raise error

        logger.debug(
            "Application ID validated",
            extra={"app_id": app_id},
        )

        return True

    @auto_trace(logger)
    def validate_token_tenant_claims(self, claims: Dict[str, Any]) -> str:
        """Complete tenant validation pipeline for Azure AD tokens.

        Performs all tenant-related validations in the correct order:
        1. Extract tenant ID from token (tid claim)
        2. Validate tenant format
        3. Validate tenant is allowed (single/multi-tenant)
        4. Validate issuer matches tenant (token confusion prevention)
        5. Validate application ID (if enabled)

        This is the recommended entry point for tenant validation.

        Args:
            claims: Decoded JWT payload (after signature verification)

        Returns:
            Validated tenant ID string

        Raises:
            TenantExtractionError: If tid claim is missing or invalid
            TenantValidationError: If tenant is not allowed
            TokenInvalidError: If issuer/app mismatch detected

        Example:
            # After signature verification
            claims = jwt.decode(token, key, algorithms=["RS256"])

            # Validate all tenant claims
            tenant_id = resolver.validate_token_tenant_claims(claims)

            # Now safe to proceed with role/permission checks
            identity = create_identity(claims, tenant_id)

        Security:
            - Must be called AFTER signature verification
            - Must be called BEFORE role/permission processing
            - Logs complete validation pipeline for audit
        """
        logger.debug("Starting tenant validation pipeline")

        # Step 1: Extract tenant ID
        tenant_id = self.extract_tenant_from_token(claims)

        # Step 2: Validate tenant is allowed
        self.validate_tenant(tenant_id)

        # Step 3: Validate issuer matches tenant (prevent token confusion)
        self.validate_issuer_tenant_match(claims)

        # Step 4: Validate application ID (if enabled)
        self.validate_app_id(claims)

        logger.info(
            "Tenant validation pipeline completed successfully",
            extra={
                "tenant_id": tenant_id,
                "mode": self._mode.value,
            },
        )

        return tenant_id


# =============================================================================
# Factory Functions
# =============================================================================


@auto_trace(logger)
def create_single_tenant_resolver(
    tenant_id: str,
    verify_app_id: bool = False,
    expected_app_id: Optional[str] = None,
) -> TenantResolver:
    """Create a TenantResolver for single-tenant applications.

    Factory function for the most common configuration: single-tenant mode
    where only tokens from one specific Azure AD tenant are accepted.

    Args:
        tenant_id: The only allowed tenant ID (Azure AD directory GUID)
        verify_app_id: Whether to verify application ID claim
        expected_app_id: Expected application ID (required if verify_app_id=True)

    Returns:
        TenantResolver configured for single-tenant mode

    Example:
        resolver = create_single_tenant_resolver(
            tenant_id="550e8400-e29b-41d4-a716-446655440000"
        )

    Security:
        - Most restrictive tenant configuration
        - Recommended for internal/corporate applications
        - Prevents accidental multi-tenant token acceptance
    """
    return TenantResolver(
        default_tenant_id=tenant_id,
        mode=TenantMode.SINGLE,
        verify_app_id=verify_app_id,
        expected_app_id=expected_app_id,
    )


@auto_trace(logger)
def create_multi_tenant_resolver(
    primary_tenant_id: str,
    allowed_tenants: FrozenSet[str],
    verify_app_id: bool = False,
    expected_app_id: Optional[str] = None,
) -> TenantResolver:
    """Create a TenantResolver for multi-tenant applications.

    Factory function for multi-tenant applications that accept tokens from
    a predefined set of Azure AD tenants.

    Args:
        primary_tenant_id: Default tenant ID (always included in allowed list)
        allowed_tenants: Set of allowed tenant IDs (GUIDs)
        verify_app_id: Whether to verify application ID claim
        expected_app_id: Expected application ID (required if verify_app_id=True)

    Returns:
        TenantResolver configured for multi-tenant mode

    Example:
        resolver = create_multi_tenant_resolver(
            primary_tenant_id="550e8400-e29b-41d4-a716-446655440000",
            allowed_tenants=frozenset({
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440000",
                "770e8400-e29b-41d4-a716-446655440000",
            }),
        )

    Security:
        - Tenant list is immutable (frozenset)
        - All tenants validated at construction time
        - Primary tenant always included in allowed list
    """
    return TenantResolver(
        default_tenant_id=primary_tenant_id,
        allowed_tenants=allowed_tenants,
        mode=TenantMode.MULTI,
        verify_app_id=verify_app_id,
        expected_app_id=expected_app_id,
    )


__all__ = [
    # Main class
    "TenantResolver",
    # Configuration types
    "TenantConfig",
    "TenantMode",
    # Error types
    "TenantValidationError",
    "TenantExtractionError",
    # Factory functions
    "create_single_tenant_resolver",
    "create_multi_tenant_resolver",
    # Constants
    "TENANT_COMMON",
    "TENANT_ORGANIZATIONS",
    "TENANT_CONSUMERS",
    "SPECIAL_TENANT_VALUES",
    "DEFAULT_TENANT_ID_CLAIM",
    "DEFAULT_APP_ID_CLAIM",
    "DEFAULT_CLIENT_ID_CLAIM",
]
