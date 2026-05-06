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

"""Auth0-specific OIDC decoder for Auth0 tokens.

Validates tokens issued by Auth0 tenants with Auth0-specific features
including custom claims namespaces, organizations, and email verification.

This decoder extends OIDCDecoder to add Auth0-specific functionality:
- Auto-construction of issuer and JWKS URIs from domain
- Auth0-specific claims handling (org_id, email_verified, custom namespaces)
- Support for Auth0 token types (access, ID, refresh)
- Auth0 domain validation
- Full JWKS signature verification (inherited from OIDCDecoder)

Auth0 Token Structure:
    Auth0 issues tokens from: https://{domain}/
    Domain format: {tenant}.{region}.auth0.com or custom domain
    Example: myapp.us.auth0.com, myapp.eu.auth0.com

Auth0-Specific Claims:
    - org_id: Organization identifier (Auth0 Organizations)
    - email_verified: Email verification status (boolean)
    - sub: Subject (format: auth0|{id} or {provider}|{id})
    - Custom claims: Must use namespaced format (https://...)
    - aud: Audience (API identifier or client_id)
    - azp: Authorized party (client_id that requested token)

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import Auth0Decoder

    # Basic configuration
    decoder = Auth0Decoder(
        domain="myapp.us.auth0.com",
        client_id="abc123def456ghi789",
    )

    # With audience validation (recommended for APIs)
    decoder = Auth0Decoder(
        domain="myapp.us.auth0.com",
        client_id="abc123def456ghi789",
        audience="https://api.myapp.com",
    )

    # Decode token with Auth0-specific claims
    identity = await decoder.decode(token)
    logger.info(
        f"Decoded Auth0 token",
        user_id=identity.user_id,
        org_id=identity.attributes.get("org_id"),
        email_verified=identity.attributes.get("email_verified"),
    )

Environment Variables:
    Create decoder from environment variables:
    - AUTH0_DOMAIN: Auth0 domain (e.g., "myapp.us.auth0.com")
    - AUTH0_CLIENT_ID: OAuth 2.0 client ID
    - AUTH0_CLIENT_SECRET: OAuth 2.0 client secret (optional)
    - AUTH0_AUDIENCE: Expected audience claim (recommended)
    - AUTH0_SCOPE: OAuth scopes (optional)

    decoder = create_auth0_decoder()  # Reads from environment
"""

import os
import re
from typing import Any, Dict, Optional

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError

logger = get_telemetry(__name__)


class Auth0Decoder(OIDCDecoder):
    """Decode and validate Auth0-issued OIDC tokens.

    Extends OIDCDecoder with Auth0-specific features:
    - Automatic issuer/JWKS URI construction from domain
    - Auth0 custom claims extraction (org_id, email_verified, namespaced claims)
    - Support for Auth0 Organizations
    - Auth0 domain validation
    - Token type detection (access vs. ID tokens)
    - Full JWKS signature verification (inherited from OIDCDecoder)

    This decoder demonstrates how to extend OIDCDecoder for provider-specific
    optimizations. The parent OIDCDecoder handles all signature verification,
    while Auth0Decoder focuses on Auth0-specific URL construction and claims.

    Attributes:
        domain: Auth0 domain (e.g., "myapp.us.auth0.com")
        client_id: OAuth 2.0 client ID from Auth0 application
        client_secret: OAuth 2.0 client secret (optional, for token introspection)
        audience: Expected audience claim (recommended for access tokens)
        scope: OAuth scopes for validation (optional)
        issuer: Auto-constructed from domain (https://{domain}/)
        jwks_uri: Auto-constructed JWKS endpoint for key retrieval
        clock_skew_seconds: Clock skew tolerance for time-based claims
    """

    @auto_trace(logger)
    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    ):
        """Initialize Auth0 decoder with domain configuration.

        Args:
            domain: Auth0 domain WITHOUT https:// prefix.
                   Examples: "myapp.us.auth0.com", "myapp.eu.auth0.com"
                   Custom domains also supported: "auth.mycompany.com"
            client_id: OAuth 2.0 client ID from your Auth0 application.
                      Format: alphanumeric string (~32 characters).
            client_secret: OAuth 2.0 client secret (optional). Required for
                          token introspection but not for JWT signature validation.
                          Supports "env:VAR_NAME" format for environment variable lookup.
            audience: Expected audience claim (aud) for validation. RECOMMENDED
                     for access tokens. Should be your API identifier.
                     Example: "https://api.myapp.com"
            scope: OAuth scopes for validation (optional). Space-separated string.
                  Example: "openid profile email read:users"
            clock_skew_seconds: Clock skew tolerance in seconds for exp/nbf
                               validation. Default: 30 seconds.

        Raises:
            AuthError: If domain format is invalid or required configuration
                      is missing

        Example:
            # Basic setup
            decoder = Auth0Decoder(
                domain="myapp.us.auth0.com",
                client_id="abc123def456",
            )

            # Production setup with audience validation
            decoder = Auth0Decoder(
                domain="myapp.us.auth0.com",
                client_id="abc123def456",
                audience="https://api.myapp.com",
                client_secret="env:AUTH0_CLIENT_SECRET",
            )
        """
        # Validate domain format (must NOT include https://)
        if not self._validate_domain(domain):
            error = AuthError(
                f"Invalid Auth0 domain format: '{domain}'. "
                f"Expected format: 'tenant.region.auth0.com' (no https:// prefix). "
                f"Example: 'myapp.us.auth0.com'"
            )
            logger.log_error(error=error)
            raise error

        # Validate client_id is present
        if not client_id:
            error = AuthError("Auth0 client_id is required")
            logger.log_error(error=error)
            raise error

        # Store Auth0-specific configuration
        self.domain = domain
        self.scope = scope

        # Auto-construct issuer URL
        # Auth0 format: https://{domain}/ (note trailing slash is REQUIRED)
        issuer = f"https://{domain}/"

        # Auto-construct JWKS URI for public key retrieval
        # Auth0 format: https://{domain}/.well-known/jwks.json
        jwks_uri = f"https://{domain}/.well-known/jwks.json"

        # Call parent OIDCDecoder constructor with constructed URLs
        # This sets up JWKS signature verification automatically
        super().__init__(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience or client_id,
            jwks_uri=jwks_uri,
            clock_skew_seconds=clock_skew_seconds,
            key_cache=None,  # Can be overridden in factory function
        )

        logger.info(
            f"Initialized Auth0Decoder for domain={domain}, "
            f"issuer={self.issuer}, jwks_uri={self.jwks_uri}, "
            f"audience={self.audience}, "
            f"has_client_secret={bool(client_secret)}"
        )

    @auto_trace(logger)
    def _extract_oidc_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Override parent to extract Auth0-specific identity claims.

        Maps Auth0-specific claims to IdentityContext:
        - sub -> user_id (Auth0 user ID in format provider|id)
        - iss -> issuer (validated Auth0 domain)
        - org_id -> stored in attributes["org_id"] (if present)
        - email_verified -> stored in attributes["email_verified"]
        - permissions -> permissions (Auth0 API permissions array, takes priority)
        - scope -> permissions (OAuth scopes string, fallback if no permissions claim)
        - Custom claims (https://...) -> stored in attributes
        - azp -> stored in attributes["azp"] (authorized party)

        Auth0 Token Types:
        - ID tokens: Contain user profile claims (email, name, picture, etc.)
        - Access tokens: Contain scopes and minimal user info

        Args:
            claims: Decoded and validated JWT payload claims

        Returns:
            IdentityContext with user identity and Auth0-specific attributes

        Raises:
            TokenInvalidError: If required claims (sub) are missing
        """
        # Extract required claims
        user_id = claims.get("sub")
        if not user_id:
            error = TokenInvalidError(
                "Auth0 token missing required 'sub' (subject) claim"
            )
            logger.log_error(error=error)
            raise error

        # Extract tenant_id (org_id if present, otherwise domain)
        tenant_id = claims.get("org_id", self.domain)

        # Extract roles from custom claims (Auth0 uses namespaced claims)
        # Common patterns: https://myapp.com/roles, https://myapp.com/app_metadata
        roles = frozenset()
        for claim_name, claim_value in claims.items():
            if claim_name.endswith("/roles") and isinstance(claim_value, (list, str)):
                if isinstance(claim_value, str):
                    roles = frozenset(r.strip() for r in claim_value.split(",") if r.strip())
                else:
                    roles = frozenset(claim_value)
                break

        # Extract permissions from Auth0 tokens
        # Auth0 uses "permissions" claim (array) for API permissions
        # and "scope" claim (string) for OIDC scopes
        # Priority: permissions > scope
        permissions_claim = claims.get("permissions")

        if permissions_claim and isinstance(permissions_claim, list):
            # Auth0 API permissions (e.g., ["read:users", "write:users"])
            permissions = frozenset(permissions_claim)
        else:
            # Fallback to scope claim for OIDC tokens
            scope_claim = claims.get("scope", "")
            if isinstance(scope_claim, str):
                # Auth0 uses space-separated scopes
                permissions = frozenset(
                    s.strip() for s in scope_claim.split() if s.strip()
                )
            elif isinstance(scope_claim, list):
                permissions = frozenset(scope_claim)
            else:
                permissions = frozenset()

        # Extract Auth0-specific attributes
        # Exclude standard JWT claims
        standard_claims = {
            "sub",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "azp",
            "scope",
            "org_id",
        }

        attributes = {}

        # Add all non-standard claims (including custom namespaced claims)
        for claim_name, claim_value in claims.items():
            if claim_name not in standard_claims:
                attributes[claim_name] = claim_value

        # Explicitly add important Auth0 claims to attributes
        if "org_id" in claims:
            attributes["org_id"] = claims["org_id"]
        if "email_verified" in claims:
            attributes["email_verified"] = claims["email_verified"]
        if "azp" in claims:
            attributes["azp"] = claims["azp"]

        # Parse sub to extract identity provider
        # Format: provider|id (e.g., "auth0|123", "google-oauth2|456")
        sub_parts = user_id.split("|", 1)
        if len(sub_parts) == 2:
            attributes["sub_iss"] = sub_parts[0]  # Identity provider
            attributes["sub_id"] = sub_parts[1]   # Provider-specific ID

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            attributes=attributes,
            provider="auth0",
            issuer=claims.get("iss", self.issuer),
            provider_user_id=user_id,  # Auth0 sub is the provider user ID
        )

        logger.debug(
            f"Extracted Auth0 identity: user_id={user_id}, "
            f"tenant_id={tenant_id}, roles={len(roles)}, "
            f"permissions={len(permissions)}, "
            f"org_id={attributes.get('org_id')}, "
            f"email_verified={attributes.get('email_verified')}, "
            f"sub_iss={attributes.get('sub_iss')}"
        )

        return identity

    @auto_trace(logger)
    def _validate_domain(self, domain: str) -> bool:
        """Validate Auth0 domain format.

        Auth0 domains follow patterns:
        - Regional tenant: "{tenant}.{region}.auth0.com"
          Examples: "myapp.us.auth0.com", "myapp.eu.auth0.com"
        - Legacy tenant: "{tenant}.auth0.com"
        - Custom domain: "{custom}.com" (requires DNS setup)

        Domain must NOT include:
        - https:// prefix
        - Trailing slash
        - Path components

        Args:
            domain: Auth0 domain to validate

        Returns:
            True if format appears valid, False otherwise

        Notes:
            - This is a basic format check, not a connectivity test
            - Custom domains may not match standard patterns
            - Production validation should verify DNS/TLS certificates
        """
        # Basic format check: must contain a dot and not be empty
        if not domain or "." not in domain:
            logger.warning(
                f"Invalid domain format: '{domain}' - must be a domain name"
            )
            return False

        # Must NOT contain https:// or http://
        if domain.startswith("https://") or domain.startswith("http://"):
            logger.warning(
                f"Invalid domain format: '{domain}' - must NOT include protocol. "
                f"Use domain only (e.g., 'myapp.us.auth0.com')"
            )
            return False

        # Must NOT contain path components
        if "/" in domain:
            logger.warning(
                f"Invalid domain format: '{domain}' - must NOT include path. "
                f"Use domain only (e.g., 'myapp.us.auth0.com')"
            )
            return False

        # Check for common Auth0 patterns (not exhaustive)
        # ReDoS-safe: All quantifiers are bounded to prevent catastrophic backtracking
        auth0_patterns = [
            r"^[a-zA-Z0-9-]{1,64}\.[a-z]{2}\.auth0\.com$",  # Regional: tenant.us.auth0.com (bounded)
            r"^[a-zA-Z0-9-]{1,64}\.auth0\.com$",  # Legacy: tenant.auth0.com (bounded)
        ]

        for pattern in auth0_patterns:
            if re.match(pattern, domain):
                logger.debug(f"Domain '{domain}' matches Auth0 pattern: {pattern}")
                return True

        # Allow custom domains (can't validate format)
        logger.debug(
            f"Domain '{domain}' does not match standard Auth0 patterns. "
            f"Assuming custom domain."
        )
        return True

    @auto_trace(logger)
    def _validate_auth0_claims(self, claims: Dict[str, Any]) -> None:
        """Validate required Auth0 claims are present.

        Auth0 tokens must contain:
        - sub: Subject (user ID in format provider|id)
        - iss: Issuer (Auth0 domain URL)
        - exp: Expiration timestamp
        - iat: Issued at timestamp
        - aud: Audience (client ID or API identifier)

        Optional Auth0 claims:
        - azp: Authorized party (client ID that requested token)
        - scope: OAuth scopes (space-separated)
        - org_id: Organization ID (Auth0 Organizations)
        - email_verified: Email verification status
        - Custom claims: Must use namespaced format (https://...)

        Args:
            claims: Decoded JWT payload claims

        Raises:
            TokenInvalidError: If required claims are missing
        """
        required_claims = ["sub", "iss", "exp", "iat", "aud"]
        self._validate_required_claims(claims, required_claims)

        # Detect token type based on claims
        token_type = "id" if "email" in claims or "name" in claims else "access"

        logger.debug(
            f"Auth0 claims validation passed. "
            f"Token type: {token_type}, "
            f"has_org_id: {'org_id' in claims}, "
            f"has_email_verified: {'email_verified' in claims}"
        )

    @auto_trace(logger)
    def _validate_issuer(self, iss: str, claims: Dict[str, Any]) -> None:
        """Validate token issuer matches expected Auth0 issuer.

        The issuer (iss claim) must exactly match the constructed issuer
        URL based on domain. Auth0 issuer format includes trailing slash.

        Args:
            iss: Issuer claim value from token
            claims: Decoded JWT payload claims (for context)

        Raises:
            TokenInvalidError: If issuer doesn't match expected value
        """
        if iss != self.issuer:
            error = TokenInvalidError(
                f"Issuer mismatch. Expected '{self.issuer}', got '{iss}'. "
                f"Verify domain configuration. Note: Auth0 issuer requires trailing slash."
            )
            logger.log_error(error=error)
            raise error

        logger.debug(f"Issuer validation passed: {iss}")

    @auto_trace(logger)
    def _validate_audience(self, claims: Dict[str, Any]) -> None:
        """Validate token audience matches expected value.

        The audience (aud claim) can be:
        - String: Single audience value
        - Array: Multiple audience values (for access tokens)

        Token is valid if configured audience matches any value in aud claim.

        For Auth0:
        - ID tokens: aud = client_id
        - Access tokens: aud = API identifier

        Args:
            claims: Decoded JWT payload claims

        Raises:
            TokenInvalidError: If audience doesn't match expected value
        """
        token_audience = claims.get("aud")

        # Handle both string and array audience formats
        if isinstance(token_audience, str):
            audiences = [token_audience]
        elif isinstance(token_audience, list):
            audiences = token_audience
        else:
            error = TokenInvalidError(
                f"Invalid audience claim type: {type(token_audience)}. "
                f"Expected string or array."
            )
            logger.log_error(error=error)
            raise error

        if self.audience not in audiences:
            error = TokenInvalidError(
                f"Audience mismatch. Expected '{self.audience}', "
                f"got {audiences}. Verify audience configuration."
            )
            logger.log_error(error=error)
            raise error

        logger.debug(f"Audience validation passed: {self.audience} in {audiences}")

    @auto_trace(logger)
    def _check_expiration_claim(self, claims: Dict[str, Any]) -> bool:
        """Validate token expiration with clock skew tolerance.

        Checks if current time is before exp claim, accounting for clock skew.

        NOTE: This is a simplified implementation for demonstration. Production
        implementation should use PyJWT's built-in expiration validation during
        signature verification.

        Args:
            claims: JWT payload claims dictionary

        Returns:
            True if token is not expired, False if expired
        """
        import time

        exp = claims.get("exp")
        if exp is None:
            logger.warning("Token missing exp claim")
            return False

        current_time = time.time()
        # Account for clock skew (current time can be slightly ahead)
        is_valid = current_time <= (exp + self.clock_skew_seconds)

        if not is_valid:
            logger.debug(
                f"Token expired: current_time={current_time}, "
                f"exp={exp}, clock_skew={self.clock_skew_seconds}"
            )

        return is_valid

    @auto_trace(logger)
    def _resolve_secret(self, secret: Optional[str]) -> Optional[str]:
        """Resolve client secret from parameter or environment variable.

        Supports "env:VAR_NAME" format for secure secret management.

        Args:
            secret: Secret value or "env:VAR_NAME" reference

        Returns:
            Resolved secret value or None

        Example:
            # Direct value
            secret = self._resolve_secret("my_secret")  # Returns "my_secret"

            # Environment variable reference
            secret = self._resolve_secret("env:AUTH0_SECRET")  # Returns os.getenv("AUTH0_SECRET")
        """
        if not secret:
            return None

        if secret.startswith("env:"):
            env_var = secret[4:]  # Remove "env:" prefix
            resolved = os.getenv(env_var)
            if resolved:
                logger.debug(f"Resolved client_secret from environment variable: {env_var}")
            else:
                logger.warning(f"Environment variable not found: {env_var}")
            return resolved

        return secret


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_auth0_decoder(
    domain: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    audience: Optional[str] = None,
    scope: Optional[str] = None,
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
) -> Auth0Decoder:
    """Factory function for Auth0Decoder instantiation.

    Creates an Auth0Decoder instance with configuration from parameters or
    environment variables.

    Environment variables (used if parameters not provided):
    - AUTH0_DOMAIN: Auth0 domain (without https://)
    - AUTH0_CLIENT_ID: OAuth 2.0 client ID
    - AUTH0_CLIENT_SECRET: OAuth 2.0 client secret
    - AUTH0_AUDIENCE: Expected audience claim
    - AUTH0_SCOPE: OAuth scopes (space-separated)

    Args:
        domain: Auth0 domain (or None to read from AUTH0_DOMAIN)
        client_id: OAuth client ID (or None to read from AUTH0_CLIENT_ID)
        client_secret: OAuth client secret (or None to read from AUTH0_CLIENT_SECRET)
        audience: Expected audience (or None to read from AUTH0_AUDIENCE)
        scope: OAuth scopes (or None to read from AUTH0_SCOPE)
        clock_skew_seconds: Clock skew tolerance in seconds (default: 30)

    Returns:
        Auth0Decoder instance configured from parameters or environment

    Raises:
        AuthError: If required configuration (domain, client_id) is missing
                  from both parameters and environment

    Example:
        # Create from environment variables
        decoder = create_auth0_decoder()

        # Create with explicit parameters
        decoder = create_auth0_decoder(
            domain="myapp.us.auth0.com",
            client_id="abc123def456",
            audience="https://api.myapp.com",
        )

        # Mixed: some from params, some from environment
        decoder = create_auth0_decoder(
            domain="myapp.us.auth0.com",  # Explicit
            # client_id read from AUTH0_CLIENT_ID environment variable
        )
    """
    # Read from environment if not provided
    domain = domain or os.getenv("AUTH0_DOMAIN")
    client_id = client_id or os.getenv("AUTH0_CLIENT_ID")
    client_secret = client_secret or os.getenv("AUTH0_CLIENT_SECRET")
    audience = audience or os.getenv("AUTH0_AUDIENCE")
    scope = scope or os.getenv("AUTH0_SCOPE")

    # Validate required configuration
    if not domain:
        error = AuthError(
            "Auth0 domain is required. Provide via parameter or "
            "AUTH0_DOMAIN environment variable. "
            "Format: 'tenant.region.auth0.com' (no https:// prefix)"
        )
        logger.log_error(error=error)
        raise error

    if not client_id:
        error = AuthError(
            "Auth0 client_id is required. Provide via parameter or "
            "AUTH0_CLIENT_ID environment variable."
        )
        logger.log_error(error=error)
        raise error

    logger.info(
        f"Creating Auth0Decoder from factory: domain={domain}, "
        f"audience={audience or 'not validated'}, "
        f"has_client_secret={bool(client_secret)}"
    )

    return Auth0Decoder(
        domain=domain,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        scope=scope,
        clock_skew_seconds=clock_skew_seconds,
    )
