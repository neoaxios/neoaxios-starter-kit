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

"""Okta-specific OIDC decoder for Okta tokens.

Validates tokens issued by Okta authorization servers with Okta-specific
features including custom claims, groups, and organization attributes.

This decoder extends OIDCDecoder to add Okta-specific functionality:
- Auto-construction of issuer and JWKS URIs from tenant_id
- Okta-specific claims handling (groups, org, custom attributes)
- Support for Okta token types (access, ID, refresh)
- Okta tenant validation
- Full JWKS signature verification (inherited from OIDCDecoder)

Okta Token Structure:
    Okta issues tokens from: https://{tenant_id}/oauth2/{authz_server_id}
    Common authorization servers:
    - /oauth2/default (org authorization server)
    - /oauth2/{custom_id} (custom authorization servers)

Okta-Specific Claims:
    - groups: User's group memberships (array)
    - org: Okta organization ID
    - scp: OAuth scopes (access tokens)
    - ver: Token version (1 = org auth server, 2 = custom auth server)
    - uid: Okta universal ID
    - Custom claims: Can be configured in Okta authorization server

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import OktaDecoder

    # Basic configuration (org authorization server)
    decoder = OktaDecoder(
        tenant_id="dev-12345.okta.com",
        client_id="0oa2t1n3k4p5q6r7s8t9",
    )

    # Custom authorization server
    decoder = OktaDecoder(
        tenant_id="dev-12345.okta.com",
        client_id="0oa2t1n3k4p5q6r7s8t9",
        authorization_server_id="custom_auth_server",
        audience="api://my-service",
    )

    # Decode token with Okta-specific claims
    identity = await decoder.decode(token)
    logger.info(
        f"Decoded Okta token",
        user_id=identity.user_id,
        groups=identity.attributes.get("groups"),
        org=identity.attributes.get("org"),
    )

Environment Variables:
    Create decoder from environment variables:
    - OKTA_TENANT_ID: Okta tenant domain (e.g., "dev-12345.okta.com")
    - OKTA_CLIENT_ID: OAuth 2.0 client ID
    - OKTA_CLIENT_SECRET: OAuth 2.0 client secret (optional)
    - OKTA_AUTHORIZATION_SERVER_ID: Custom auth server ID (default: "default")
    - OKTA_AUDIENCE: Expected audience claim (optional)

    decoder = create_okta_decoder()  # Reads from environment
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


class OktaDecoder(OIDCDecoder):
    """Decode and validate Okta-issued OIDC tokens.

    Extends OIDCDecoder with Okta-specific features:
    - Automatic issuer/JWKS URI construction from tenant_id
    - Okta custom claims extraction (groups, org, ver, uid)
    - Support for both org and custom authorization servers
    - Okta tenant validation
    - Token type detection (access vs. ID tokens)
    - Full JWKS signature verification (inherited from OIDCDecoder)

    This decoder demonstrates how to extend OIDCDecoder for provider-specific
    optimizations. The parent OIDCDecoder handles all signature verification,
    while OktaDecoder focuses on Okta-specific URL construction and claims.

    Attributes:
        tenant_id: Okta tenant domain (e.g., "dev-12345.okta.com")
        client_id: OAuth 2.0 client ID from Okta application
        client_secret: OAuth 2.0 client secret (optional, for token introspection)
        authorization_server_id: Okta auth server ID (default: "default" for org server)
        audience: Expected audience claim (optional)
        issuer: Auto-constructed from tenant_id and authorization_server_id
        jwks_uri: Auto-constructed JWKS endpoint for key retrieval
        clock_skew_seconds: Clock skew tolerance for time-based claims
    """

    @auto_trace(logger)
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: Optional[str] = None,
        authorization_server_id: str = "default",
        audience: Optional[str] = None,
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    ):
        """Initialize Okta decoder with tenant configuration.

        Args:
            tenant_id: Okta tenant domain, e.g., "dev-12345.okta.com" or
                      "mycompany.okta.com". Must be a valid Okta domain.
            client_id: OAuth 2.0 client ID from your Okta application.
                      Format: 20-character alphanumeric string.
            client_secret: OAuth 2.0 client secret (optional). Required for
                          token introspection but not for JWT signature validation.
            authorization_server_id: Okta authorization server ID.
                                    - "default": Org authorization server (default)
                                    - Custom ID: Custom authorization server
                                    Example: "custom_auth_server"
            audience: Expected audience claim (aud) for validation. If provided,
                     token aud must match. Common values:
                     - "api://default" (org auth server default)
                     - Your API identifier
            clock_skew_seconds: Clock skew tolerance in seconds for exp/nbf
                               validation. Default: 30 seconds.

        Raises:
            AuthError: If tenant_id format is invalid or required configuration
                      is missing

        Example:
            # Org authorization server (most common)
            decoder = OktaDecoder(
                tenant_id="dev-12345.okta.com",
                client_id="0oa2t1n3k4p5q6r7s8t9",
            )

            # Custom authorization server with audience validation
            decoder = OktaDecoder(
                tenant_id="mycompany.okta.com",
                client_id="0oa2t1n3k4p5q6r7s8t9",
                authorization_server_id="api_server",
                audience="api://myapp",
            )
        """
        # Validate tenant_id format
        if not self._validate_tenant_id(tenant_id):
            error = AuthError(
                f"Invalid Okta tenant_id format: '{tenant_id}'. "
                f"Expected format: 'dev-xxxxx.okta.com' or 'company.okta.com'"
            )
            logger.log_error(error=error)
            raise error

        # Validate client_id is present
        if not client_id:
            error = AuthError("Okta client_id is required")
            logger.log_error(error=error)
            raise error

        # Store Okta-specific configuration
        self.tenant_id = tenant_id
        self.authorization_server_id = authorization_server_id

        # Auto-construct issuer URL
        # Format: https://{tenant_id}/oauth2/{authz_server_id}
        issuer = f"https://{tenant_id}/oauth2/{authorization_server_id}"

        # Auto-construct JWKS URI for public key retrieval
        # Format: https://{tenant_id}/oauth2/{authz_server_id}/v1/keys
        jwks_uri = f"https://{tenant_id}/oauth2/{authorization_server_id}/v1/keys"

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
            f"Initialized OktaDecoder for tenant={tenant_id}, "
            f"authz_server={authorization_server_id}, "
            f"issuer={self.issuer}, jwks_uri={self.jwks_uri}, "
            f"audience={self.audience}"
        )

    @auto_trace(logger)
    def _extract_oidc_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Override parent to extract Okta-specific identity claims.

        Maps Okta-specific claims to IdentityContext:
        - sub -> user_id (Okta user ID or email)
        - iss -> issuer (validated Okta authorization server)
        - groups -> stored in attributes["groups"] (if present)
        - scp -> permissions (OAuth scopes for access tokens)
        - roles -> roles (custom claim if configured)
        - org -> stored in attributes["org"] (Okta organization ID)
        - ver -> stored in attributes["ver"] (token version)
        - uid -> stored in attributes["uid"] (Okta universal ID)

        Okta Token Types:
        - ID tokens: Contain user profile claims (email, name, etc.)
        - Access tokens: Contain scopes (scp) and minimal user info

        Args:
            claims: Decoded and validated JWT payload claims

        Returns:
            IdentityContext with user identity and Okta-specific attributes

        Raises:
            TokenInvalidError: If required claims (sub) are missing
        """
        # Extract required claims
        user_id = claims.get("sub")
        if not user_id:
            error = TokenInvalidError(
                "Okta token missing required 'sub' (subject) claim"
            )
            logger.log_error(error=error)
            raise error

        # Extract tenant_id (org claim or derive from issuer)
        tenant_id = claims.get("org", self.tenant_id)

        # Extract roles (custom claim if configured in Okta)
        roles_claim = claims.get("roles", [])
        if isinstance(roles_claim, str):
            roles = frozenset(r.strip() for r in roles_claim.split(",") if r.strip())
        elif isinstance(roles_claim, list):
            roles = frozenset(roles_claim)
        else:
            roles = frozenset()

        # Extract permissions from scopes (access tokens)
        # Okta uses "scp" claim for scopes in access tokens
        scopes_claim = claims.get("scp", [])
        if isinstance(scopes_claim, str):
            # Some Okta configs use space-separated scopes
            permissions = frozenset(
                s.strip() for s in scopes_claim.split() if s.strip()
            )
        elif isinstance(scopes_claim, list):
            permissions = frozenset(scopes_claim)
        else:
            permissions = frozenset()

        # Extract Okta-specific attributes
        # Include groups, org, ver, uid, and any custom claims
        standard_claims = {
            "sub",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "roles",
            "scp",
            "org",
        }

        attributes = {k: v for k, v in claims.items() if k not in standard_claims}

        # Explicitly add important Okta claims to attributes
        if "groups" in claims:
            attributes["groups"] = claims["groups"]
        if "org" in claims:
            attributes["org"] = claims["org"]
        if "ver" in claims:
            attributes["ver"] = claims["ver"]
        if "uid" in claims:
            attributes["uid"] = claims["uid"]

        # Add standard OIDC profile claims if present
        if "email" in claims:
            attributes["email"] = claims["email"]
        if "name" in claims:
            attributes["name"] = claims["name"]
        if "picture" in claims:
            attributes["picture"] = claims["picture"]
        if "email_verified" in claims:
            attributes["email_verified"] = claims["email_verified"]

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            attributes=attributes,
            provider="okta",
            issuer=claims.get("iss", self.issuer),
            provider_user_id=user_id,  # Okta sub is the provider user ID
        )

        logger.debug(
            f"Extracted Okta identity: user_id={user_id}, "
            f"tenant_id={tenant_id}, roles={len(roles)}, "
            f"permissions={len(permissions)}, groups={len(attributes.get('groups', []))}, "
            f"org={attributes.get('org')}, ver={attributes.get('ver')}"
        )

        return identity

    @auto_trace(logger)
    def _validate_tenant_id(self, tenant_id: str) -> bool:
        """Validate Okta tenant_id format.

        Okta tenant IDs follow patterns:
        - Dev tenant: "dev-{6_digits}.okta.com" or "dev-{6_digits}.oktapreview.com"
        - Production: "{org_name}.okta.com" or "{org_name}.okta-emea.com"
        - Custom domain: "{custom}.com" (requires additional DNS setup)

        Args:
            tenant_id: Okta tenant domain to validate

        Returns:
            True if format appears valid, False otherwise

        Notes:
            - This is a basic format check, not a connectivity test
            - Custom domains may not match standard patterns
            - Production validation should verify DNS/TLS certificates
        """
        # Basic format check: must contain a dot and not be empty
        if not tenant_id or "." not in tenant_id:
            logger.warning(
                f"Invalid tenant_id format: '{tenant_id}' - must be a domain"
            )
            return False

        # Check for common Okta patterns (not exhaustive)
        # ReDoS-safe: All quantifiers are bounded to prevent catastrophic backtracking
        okta_patterns = [
            r"^dev-\d{6}\.okta\.com$",  # Dev tenant (already bounded)
            r"^dev-\d{6}\.oktapreview\.com$",  # Dev preview (already bounded)
            r"^[a-zA-Z0-9-]{1,64}\.okta\.com$",  # Prod tenant (bounded)
            r"^[a-zA-Z0-9-]{1,64}\.okta-emea\.com$",  # EMEA tenant (bounded)
            r"^[a-zA-Z0-9-]{1,64}\.okta-gov\.com$",  # Gov cloud (bounded)
        ]

        for pattern in okta_patterns:
            if re.match(pattern, tenant_id):
                logger.debug(f"Tenant ID '{tenant_id}' matches Okta pattern: {pattern}")
                return True

        # Allow custom domains (can't validate format)
        logger.debug(
            f"Tenant ID '{tenant_id}' does not match standard Okta patterns. "
            f"Assuming custom domain."
        )
        return True



# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_okta_decoder(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    authorization_server_id: Optional[str] = None,
    audience: Optional[str] = None,
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
) -> OktaDecoder:
    """Factory function for OktaDecoder instantiation.

    Creates an OktaDecoder instance with configuration from parameters or
    environment variables.

    Environment variables (used if parameters not provided):
    - OKTA_TENANT_ID: Okta tenant domain
    - OKTA_CLIENT_ID: OAuth 2.0 client ID
    - OKTA_CLIENT_SECRET: OAuth 2.0 client secret
    - OKTA_AUTHORIZATION_SERVER_ID: Auth server ID (default: "default")
    - OKTA_AUDIENCE: Expected audience claim

    Args:
        tenant_id: Okta tenant domain (or None to read from OKTA_TENANT_ID)
        client_id: OAuth client ID (or None to read from OKTA_CLIENT_ID)
        client_secret: OAuth client secret (or None to read from OKTA_CLIENT_SECRET)
        authorization_server_id: Auth server ID (or None to read from
                                 OKTA_AUTHORIZATION_SERVER_ID, default: "default")
        audience: Expected audience (or None to read from OKTA_AUDIENCE)
        clock_skew_seconds: Clock skew tolerance in seconds (default: 30)

    Returns:
        OktaDecoder instance configured from parameters or environment

    Raises:
        AuthError: If required configuration (tenant_id, client_id) is missing
                  from both parameters and environment

    Example:
        # Create from environment variables
        decoder = create_okta_decoder()

        # Create with explicit parameters
        decoder = create_okta_decoder(
            tenant_id="dev-12345.okta.com",
            client_id="0oa2t1n3k4p5q6r7s8t9",
            authorization_server_id="custom_server",
            audience="api://myapp",
        )

        # Mixed: some from params, some from environment
        decoder = create_okta_decoder(
            tenant_id="dev-12345.okta.com",  # Explicit
            # client_id read from OKTA_CLIENT_ID environment variable
        )
    """
    # Read from environment if not provided
    tenant_id = tenant_id or os.getenv("OKTA_TENANT_ID")
    client_id = client_id or os.getenv("OKTA_CLIENT_ID")
    client_secret = client_secret or os.getenv("OKTA_CLIENT_SECRET")
    authorization_server_id = (
        authorization_server_id
        or os.getenv("OKTA_AUTHORIZATION_SERVER_ID")
        or "default"
    )
    audience = audience or os.getenv("OKTA_AUDIENCE")

    # Validate required configuration
    if not tenant_id:
        error = AuthError(
            "Okta tenant_id is required. Provide via parameter or "
            "OKTA_TENANT_ID environment variable."
        )
        logger.log_error(error=error)
        raise error

    if not client_id:
        error = AuthError(
            "Okta client_id is required. Provide via parameter or "
            "OKTA_CLIENT_ID environment variable."
        )
        logger.log_error(error=error)
        raise error

    logger.info(
        f"Creating OktaDecoder from factory: tenant={tenant_id}, "
        f"authz_server={authorization_server_id}, "
        f"audience={audience or 'not validated'}"
    )

    return OktaDecoder(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        authorization_server_id=authorization_server_id,
        audience=audience,
        clock_skew_seconds=clock_skew_seconds,
    )
