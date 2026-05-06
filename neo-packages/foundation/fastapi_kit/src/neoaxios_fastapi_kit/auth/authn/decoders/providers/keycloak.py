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

"""Keycloak-specific OIDC decoder for Keycloak tokens.

Validates tokens issued by Keycloak with Keycloak-specific features including
realm-based access control, nested role mappings, and resource access patterns.

This decoder extends OIDCDecoder to add Keycloak-specific functionality:
- Realm path validation (issuer must contain /realms/)
- Nested claims handling (realm_access, resource_access)
- Support for both realm roles and client-specific roles
- Keycloak token type support (access, ID, refresh, bearer)
- Realm name validation and issuer verification
- Full JWKS signature verification (inherited from OIDCDecoder)

Keycloak Token Structure:
    Keycloak issues tokens from: https://{host}/realms/{realm_name}
    Examples:
    - https://keycloak.example.com/realms/myrealm
    - https://auth.company.com/realms/production

Keycloak-Specific Claims:
    - realm_access.roles: Array of realm-level role assignments
    - resource_access.{client_id}.roles: Array of client-specific roles
    - azp: Authorized party (client ID)
    - scope: OAuth scopes (space-separated string)
    - email_verified: Email verification status
    - preferred_username: Username for display
    - given_name, family_name: User profile attributes

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.providers import KeycloakDecoder

    # Basic configuration with realm name
    decoder = KeycloakDecoder(
        realm_name="myrealm",
        issuer="https://keycloak.example.com/realms/myrealm",
        client_id="my-client-id",
    )

    # With client secret for confidential clients
    decoder = KeycloakDecoder(
        realm_name="production",
        issuer="https://auth.company.com/realms/production",
        client_id="backend-service",
        client_secret="env:KEYCLOAK_CLIENT_SECRET",  # Supports env: prefix
        audience="account",
    )

    # Decode token with Keycloak-specific nested roles
    identity = await decoder.decode(token)
    logger.info(
        f"Decoded Keycloak token",
        user_id=identity.user_id,
        realm_roles=identity.roles,  # From realm_access.roles
        client_roles=identity.attributes.get("client_roles"),  # From resource_access
        realm=identity.attributes.get("realm_name"),
    )

Environment Variables:
    Create decoder from environment variables:
    - KEYCLOAK_REALM_NAME: Keycloak realm name (required)
    - KEYCLOAK_ISSUER: Full issuer URL with /realms/ path (required)
    - KEYCLOAK_CLIENT_ID: OAuth 2.0 client ID (required)
    - KEYCLOAK_CLIENT_SECRET: OAuth 2.0 client secret (optional, supports env:)
    - KEYCLOAK_AUDIENCE: Expected audience claim (optional)
    - KEYCLOAK_SCOPE: OAuth scopes (optional)

    decoder = create_keycloak_decoder()  # Reads from environment
"""

import os
import re
from typing import Any, Dict, List, Optional

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError

logger = get_telemetry(__name__)


class KeycloakDecoder(OIDCDecoder):
    """Decode and validate Keycloak-issued OIDC tokens.

    Extends OIDCDecoder with Keycloak-specific features:
    - Realm path validation (issuer must contain /realms/)
    - Nested role extraction from realm_access and resource_access
    - Support for both realm and client-specific roles
    - Keycloak token type detection (access vs. ID tokens)
    - Realm name validation and consistency checking
    - Full JWKS signature verification (inherited from OIDCDecoder)

    This decoder demonstrates how to extend OIDCDecoder for provider-specific
    customizations. The parent OIDCDecoder handles all signature verification,
    while KeycloakDecoder focuses on Keycloak's unique nested role structure.

    Attributes:
        realm_name: Keycloak realm name (e.g., "myrealm", "production")
        issuer: Full issuer URL (must contain /realms/{realm_name})
        client_id: OAuth 2.0 client ID from Keycloak application
        client_secret: OAuth 2.0 client secret (optional, for confidential clients)
        audience: Expected audience claim (optional)
        scope: OAuth scopes (optional)
        jwks_uri: Auto-constructed JWKS endpoint for key retrieval
        clock_skew_seconds: Clock skew tolerance for time-based claims
    """

    @auto_trace(logger)
    def __init__(
        self,
        realm_name: str,
        issuer: str,
        client_id: str,
        client_secret: Optional[str] = None,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    ):
        """Initialize Keycloak decoder with realm configuration.

        Args:
            realm_name: Keycloak realm name, e.g., "myrealm" or "production".
                       Must match the realm in the issuer URL path.
            issuer: Full issuer URL including /realms/ path.
                   Format: "https://{host}/realms/{realm_name}"
                   Example: "https://keycloak.example.com/realms/myrealm"
            client_id: OAuth 2.0 client ID from your Keycloak application.
                      Used to extract client-specific roles from resource_access.
            client_secret: OAuth 2.0 client secret (optional). Required for
                          confidential clients and token introspection. Supports
                          "env:" prefix for environment variable references.
                          Example: "env:KEYCLOAK_CLIENT_SECRET"
            audience: Expected audience claim (aud) for validation. If provided,
                     token aud must match. Common values:
                     - "account" (Keycloak default)
                     - Client ID
                     - Custom API identifier
            scope: OAuth scopes (optional). Space-separated list of scopes.
                  Example: "openid profile email"
            clock_skew_seconds: Clock skew tolerance in seconds for exp/nbf
                               validation. Default: 30 seconds.

        Raises:
            AuthError: If realm_name format is invalid, issuer doesn't contain
                      /realms/, or required configuration is missing

        Example:
            # Basic realm configuration
            decoder = KeycloakDecoder(
                realm_name="myrealm",
                issuer="https://keycloak.example.com/realms/myrealm",
                client_id="my-client-id",
            )

            # Confidential client with audience validation
            decoder = KeycloakDecoder(
                realm_name="production",
                issuer="https://auth.company.com/realms/production",
                client_id="backend-service",
                client_secret="env:KEYCLOAK_CLIENT_SECRET",
                audience="account",
            )
        """
        # Validate required parameters
        if not realm_name:
            error = AuthError("Keycloak realm_name is required")
            logger.log_error(error=error)
            raise error

        if not issuer:
            error = AuthError("Keycloak issuer is required")
            logger.log_error(error=error)
            raise error

        if not client_id:
            error = AuthError("Keycloak client_id is required")
            logger.log_error(error=error)
            raise error

        # Validate realm_name format
        if not self._validate_realm_name(realm_name):
            error = AuthError(
                f"Invalid Keycloak realm_name format: '{realm_name}'. "
                f"Expected alphanumeric with hyphens/underscores."
            )
            logger.log_error(error=error)
            raise error

        # Validate issuer format (must contain /realms/)
        if not self._validate_issuer_format(issuer):
            error = AuthError(
                f"Invalid Keycloak issuer format: '{issuer}'. "
                f"Expected format: 'https://{{host}}/realms/{{realm_name}}'"
            )
            logger.log_error(error=error)
            raise error

        # Validate realm_name matches issuer path
        if not self._validate_realm_matches_issuer(realm_name, issuer):
            logger.warning(
                f"Realm name '{realm_name}' does not match issuer path '{issuer}'. "
                f"This may indicate a configuration mismatch."
            )

        # Store Keycloak-specific configuration
        self.realm_name = realm_name
        self.scope = scope

        # Auto-construct JWKS URI for public key retrieval
        # Format: https://{host}/realms/{realm_name}/protocol/openid-connect/certs
        jwks_uri = f"{issuer}/protocol/openid-connect/certs"

        # Call parent OIDCDecoder constructor with issuer and JWKS URI
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
            f"Initialized KeycloakDecoder for realm={realm_name}, "
            f"issuer={issuer}, jwks_uri={self.jwks_uri}, "
            f"client_id={client_id}, audience={self.audience}"
        )

    @auto_trace(logger)
    def _validate_realm_name(self, realm_name: str) -> bool:
        """Validate Keycloak realm_name format.

        Keycloak realm names typically follow patterns:
        - Alphanumeric characters
        - Hyphens and underscores allowed
        - No spaces or special characters
        - Common examples: "master", "myrealm", "production-env"

        Args:
            realm_name: Keycloak realm name to validate

        Returns:
            True if format appears valid, False otherwise

        Notes:
            - This is a basic format check, not a connectivity test
            - Keycloak allows flexible realm naming
            - Production validation should verify realm exists
        """
        # Basic format check: alphanumeric with hyphens/underscores
        if not realm_name:
            logger.warning("Realm name is empty")
            return False

        # Allow alphanumeric, hyphens, and underscores
        # ReDoS-safe: Bounded quantifier to prevent catastrophic backtracking
        pattern = r"^[a-zA-Z0-9_-]{1,64}$"
        if not re.match(pattern, realm_name):
            logger.warning(
                f"Invalid realm_name format: '{realm_name}' - must be alphanumeric "
                f"with hyphens/underscores only"
            )
            return False

        logger.debug(f"Realm name '{realm_name}' format is valid")
        return True

    @auto_trace(logger)
    def _validate_issuer_format(self, issuer: str) -> bool:
        """Validate issuer contains required /realms/ path.

        Keycloak issuers must follow the pattern:
        https://{host}/realms/{realm_name}

        Args:
            issuer: Issuer URL to validate

        Returns:
            True if issuer contains /realms/ path, False otherwise

        Notes:
            - Keycloak requires /realms/ in issuer path
            - This distinguishes Keycloak from other OIDC providers
            - Path is case-sensitive
        """
        if not issuer:
            logger.warning("Issuer is empty")
            return False

        if "/realms/" not in issuer:
            logger.warning(
                f"Issuer '{issuer}' does not contain '/realms/' path. "
                f"Expected format: 'https://{{host}}/realms/{{realm_name}}'"
            )
            return False

        # Basic URL format check
        if not issuer.startswith("http://") and not issuer.startswith("https://"):
            logger.warning(f"Issuer '{issuer}' must be an HTTP/HTTPS URL")
            return False

        logger.debug(f"Issuer '{issuer}' format is valid")
        return True

    @auto_trace(logger)
    def _validate_realm_matches_issuer(self, realm_name: str, issuer: str) -> bool:
        """Validate realm_name matches issuer path.

        Checks if the realm_name parameter matches the realm in the issuer URL.
        Issues a warning if they don't match, as this may indicate misconfiguration.

        Args:
            realm_name: Configured realm name
            issuer: Configured issuer URL

        Returns:
            True if realm_name appears in issuer path, False otherwise
        """
        # Extract realm from issuer path
        # Expected format: https://{host}/realms/{realm_name}
        # ReDoS-safe: Bounded quantifier to prevent catastrophic backtracking
        match = re.search(r"/realms/([^/]{1,128})", issuer)
        if not match:
            logger.warning(
                f"Could not extract realm from issuer '{issuer}'. "
                f"Expected format: 'https://{{host}}/realms/{{realm_name}}'"
            )
            return False

        issuer_realm = match.group(1)
        if issuer_realm != realm_name:
            logger.warning(
                f"Realm name '{realm_name}' does not match issuer realm '{issuer_realm}'. "
                f"This may indicate a configuration mismatch."
            )
            return False

        logger.debug(f"Realm name '{realm_name}' matches issuer path")
        return True

    @auto_trace(logger)
    def _extract_realm_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract realm-level roles from realm_access claim.

        Keycloak stores realm-level roles in the nested structure:
        realm_access: {
            roles: ["role1", "role2"]
        }

        Args:
            claims: Decoded JWT payload claims

        Returns:
            List of realm role names (empty list if no roles)

        Example:
            claims = {
                "realm_access": {
                    "roles": ["user", "admin"]
                }
            }
            roles = self._extract_realm_roles(claims)
            # roles = ["user", "admin"]
        """
        realm_access = claims.get("realm_access", {})
        if not isinstance(realm_access, dict):
            logger.debug("realm_access claim is not a dictionary")
            return []

        roles = realm_access.get("roles", [])
        if not isinstance(roles, list):
            logger.debug("realm_access.roles is not a list")
            return []

        logger.debug(f"Extracted {len(roles)} realm roles")
        return roles

    @auto_trace(logger)
    def _extract_client_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract client-specific roles from resource_access claim.

        Keycloak stores client-specific roles in the nested structure:
        resource_access: {
            "{client_id}": {
                "roles": ["client_role1", "client_role2"]
            }
        }

        Args:
            claims: Decoded JWT payload claims

        Returns:
            List of client role names for this decoder's client_id
            (empty list if no client roles)

        Example:
            claims = {
                "resource_access": {
                    "my-client-id": {
                        "roles": ["view_data", "edit_data"]
                    }
                }
            }
            # With client_id="my-client-id"
            roles = self._extract_client_roles(claims)
            # roles = ["view_data", "edit_data"]
        """
        resource_access = claims.get("resource_access", {})
        if not isinstance(resource_access, dict):
            logger.debug("resource_access claim is not a dictionary")
            return []

        client_access = resource_access.get(self.client_id, {})
        if not isinstance(client_access, dict):
            logger.debug(
                f"resource_access.{self.client_id} is not a dictionary "
                f"or does not exist"
            )
            return []

        roles = client_access.get("roles", [])
        if not isinstance(roles, list):
            logger.debug(f"resource_access.{self.client_id}.roles is not a list")
            return []

        logger.debug(f"Extracted {len(roles)} client roles for client_id={self.client_id}")
        return roles

    @auto_trace(logger)
    def _extract_oidc_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Override parent to extract Keycloak-specific identity claims.

        Maps Keycloak-specific claims to IdentityContext:
        - sub -> user_id (Keycloak user UUID or username)
        - iss -> issuer (validated Keycloak realm URL)
        - realm_access.roles -> roles (realm-level roles)
        - resource_access.{client_id}.roles -> attributes["client_roles"]
        - scope -> permissions (OAuth scopes)
        - azp -> stored in attributes["azp"] (authorized party)
        - email, preferred_username, etc. -> stored in attributes

        Keycloak Token Types:
        - ID tokens: Contain full user profile claims
        - Access tokens: Contain scopes and role mappings
        - Refresh tokens: Used to obtain new access tokens

        Args:
            claims: Decoded and validated JWT payload claims

        Returns:
            IdentityContext with user identity and Keycloak-specific attributes

        Raises:
            TokenInvalidError: If required claims (sub) are missing

        Example:
            claims = {
                "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "email": "user@example.com",
                "realm_access": {"roles": ["user", "admin"]},
                "resource_access": {"my-client": {"roles": ["view", "edit"]}},
                "scope": "openid profile email",
                "preferred_username": "john.doe",
            }

            identity = self._extract_keycloak_identity(claims)
            # identity.user_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
            # identity.roles = frozenset({"user", "admin"})
            # identity.permissions = frozenset({"openid", "profile", "email"})
            # identity.attributes["client_roles"] = ["view", "edit"]
            # identity.attributes["email"] = "user@example.com"
        """
        # Extract required claims
        user_id = claims.get("sub")
        if not user_id:
            error = TokenInvalidError(
                "Keycloak token missing required 'sub' (subject) claim"
            )
            logger.log_error(error=error)
            raise error

        # Extract realm name from issuer or use configured realm
        tenant_id = self.realm_name

        # Extract realm-level roles
        realm_roles = self._extract_realm_roles(claims)
        roles = frozenset(realm_roles)

        # Extract client-specific roles (stored separately in attributes)
        client_roles = self._extract_client_roles(claims)

        # Extract permissions from scope claim
        # Keycloak uses space-separated scope string
        scope_claim = claims.get("scope", "")
        if isinstance(scope_claim, str):
            permissions = frozenset(
                s.strip() for s in scope_claim.split() if s.strip()
            )
        else:
            permissions = frozenset()

        # Extract Keycloak-specific attributes
        # Exclude standard claims and nested structures
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
            "realm_access",
            "resource_access",
        }

        attributes = {k: v for k, v in claims.items() if k not in standard_claims}

        # Explicitly add important Keycloak claims to attributes
        attributes["realm_name"] = self.realm_name
        attributes["client_roles"] = client_roles  # Client-specific roles

        if "azp" in claims:
            attributes["azp"] = claims["azp"]  # Authorized party
        if "email" in claims:
            attributes["email"] = claims["email"]
        if "email_verified" in claims:
            attributes["email_verified"] = claims["email_verified"]
        if "preferred_username" in claims:
            attributes["preferred_username"] = claims["preferred_username"]
        if "given_name" in claims:
            attributes["given_name"] = claims["given_name"]
        if "family_name" in claims:
            attributes["family_name"] = claims["family_name"]

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            attributes=attributes,
            provider="keycloak",
            issuer=claims.get("iss", self.issuer),
            provider_user_id=user_id,  # Keycloak sub is the provider user ID
        )

        logger.debug(
            f"Extracted Keycloak identity: user_id={user_id}, "
            f"tenant_id={tenant_id}, realm_roles={len(roles)}, "
            f"client_roles={len(client_roles)}, permissions={len(permissions)}"
        )

        return identity


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_keycloak_decoder(
    realm_name: Optional[str] = None,
    issuer: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    audience: Optional[str] = None,
    scope: Optional[str] = None,
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
) -> KeycloakDecoder:
    """Factory function for KeycloakDecoder instantiation.

    Creates a KeycloakDecoder instance with configuration from parameters or
    environment variables.

    Environment variables (used if parameters not provided):
    - KEYCLOAK_REALM_NAME: Keycloak realm name
    - KEYCLOAK_ISSUER: Full issuer URL with /realms/ path
    - KEYCLOAK_CLIENT_ID: OAuth 2.0 client ID
    - KEYCLOAK_CLIENT_SECRET: OAuth 2.0 client secret (supports env: prefix)
    - KEYCLOAK_AUDIENCE: Expected audience claim
    - KEYCLOAK_SCOPE: OAuth scopes

    Args:
        realm_name: Keycloak realm name (or None to read from KEYCLOAK_REALM_NAME)
        issuer: Full issuer URL (or None to read from KEYCLOAK_ISSUER)
        client_id: OAuth client ID (or None to read from KEYCLOAK_CLIENT_ID)
        client_secret: OAuth client secret (or None to read from KEYCLOAK_CLIENT_SECRET)
        audience: Expected audience (or None to read from KEYCLOAK_AUDIENCE)
        scope: OAuth scopes (or None to read from KEYCLOAK_SCOPE)
        clock_skew_seconds: Clock skew tolerance in seconds (default: 30)

    Returns:
        KeycloakDecoder instance configured from parameters or environment

    Raises:
        AuthError: If required configuration (realm_name, issuer, client_id) is
                  missing from both parameters and environment

    Example:
        # Create from environment variables
        decoder = create_keycloak_decoder()

        # Create with explicit parameters
        decoder = create_keycloak_decoder(
            realm_name="myrealm",
            issuer="https://keycloak.example.com/realms/myrealm",
            client_id="my-client-id",
            audience="account",
        )

        # Mixed: some from params, some from environment
        decoder = create_keycloak_decoder(
            realm_name="myrealm",  # Explicit
            issuer="https://keycloak.example.com/realms/myrealm",  # Explicit
            # client_id read from KEYCLOAK_CLIENT_ID environment variable
        )
    """
    # Read from environment if not provided
    realm_name = realm_name or os.getenv("KEYCLOAK_REALM_NAME")
    issuer = issuer or os.getenv("KEYCLOAK_ISSUER")
    client_id = client_id or os.getenv("KEYCLOAK_CLIENT_ID")
    client_secret = client_secret or os.getenv("KEYCLOAK_CLIENT_SECRET")
    audience = audience or os.getenv("KEYCLOAK_AUDIENCE")
    scope = scope or os.getenv("KEYCLOAK_SCOPE")

    # Validate required configuration
    if not realm_name:
        error = AuthError(
            "Keycloak realm_name is required. Provide via parameter or "
            "KEYCLOAK_REALM_NAME environment variable."
        )
        logger.log_error(error=error)
        raise error

    if not issuer:
        error = AuthError(
            "Keycloak issuer is required. Provide via parameter or "
            "KEYCLOAK_ISSUER environment variable."
        )
        logger.log_error(error=error)
        raise error

    if not client_id:
        error = AuthError(
            "Keycloak client_id is required. Provide via parameter or "
            "KEYCLOAK_CLIENT_ID environment variable."
        )
        logger.log_error(error=error)
        raise error

    logger.info(
        f"Creating KeycloakDecoder from factory: realm={realm_name}, "
        f"issuer={issuer}, client_id={client_id}, "
        f"audience={audience or 'not validated'}"
    )

    return KeycloakDecoder(
        realm_name=realm_name,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        scope=scope,
        clock_skew_seconds=clock_skew_seconds,
    )
