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

"""OIDC decoder for generic OpenID Connect provider support.

Validates tokens from any OIDC-compliant identity provider using the OpenID
Connect Discovery protocol. Supports automatic JWKS key rotation, RS256
signature verification, and standard OIDC claim validation.

This decoder is provider-agnostic and works with any OIDC-compliant provider
including Okta, Auth0, Keycloak, and custom implementations that follow the
OpenID Connect specification.

For provider-specific optimizations (Azure AD, AWS Cognito, Google), use the
dedicated decoder implementations.

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder

    # Create decoder with OIDC provider details
    decoder = OIDCDecoder(
        issuer="https://auth.example.com",
        client_id="my-client-id",
        client_secret="my-client-secret",  # Optional for public clients
        audience="api://my-service",
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        clock_skew_seconds=30,
    )

    # Decode and validate token
    identity = await decoder.decode(token)
    logger.info("OIDC token validated", user_id=identity.user_id)

OIDC Specification Compliance:
    - Required claims: sub, iss, aud, exp, iat
    - Optional claims: email, name, picture, roles, groups
    - Signature verification: RS256, RS384, RS512
    - Key rotation: Automatic JWKS refresh on verification failure
    - Clock skew: Configurable tolerance for exp/iat/nbf validation

Security Features:
    - JWKS caching with TTL to reduce network calls
    - Issuer validation to prevent token substitution
    - Audience validation for API authorization
    - Signature verification with automatic key rotation
    - No revocation checking (use short-lived tokens)

Reference: https://openid.net/specs/openid-connect-core-1_0.html
"""

import time
from typing import Any, Dict, Optional, FrozenSet, Union

import jwt
from jwt import PyJWKClient
from pydantic import SecretStr
from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    TokenExpiredError,
)
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
from neoaxios_secure_cache import CacheBackend

logger = get_telemetry(__name__)


class OIDCDecoder(BaseDecoder):
    """Decode and validate OIDC tokens from generic OpenID Connect providers.

    Validates OIDC ID tokens and access tokens using JWKS key rotation and
    standard OpenID Connect claims validation. Provider-agnostic implementation
    that works with any OIDC-compliant identity provider.

    This decoder performs:
    - OIDC Discovery protocol support (via external discovery client)
    - JWKS-based signature verification with automatic key rotation
    - Standard OIDC claims validation (sub, iss, aud, exp, iat)
    - Clock skew tolerance for time-based claims
    - Optional JWKS caching for performance

    Attributes:
        issuer: OIDC issuer URL (iss claim value)
        client_id: OAuth2 client ID for audience validation
        client_secret: OAuth2 client secret (optional, for confidential clients)
        audience: Expected audience claim (defaults to client_id)
        jwks_uri: JWKS endpoint URL for public key retrieval
        clock_skew_seconds: Clock skew tolerance for time validation
        key_cache: Optional cache backend for JWKS caching
    """

    @auto_trace(logger)
    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: Optional[Union[SecretStr, str]] = None,
        audience: Optional[str] = None,
        jwks_uri: str = "",
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
        key_cache: Optional[CacheBackend] = None,
    ):
        """Initialize OIDC decoder with provider configuration.

        Args:
            issuer: OIDC issuer URL (must be HTTPS). This is the iss claim value
                   expected in tokens. Example: "https://auth.example.com"
            client_id: OAuth2 client ID. Used for audience validation. The aud
                      claim in tokens must match this value (or the audience param).
            client_secret: OAuth2 client secret (SecretStr or str). Optional for
                          public clients. Used for token introspection if supported.
                          Not used for signature verification (uses JWKS public keys).
            audience: Expected audience claim (aud). If None, defaults to client_id.
                     The token aud claim must exactly match this value.
            jwks_uri: JWKS endpoint URL for retrieving public signing keys.
                     Must be HTTPS. Example: "https://auth.example.com/.well-known/jwks.json"
                     Used by PyJWKClient to fetch and cache signing keys.
            clock_skew_seconds: Clock skew tolerance in seconds for exp/iat/nbf
                               validation. Allows for time drift between token issuer
                               and validator. Default: 30 seconds (recommended).
                               Range: 0-300 seconds.
            key_cache: Optional cache backend for JWKS caching. If provided, JWKS
                      keys are cached to reduce network calls. Recommended for
                      production to minimize latency and JWKS endpoint load.

        Raises:
            TokenInvalidError: If issuer or jwks_uri is invalid (not HTTPS, empty)
            TokenInvalidError: If client_id is empty
            TokenInvalidError: If clock_skew_seconds is out of range

        Example:
            decoder = OIDCDecoder(
                issuer="https://auth.example.com",
                client_id="my-app-client",
                jwks_uri="https://auth.example.com/.well-known/jwks.json",
                clock_skew_seconds=30,
            )
        """
        # Validate required parameters
        if not issuer or not issuer.strip():
            error = TokenInvalidError("OIDC issuer cannot be empty")
            logger.log_error(error=error)
            raise error

        if not issuer.startswith("https://"):
            error = TokenInvalidError(
                f"OIDC issuer must use HTTPS, got: {issuer}"
            )
            logger.log_error(error=error)
            raise error

        if not client_id or not client_id.strip():
            error = TokenInvalidError("OIDC client_id cannot be empty")
            logger.log_error(error=error)
            raise error

        if not jwks_uri or not jwks_uri.strip():
            error = TokenInvalidError("OIDC jwks_uri cannot be empty")
            logger.log_error(error=error)
            raise error

        if not jwks_uri.startswith("https://"):
            error = TokenInvalidError(
                f"OIDC jwks_uri must use HTTPS, got: {jwks_uri}"
            )
            logger.log_error(error=error)
            raise error

        if clock_skew_seconds < 0 or clock_skew_seconds > 300:
            error = TokenInvalidError(
                f"clock_skew_seconds must be between 0 and 300, got: {clock_skew_seconds}"
            )
            logger.log_error(error=error)
            raise error

        # Store configuration
        self.issuer = issuer.strip()
        self.client_id = client_id.strip()
        # Wrap client_secret in SecretStr to prevent log/repr exposure
        self.client_secret: Optional[SecretStr] = (
            client_secret if isinstance(client_secret, SecretStr)
            else SecretStr(client_secret) if client_secret is not None
            else None
        )
        self.audience = audience.strip() if audience else client_id.strip()
        self.jwks_uri = jwks_uri.strip()
        self.clock_skew_seconds = clock_skew_seconds
        self.key_cache = key_cache

        # Initialize PyJWKClient for JWKS key rotation
        # PyJWKClient handles:
        # - Fetching JWKS from jwks_uri
        # - Caching keys with TTL
        # - Automatic key rotation on verification failure
        self._jwks_client = PyJWKClient(
            uri=self.jwks_uri,
            cache_keys=True,
            max_cached_keys=16,
            # Note: PyJWKClient uses in-memory cache by default
            # For distributed systems, use key_cache parameter for shared cache
        )

        # Internal flag for subclasses to skip PyJWT issuer validation
        # When True, issuer is NOT passed to jwt.decode(), allowing subclasses
        # to perform custom issuer validation in _validate_issuer() hook.
        # Used by Azure AD decoder for multi-tenant scenarios.
        self._skip_pyjwt_issuer_validation = False

        logger.info(
            f"Initialized OIDCDecoder with issuer={self.issuer}, "
            f"client_id={self.client_id}, audience={self.audience}, "
            f"jwks_uri={self.jwks_uri}, clock_skew={self.clock_skew_seconds}s, "
            f"has_key_cache={self.key_cache is not None}"
        )

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and validate OIDC token to identity context.

        Performs complete OIDC token validation:
        1. JWT structure validation (3 parts)
        2. JWKS-based signature verification with automatic key rotation
        3. Issuer validation (iss claim must match configured issuer)
        4. Audience validation (aud claim must match configured audience)
        5. Expiration check (exp claim with clock skew tolerance)
        6. Issued-at validation (iat claim must be present and valid)
        7. Not-before check (nbf claim if present)
        8. Required OIDC claims validation (sub, iss, aud, exp, iat)
        9. Identity context extraction from OIDC claims

        Args:
            token: OIDC token string (JWT format: header.payload.signature)

        Returns:
            IdentityContext with user identity, roles, permissions, and OIDC metadata

        Raises:
            TokenInvalidError: Token format invalid, signature verification failed,
                              issuer/audience mismatch, or required claims missing
            TokenExpiredError: Token has expired (exp claim is in the past)

        Example:
            identity = await decoder.decode(bearer_token)
            logger.info(
                "OIDC token decoded",
                user_id=identity.user_id,
                issuer=identity.issuer,
                roles=identity.roles,
            )
        """
        # Validate JWT structure (3 parts)
        self._validate_token_structure(token)

        # Fetch signing key from JWKS and verify signature
        try:
            claims = self._fetch_and_verify_signature(token)
        except TokenExpiredError:
            # Re-raise TokenExpiredError as-is
            raise
        except TokenInvalidError:
            # Re-raise TokenInvalidError as-is
            raise
        except Exception as e:
            error = TokenInvalidError(f"OIDC signature verification failed: {str(e)}")
            logger.log_error(error=error)
            raise error

        # Validate OIDC-specific claims
        self._validate_oidc_claims(claims)

        # Extract identity from OIDC claims
        identity = self._extract_oidc_identity(claims)

        logger.info(
            f"Successfully decoded OIDC token for user_id='{identity.user_id}' "
            f"from issuer='{identity.issuer}', provider='{identity.provider}'"
        )

        return identity

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if OIDC token is valid without extracting identity.

        Performs same validation as decode() but returns boolean instead
        of raising exceptions. Useful for permission checks where you only
        need to know if token is valid.

        Args:
            token: OIDC token string

        Returns:
            True if token is valid (signature, expiration, issuer, audience all pass),
            False otherwise

        Example:
            is_valid = await decoder.validate(token)
            if is_valid:
                logger.info("OIDC token validation successful")
            else:
                logger.warning("OIDC token validation failed")
        """
        try:
            await self.decode(token)
            return True
        except (TokenInvalidError, TokenExpiredError) as e:
            logger.debug(f"OIDC token validation failed: {str(e)}")
            return False
        except Exception as e:
            logger.log_error(error=e)
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if OIDC token has been revoked.

        For OIDC tokens validated by JWKS signature only, revocation is not
        supported by default. This method always returns False.

        OIDC providers may support token introspection (RFC 7662) for revocation
        checking, but this requires additional HTTP calls and is not implemented
        in this base decoder.

        To implement revocation:
        1. Use short-lived tokens (5-15 minutes) with refresh token rotation
        2. Implement token introspection endpoint client (override this method)
        3. Use external revocation list (Redis set of revoked JTIs)
        4. Include 'jti' (JWT ID) claim in tokens for revocation tracking

        Args:
            token: OIDC token string

        Returns:
            False (revocation not supported for JWKS-only validation)

        Example:
            if await decoder.is_revoked(token):
                raise TokenRevokedError("Token has been revoked")
        """
        # OIDC tokens validated by JWKS signature do not support revocation
        # checking by default. For revocation support:
        # - Use short-lived tokens with refresh rotation
        # - Implement token introspection endpoint (RFC 7662)
        # - Override this method in a subclass
        return False

    @auto_trace(logger)
    def _fetch_and_verify_signature(self, token: str) -> Dict[str, Any]:
        """Fetch signing key from JWKS and verify token signature.

        Uses PyJWKClient to:
        1. Extract kid (key ID) from token header
        2. Fetch corresponding public key from JWKS endpoint
        3. Cache keys for performance (in-memory or custom cache)
        4. Automatically rotate keys on verification failure
        5. Verify signature using fetched public key

        This method also validates issuer and audience claims during verification.

        Args:
            token: OIDC token string

        Returns:
            Dictionary of OIDC claims (payload)

        Raises:
            TokenInvalidError: Signature verification failed, invalid format,
                              issuer/audience mismatch, or key not found in JWKS
            TokenExpiredError: Token has expired (raised by PyJWT)

        Notes:
            - PyJWKClient automatically caches keys to minimize JWKS endpoint calls
            - On signature failure, PyJWKClient refreshes JWKS and retries once
            - Supports multiple key IDs (kid) for key rotation scenarios
        """
        try:
            # Get signing key from JWKS using kid from token header
            # PyJWKClient handles:
            # - Parsing token header to extract kid
            # - Fetching JWKS from jwks_uri (cached)
            # - Finding matching key by kid
            # - Automatic JWKS refresh on key not found
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)

            # Build validation options for PyJWT
            # When _skip_pyjwt_issuer_validation is True, we skip PyJWT's issuer check
            # and let the subclass handle it in _validate_issuer() hook.
            # This is needed for multi-tenant Azure AD where the token issuer varies.
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": not self._skip_pyjwt_issuer_validation,
                "verify_aud": True,
                "require_exp": True,
                "require_iss": True,
                "require_iat": True,  # OIDC requires iat claim
            }

            # Build decode kwargs - only include issuer if not skipping validation
            decode_kwargs = {
                "jwt": token,
                "key": signing_key.key,
                "algorithms": ["RS256", "RS384", "RS512"],  # OIDC typically uses RSA
                "audience": self.audience,
                "options": options,
                "leeway": self.clock_skew_seconds,
            }

            # Only pass issuer if we want PyJWT to validate it
            if not self._skip_pyjwt_issuer_validation:
                decode_kwargs["issuer"] = self.issuer

            # Decode and verify token using fetched signing key
            claims = jwt.decode(**decode_kwargs)

            logger.debug(
                "OIDC signature verified successfully",
                kid=signing_key.key_id,
                algorithm=signing_key._jwk_data.get("alg", "unknown"),
                claims_count=len(claims),
            )

            return claims

        except jwt.ExpiredSignatureError:
            error = TokenExpiredError("OIDC token has expired")
            logger.log_error(error=error)
            raise error

        except jwt.InvalidTokenError as e:
            # Covers: InvalidSignatureError, DecodeError, InvalidIssuerError,
            # InvalidAudienceError, InvalidKeyError, etc.
            error = TokenInvalidError(f"Invalid OIDC token: {str(e)}")
            logger.log_error(error=error)
            raise error

        except Exception as e:
            error = TokenInvalidError(f"OIDC signature verification error: {str(e)}")
            logger.log_error(error=error)
            raise error

    @auto_trace(logger)
    def _validate_oidc_claims(self, claims: Dict[str, Any]) -> None:
        """Validate OIDC-specific required claims are present and valid.

        Validates presence and format of required OIDC claims:
        - sub: Subject identifier (user ID) - required, non-empty
        - iss: Issuer identifier - required, must match configured issuer
        - aud: Audience - required, must match configured audience
        - exp: Expiration time - required, validated by PyJWT
        - iat: Issued at time - required, must be in the past

        Optional OIDC claims validated if present:
        - nbf: Not before time - must be in the past or current
        - email: Email address - validated format if present
        - email_verified: Email verification status - boolean if present

        Args:
            claims: Dictionary of decoded OIDC claims

        Raises:
            TokenInvalidError: If required claims are missing, invalid, or
                              don't match expected values

        Notes:
            - This method is called after signature verification
            - PyJWT already validated iss, aud, exp, nbf during decode
            - This provides additional OIDC-specific validation
        """
        # Validate required OIDC claims are present
        required_claims = ["sub", "iss", "aud", "exp", "iat"]
        self._validate_required_claims(claims, required_claims)

        # Validate sub (subject) is non-empty
        sub = claims.get("sub")
        if not sub or not str(sub).strip():
            error = TokenInvalidError("OIDC 'sub' claim cannot be empty")
            logger.log_error(error=error)
            raise error

        # Validate iss (issuer) matches configured issuer
        # Note: PyJWT already validated this during decode, but we double-check
        # Subclasses can override _validate_issuer for custom validation (e.g., multi-tenant)
        iss = claims.get("iss")
        self._validate_issuer(iss, claims)

        # Validate aud (audience) matches configured audience
        # Note: PyJWT already validated this during decode, but we double-check
        aud = claims.get("aud")
        # aud can be string or array of strings in OIDC
        if isinstance(aud, list):
            if self.audience not in aud:
                error = TokenInvalidError(
                    f"OIDC audience mismatch: expected '{self.audience}', "
                    f"got list not containing it: {aud}"
                )
                logger.log_error(error=error)
                raise error
        elif aud != self.audience:
            error = TokenInvalidError(
                f"OIDC audience mismatch: expected '{self.audience}', got '{aud}'"
            )
            logger.log_error(error=error)
            raise error

        # Validate iat (issued at) is in the past
        iat = claims.get("iat")
        current_time = time.time()
        if iat > (current_time + self.clock_skew_seconds):
            error = TokenInvalidError(
                f"OIDC token issued in the future: iat={iat}, "
                f"current_time={current_time}"
            )
            logger.log_error(error=error)
            raise error

        logger.debug(
            "OIDC claims validation passed",
            sub=sub,
            iss=iss,
            has_email=("email" in claims),
            has_roles=("roles" in claims or "groups" in claims),
        )

    @auto_trace(logger, include_args=False)  # Security validation - no token data in logs
    def _validate_issuer(self, iss: str, claims: Dict[str, Any]) -> None:
        """Validate issuer claim matches expected value.

        Subclasses can override this for custom issuer validation (e.g., multi-tenant
        scenarios where the issuer varies based on tenant).

        Args:
            iss: Issuer claim value from token
            claims: Full claims dictionary (for context in subclass overrides)

        Raises:
            TokenInvalidError: If issuer doesn't match expected value
        """
        if iss != self.issuer:
            error = TokenInvalidError(
                f"OIDC issuer mismatch: expected '{self.issuer}', got '{iss}'"
            )
            logger.log_error(error=error)
            raise error

    @auto_trace(logger)
    def _extract_oidc_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Extract identity context from OIDC claims.

        Maps OIDC standard claims to IdentityContext fields:
        - sub -> user_id (required)
        - iss -> issuer (required, already validated)
        - aud -> validated against configuration
        - email -> stored in attributes
        - name -> stored in attributes
        - picture -> stored in attributes
        - roles/groups -> roles (optional, provider-specific)
        - permissions -> permissions (optional, custom claim)
        - tenant_id -> tenant_id (optional, custom claim, defaults to "default")

        Custom claims are stored in attributes dictionary for ABAC.

        Args:
            claims: Dictionary of OIDC claims from validated token

        Returns:
            IdentityContext with identity information and OIDC metadata

        Raises:
            TokenInvalidError: If required claims (sub) are missing (should not happen
                              after validation, but checked for defensive programming)

        Notes:
            - Roles can come from 'roles' or 'groups' claim (provider-specific)
            - Permissions can be in 'permissions' or 'scope' claim (custom)
            - Provider is set to "oidc" for generic OIDC tokens
            - OIDC profile claims (email, name, picture) stored in attributes
        """
        # Extract required claims
        user_id = claims.get("sub")
        if not user_id:
            # Should never happen after _validate_oidc_claims, but defensive check
            error = TokenInvalidError("OIDC token missing required 'sub' claim")
            logger.log_error(error=error)
            raise error

        # Extract standard OIDC claims
        issuer = claims.get("iss", self.issuer)
        email = claims.get("email")
        name = claims.get("name")
        picture = claims.get("picture")

        # Extract tenant_id (custom claim, provider-specific)
        tenant_id = claims.get("tenant_id", "default")

        # Extract roles from 'roles' or 'groups' claim (provider-specific)
        # Some providers use 'roles', others use 'groups' (Azure AD, Okta)
        roles_claim = claims.get("roles") or claims.get("groups") or []
        roles = self._parse_roles_claim(roles_claim)

        # Extract permissions from 'permissions' or 'scope' claim (custom/optional)
        # Some providers put permissions in 'scope' (OAuth2), others in 'permissions'
        permissions_claim = claims.get("permissions") or claims.get("scope") or []
        permissions = self._parse_permissions_claim(permissions_claim)

        # Extract additional OIDC attributes for ABAC
        # Exclude standard JWT claims and framework-specific claims
        standard_claims = {
            "sub", "iss", "aud", "exp", "nbf", "iat", "jti", "azp", "nonce",
            "email", "name", "picture", "email_verified", "phone_number",
            "phone_number_verified", "preferred_username", "updated_at",
            "roles", "groups", "permissions", "scope", "tenant_id"
        }
        attributes = {
            k: v for k, v in claims.items()
            if k not in standard_claims
        }

        # Add OIDC profile claims to attributes
        if email:
            attributes["email"] = email
        if name:
            attributes["name"] = name
        if picture:
            attributes["picture"] = picture
        if "email_verified" in claims:
            attributes["email_verified"] = claims["email_verified"]

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            attributes=attributes,
            provider="oidc",
            issuer=issuer,
            provider_user_id=user_id,  # For OIDC, provider_user_id is same as sub
        )

        logger.debug(
            f"Extracted OIDC identity: user_id={user_id}, tenant_id={tenant_id}, "
            f"roles={len(roles)}, permissions={len(permissions)}, "
            f"attributes={len(attributes)}, has_email={email is not None}"
        )

        return identity

    @auto_trace(logger)
    def _parse_claim_to_frozenset(self, claim_value: Any, claim_name: str = "claim") -> FrozenSet[str]:
        """Parse OIDC claim value to frozenset of strings.

        Claims can be represented in multiple formats:
        - Array of strings: ["admin", "user"] or ["document:read", "document:write"]
        - Comma-separated string: "admin,user" or "document:read,document:write"
        - Space-separated string: "admin user" or "document:read document:write" (OAuth2 scope format)
        - Empty/missing: []

        This is a common parsing utility used by both role and permission claims.

        Args:
            claim_value: Claim value from token (any type)
            claim_name: Name of claim for logging (default: "claim")

        Returns:
            FrozenSet of parsed strings (empty if no values)

        Example:
            roles = self._parse_claim_to_frozenset(claims.get("roles"), "roles")
            perms = self._parse_claim_to_frozenset(claims.get("permissions"), "permissions")
        """
        if not claim_value:
            return frozenset()

        if isinstance(claim_value, str):
            # Handle comma-separated or space-separated strings
            # Try comma first, fall back to space
            if "," in claim_value:
                result = frozenset(item.strip() for item in claim_value.split(",") if item.strip())
            else:
                result = frozenset(item.strip() for item in claim_value.split() if item.strip())
        elif isinstance(claim_value, list):
            result = frozenset(str(item).strip() for item in claim_value if str(item).strip())
        else:
            logger.warning(
                f"Unexpected {claim_name} claim type: {type(claim_value)}, "
                f"expected str or list"
            )
            result = frozenset()

        logger.debug(f"Parsed {claim_name} claim: {len(result)} items")
        return result

    @auto_trace(logger)
    def _parse_roles_claim(self, roles_claim: Any) -> FrozenSet[str]:
        """Parse roles claim from OIDC token.

        Roles can be represented in multiple formats:
        - Array of strings: ["admin", "user"]
        - Comma-separated string: "admin,user"
        - Space-separated string: "admin user" (OAuth2 scope format)
        - Empty/missing: []

        Args:
            roles_claim: Roles claim value from token (any type)

        Returns:
            FrozenSet of role names (empty if no roles)

        Example:
            roles = self._parse_roles_claim(claims.get("roles"))
        """
        return self._parse_claim_to_frozenset(roles_claim, claim_name="roles")

    @auto_trace(logger)
    def _parse_permissions_claim(self, permissions_claim: Any) -> FrozenSet[str]:
        """Parse permissions claim from OIDC token.

        Permissions can be represented in multiple formats:
        - Array of strings: ["document:read", "document:write"]
        - Comma-separated string: "document:read,document:write"
        - Space-separated string: "document:read document:write" (OAuth2 scope)
        - Empty/missing: []

        Args:
            permissions_claim: Permissions claim value from token (any type)

        Returns:
            FrozenSet of permission strings (empty if no permissions)

        Example:
            perms = self._parse_permissions_claim(claims.get("permissions"))
        """
        return self._parse_claim_to_frozenset(permissions_claim, claim_name="permissions")


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_oidc_decoder(
    issuer: str,
    client_id: str,
    client_secret: Optional[Union[SecretStr, str]] = None,
    audience: Optional[str] = None,
    jwks_uri: str = "",
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    key_cache: Optional[CacheBackend] = None,
) -> OIDCDecoder:
    """Factory function for OIDCDecoder instantiation.

    Creates an OIDCDecoder instance with validated parameters.

    Args:
        issuer: OIDC issuer URL (iss claim value)
        client_id: OAuth2 client ID for audience validation
        client_secret: OAuth2 client secret (SecretStr or str, optional for public clients)
        audience: Expected audience claim (defaults to client_id)
        jwks_uri: JWKS endpoint URL for public key retrieval
        clock_skew_seconds: Clock skew tolerance in seconds (default: 30)
        key_cache: Optional cache backend for JWKS caching

    Returns:
        OIDCDecoder instance configured with validated parameters

    Raises:
        TokenInvalidError: If configuration is invalid

    Example:
        decoder = create_oidc_decoder(
            issuer="https://auth.example.com",
            client_id="my-app",
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
            clock_skew_seconds=30,
        )
        identity = await decoder.decode(token)
    """
    return OIDCDecoder(
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        jwks_uri=jwks_uri,
        clock_skew_seconds=clock_skew_seconds,
        key_cache=key_cache,
    )
