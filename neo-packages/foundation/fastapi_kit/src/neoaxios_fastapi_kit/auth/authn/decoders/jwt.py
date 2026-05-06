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

"""JWT decoder for local token validation.

Validates locally-issued JWT tokens using public key cryptography.
Supports RS256 (RSA with SHA-256) and HS256 (HMAC with SHA-256) algorithms.

This decoder is for validating tokens issued by your own authorization server.
For third-party identity providers (Azure AD, AWS Cognito, Google), use
provider-specific decoders that handle JWKS key rotation and introspection.

Usage:
    from neoaxios_fastapi_kit.auth.decoders.jwt import JWTDecoder

    # RS256 with RSA public key
    decoder = JWTDecoder(
        public_key=open("public_key.pem").read(),
        algorithm="RS256",
        issuer="https://auth.mycompany.com",
        audience="api://my-service",
    )

    # HS256 with shared secret
    decoder = JWTDecoder(
        public_key="your-secret-key",
        algorithm="HS256",
        issuer="https://auth.mycompany.com",
    )

    # Decode and validate token
    identity = await decoder.decode(token)
"""


from typing import Any, Dict, Optional, Union

import jwt
from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    TokenExpiredError,
)

logger = get_telemetry(__name__)


class JWTDecoder(BaseDecoder):
    """Decode and validate locally-issued JWT tokens.

    Validates JWT signature, expiration, issuer, and audience claims.
    Maps JWT claims to IdentityContext for use with authorization framework.

    This decoder does NOT check revocation - local JWTs are validated by
    signature and expiration only. For revocation support, use tokens with
    short TTL and refresh token rotation, or implement external revocation
    checking via is_revoked().

    Attributes:
        public_key: RSA public key (PEM format) or HMAC shared secret
        algorithm: JWT algorithm (RS256 or HS256)
        issuer: Expected issuer claim (iss) for validation
        audience: Expected audience claim (aud) for validation (optional)
        clock_skew_seconds: Clock skew tolerance for time-based claims
    """

    @auto_trace(logger)
    def __init__(
        self,
        public_key: Union[str, bytes],
        algorithm: str = "RS256",
        issuer: str = "",
        audience: Optional[str] = None,
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    ):
        """Initialize JWT decoder with validation parameters.

        Args:
            public_key: RSA public key (PEM format) for RS256, or shared secret for HS256.
                       Can be string or bytes.
            algorithm: JWT signing algorithm. Must be "RS256" or "HS256".
                      RS256 uses RSA public key cryptography (recommended for production).
                      HS256 uses HMAC with shared secret (simpler for development).
            issuer: Expected JWT issuer (iss claim). Must match token issuer exactly.
                   Example: "https://auth.mycompany.com"
            audience: Optional expected audience (aud claim). If provided, token aud
                     must match exactly. If None, audience is not validated.
                     Example: "api://my-service"
            clock_skew_seconds: Clock skew tolerance in seconds for exp/nbf validation.
                               Allows for time drift between token issuer and validator.
                               Default: 30 seconds (recommended for distributed systems)

        Raises:
            AuthError: If algorithm is not supported or configuration is invalid
        """
        if algorithm not in ("RS256", "HS256"):
            error = AuthError(
                f"Unsupported algorithm '{algorithm}'. Only RS256 and HS256 are supported."
            )
            logger.log_error(error=error)
            raise error

        if not issuer:
            error = AuthError("Issuer is required for JWT validation")
            logger.log_error(error=error)
            raise error

        # Convert string key to bytes if needed
        if isinstance(public_key, str):
            public_key = public_key.encode("utf-8")

        self.public_key = public_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.clock_skew_seconds = clock_skew_seconds

        logger.info(
            f"Initialized JWTDecoder with algorithm={algorithm}, "
            f"issuer={issuer}, audience={audience}, "
            f"clock_skew={clock_skew_seconds}s"
        )

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and validate JWT token to identity context.

        Performs full validation:
        1. Signature verification using public key
        2. Expiration check (exp claim)
        3. Not-before check (nbf claim, if present)
        4. Issuer validation (iss claim must match)
        5. Audience validation (aud claim must match, if configured)

        Args:
            token: JWT token string (header.payload.signature)

        Returns:
            IdentityContext with user identity and attributes from JWT claims

        Raises:
            TokenInvalidError: Token format is invalid, signature verification failed,
                              or required claims are missing
            TokenExpiredError: Token has expired (exp claim is in the past)

        Example:
            identity = await decoder.decode(bearer_token)
            logger.info(f"Decoded JWT token", user_id=identity.user_id, roles=identity.roles)
        """
        # Verify signature and extract claims
        try:
            claims = self._verify_signature(token)
        except TokenExpiredError:
            # Re-raise TokenExpiredError as-is
            raise
        except TokenInvalidError:
            # Re-raise TokenInvalidError as-is
            raise
        except Exception as e:
            error = TokenInvalidError(f"JWT verification failed: {str(e)}")
            logger.log_error(error=error)
            raise error

        # Expiration already validated by PyJWT (leeway=clock_skew_seconds,
        # require_exp=True) in _verify_signature. No redundant check needed.

        # Extract identity from claims
        identity = self._extract_identity(claims)

        logger.info(
            f"Successfully decoded JWT for user_id='{identity.user_id}' "
            f"from issuer='{identity.issuer}'"
        )

        return identity

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if token is valid without extracting identity.

        Performs same validation as decode() but returns boolean instead
        of raising exceptions. Useful for permission checks where you only
        need to know if token is valid.

        Args:
            token: JWT token string

        Returns:
            True if token is valid (signature, expiration, issuer all pass),
            False otherwise

        Example:
            is_valid = await decoder.validate(token)
            if is_valid:
                logger.info("Token validation successful")
            else:
                logger.warning("Token validation failed")
        """
        try:
            await self.decode(token)
            return True
        except (TokenInvalidError, TokenExpiredError) as e:
            logger.debug(f"Token validation failed: {str(e)}")
            return False
        except Exception as e:
            logger.log_error(error=e)
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if token has been revoked.

        For local JWT tokens validated by signature only, revocation is not
        supported by default. This method always returns False.

        To implement revocation:
        1. Use short-lived tokens (5-15 minutes) with refresh token rotation
        2. Implement external revocation list (Redis set of revoked JTIs)
        3. Override this method in a subclass to check revocation list
        4. Include 'jti' (JWT ID) claim in tokens for revocation tracking

        Args:
            token: JWT token string

        Returns:
            False (revocation not supported for signature-only validation)

        Example:
            if await decoder.is_revoked(token):
                raise TokenRevokedError("Token has been revoked")
        """
        # JWT tokens validated by signature do not support revocation checking
        # by default. For revocation support:
        # - Use short-lived tokens with refresh rotation
        # - Implement external revocation list (override this method)
        return False

    @auto_trace(logger)
    def _verify_signature(self, token: str) -> Dict[str, Any]:
        """Verify JWT signature and decode claims.

        Uses PyJWT library to verify signature with configured public key
        and algorithm. Validates issuer and audience claims during verification.

        Args:
            token: JWT token string

        Returns:
            Dictionary of JWT claims (payload)

        Raises:
            TokenInvalidError: Signature verification failed, invalid format,
                              or required claims missing
            TokenExpiredError: Token has expired (raised by PyJWT)
        """
        try:
            # Build validation options
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": self.audience is not None,
                "require_exp": True,
                "require_iss": True,
            }

            # Decode and verify token
            claims = jwt.decode(
                token,
                key=self.public_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options=options,
                leeway=self.clock_skew_seconds,
            )

            return claims

        except jwt.ExpiredSignatureError:
            error = TokenExpiredError("Token has expired")
            logger.log_error(error=error)
            raise error

        except jwt.InvalidTokenError as e:
            # Covers: InvalidSignatureError, DecodeError, InvalidIssuerError,
            # InvalidAudienceError, etc.
            error = TokenInvalidError(f"Invalid JWT token: {str(e)}")
            logger.log_error(error=error)
            raise error

        except Exception as e:
            error = TokenInvalidError(f"JWT verification error: {str(e)}")
            logger.log_error(error=error)
            raise error

    @auto_trace(logger)
    def _extract_identity(self, claims: Dict[str, Any]) -> IdentityContext:
        """Extract identity context from JWT claims.

        Maps standard JWT claims to IdentityContext fields:
        - sub -> user_id (required)
        - iss -> issuer (required, already validated)
        - aud -> validated against configuration
        - roles -> roles (optional, defaults to empty frozenset)
        - permissions -> permissions (optional, defaults to empty frozenset)
        - tenant_id -> tenant_id (optional, defaults to "default")
        - Custom claims -> attributes dictionary

        Args:
            claims: JWT payload claims dictionary

        Returns:
            IdentityContext with identity information

        Raises:
            TokenInvalidError: If required claims (sub) are missing

        Notes:
            - Roles and permissions can be arrays or comma-separated strings
            - Additional claims are stored in attributes dict for ABAC
            - Provider is always set to "jwt" for local tokens
        """
        # Extract required claims
        user_id = claims.get("sub")
        if not user_id:
            error = TokenInvalidError("Token missing required 'sub' (subject) claim")
            logger.log_error(error=error)
            raise error

        # Extract standard claims
        issuer = claims.get("iss", self.issuer)
        tenant_id = claims.get("tenant_id", "default")

        # Extract roles (array or comma-separated string)
        roles_claim = claims.get("roles", [])
        if isinstance(roles_claim, str):
            roles = frozenset(r.strip() for r in roles_claim.split(",") if r.strip())
        elif isinstance(roles_claim, list):
            roles = frozenset(roles_claim)
        else:
            roles = frozenset()

        # Extract permissions (array or comma-separated string)
        permissions_claim = claims.get("permissions", [])
        if isinstance(permissions_claim, str):
            permissions = frozenset(
                p.strip() for p in permissions_claim.split(",") if p.strip()
            )
        elif isinstance(permissions_claim, list):
            permissions = frozenset(permissions_claim)
        else:
            permissions = frozenset()

        # Extract additional attributes for ABAC
        # Exclude standard JWT claims and our framework claims
        standard_claims = {
            "sub", "iss", "aud", "exp", "nbf", "iat", "jti",
            "roles", "permissions", "tenant_id"
        }
        attributes = {
            k: v for k, v in claims.items()
            if k not in standard_claims
        }

        # Build identity context
        identity = IdentityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            attributes=attributes,
            provider="jwt",
            issuer=issuer,
            provider_user_id=user_id,  # For JWT, provider_user_id is same as user_id
        )

        logger.debug(
            f"Extracted identity: user_id={user_id}, tenant_id={tenant_id}, "
            f"roles={len(roles)}, permissions={len(permissions)}, "
            f"attributes={len(attributes)}"
        )

        return identity


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger)
def create_jwt_decoder(
    public_key: Union[str, bytes],
    algorithm: str = "RS256",
    issuer: str = "",
    audience: Optional[str] = None,
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
) -> JWTDecoder:
    """Factory function for JWTDecoder instantiation.

    Creates a JWTDecoder instance with validated parameters.

    Args:
        public_key: RSA public key (PEM format) for RS256, or shared secret for HS256
        algorithm: JWT signing algorithm (RS256 or HS256, default: RS256)
        issuer: Expected JWT issuer (iss claim)
        audience: Expected audience (aud claim, optional)
        clock_skew_seconds: Clock skew tolerance in seconds (default: 30)

    Returns:
        JWTDecoder instance configured with validated parameters

    Raises:
        AuthError: If algorithm is unsupported or configuration is invalid

    Example:
        decoder = create_jwt_decoder(
            public_key=open("public_key.pem").read(),
            algorithm="RS256",
            issuer="https://auth.example.com",
        )
        identity = await decoder.decode(token)
    """
    return JWTDecoder(
        public_key=public_key,
        algorithm=algorithm,
        issuer=issuer,
        audience=audience,
        clock_skew_seconds=clock_skew_seconds,
    )
