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

"""Development JWT decoder for local authentication.

Provides JWT-based authentication for development/testing environments that
mirrors production Azure AD token structure without requiring external identity
provider setup.

SECURITY: This decoder is BLOCKED in production environments.
Only allowed when NEO_ENV is one of: development, local, dev, test.
This is the first of several defense-in-depth checks that block
development authentication paths from running in production.

Token Claims Structure (Azure AD compatible):
    - iss: Issuer (dev-auth)
    - sub: Subject (same as oid)
    - aud: Audience (dev)
    - oid: Object ID (maps to user_id)
    - tid: Tenant ID (maps to tenant_id)
    - roles: Array of role names
    - exp: Expiration timestamp
    - iat: Issued at timestamp
    - nbf: Not before timestamp

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders import DevJWTDecoder, create_dev_jwt_decoder
    from neoaxios_logging import get_telemetry

    logger = get_telemetry(__name__)

    # Using factory function (recommended)
    decoder = create_dev_jwt_decoder(
        secret_key="your-32-char-minimum-secret-key-here",
        issuer="dev-auth",
        audience="dev"
    )

    # Decode a token
    identity = await decoder.decode(token)
    logger.info("Token decoded", user_id=identity.user_id, tenant_id=identity.tenant_id)
"""

import os
from typing import Any, Dict, Optional

import jwt
from pydantic import SecretStr

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    TokenExpiredError,
    SecurityError,
)
from neoaxios_fastapi_kit.auth.config import ALLOWED_DEV_ENVIRONMENTS
from neoaxios_fastapi_kit.auth.defaults import DEFAULT_TOKEN_CLOCK_SKEW_SECONDS

logger = get_telemetry(__name__)

# =============================================================================
# Security Constants
# =============================================================================

# ALLOWED_DEV_ENVIRONMENTS imported from neoaxios_fastapi_kit.auth.config
# Canonical definition in schemas.py - environments where dev-jwt is permitted

# Required claims for a valid dev JWT token
REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "oid", "tid", "exp", "iat"})


# =============================================================================
# DevJWTDecoder
# =============================================================================


class DevJWTDecoder(BaseDecoder):
    """JWT decoder for development tokens - BLOCKED BY DEFAULT.

    Security Model: ALLOWLIST ONLY
    - Only environments in ALLOWED_DEV_ENVIRONMENTS can use this decoder
    - All other environments are blocked, including unset NEO_ENV
    - This is fail-closed security: deny by default, allow explicitly

    This is the first of several defense-in-depth checks that prevent
    development authentication from running in production:
    1. DevJWTDecoder.__init__ - Raises SecurityError (this check)
    2. AuthConfig validator - Raises ValueError
    3. AzureADDecoder.decode - Rejects dev issuers
    4. Application startup - Raises RuntimeError

    Attributes:
        secret_key: HS256 signing secret (stored as SecretStr)
        algorithm: JWT algorithm (HS256, HS384, HS512)
        issuer: Expected token issuer (iss claim)
        audience: Expected token audience (aud claim)
        clock_skew_seconds: Maximum allowed clock skew for exp/nbf validation

    Example:
        decoder = DevJWTDecoder(
            secret_key="your-32-char-minimum-secret-key",
            issuer="dev-auth",
            audience="dev"
        )
        identity = await decoder.decode(token)
    """

    @auto_trace(logger, include_args=False)  # Security: don't log secret_key
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        issuer: str = "dev-auth",
        audience: str = "dev",
        clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
    ):
        """Initialize DevJWTDecoder with production block.

        Args:
            secret_key: HS256 signing secret (min 32 characters)
            algorithm: JWT algorithm (HS256, HS384, HS512)
            issuer: Expected token issuer
            audience: Expected token audience
            clock_skew_seconds: Max clock skew for exp/nbf (5-60)

        Raises:
            SecurityError: If NEO_ENV is unset or not in allowlist
            ValueError: If secret_key is too short or algorithm invalid
        """
        # === PRODUCTION BLOCK (ALLOWLIST) ===
        current_env = os.getenv("NEO_ENV", "").lower()

        # FAIL CLOSED: Block if NEO_ENV is not set
        if not current_env:
            logger.error(
                "DevJWTDecoder blocked: NEO_ENV not set",
                extra={
                    "allowed_environments": sorted(ALLOWED_DEV_ENVIRONMENTS),
                    "neo_env": "unset",
                    "security_block": True,
                },
            )
            raise SecurityError(
                f"DevJWTDecoder requires NEO_ENV to be explicitly set. "
                f"Allowed values: {sorted(ALLOWED_DEV_ENVIRONMENTS)}. "
                f"Refusing to initialize without explicit environment declaration."
            )

        # FAIL CLOSED: Block if not in allowlist
        if current_env not in ALLOWED_DEV_ENVIRONMENTS:
            logger.error(
                "DevJWTDecoder blocked: environment not in allowlist",
                extra={
                    "neo_env": current_env,
                    "allowed_environments": sorted(ALLOWED_DEV_ENVIRONMENTS),
                    "security_block": True,
                },
            )
            raise SecurityError(
                f"DevJWTDecoder is BLOCKED in '{current_env}' environment. "
                f"Only allowed in: {sorted(ALLOWED_DEV_ENVIRONMENTS)}. "
                f"Use auth_mode='azure-ad' for non-development deployments."
            )

        # Validate algorithm
        allowed_algorithms = {"HS256", "HS384", "HS512"}
        if algorithm not in allowed_algorithms:
            raise ValueError(
                f"algorithm must be one of {allowed_algorithms}, got '{algorithm}'"
            )

        # Validate secret key length
        if len(secret_key) < 32:
            raise ValueError(
                f"secret_key must be at least 32 characters, got {len(secret_key)}. "
                f"Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        # Validate clock_skew_seconds
        if not 5 <= clock_skew_seconds <= 60:
            raise ValueError(
                f"clock_skew_seconds must be between 5 and 60, got {clock_skew_seconds}"
            )

        # Passed allowlist check - safe to initialize
        self._secret_key = SecretStr(secret_key)
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.clock_skew_seconds = clock_skew_seconds

        logger.info(
            "DevJWTDecoder initialized",
            extra={
                "neo_env": current_env,
                "algorithm": algorithm,
                "issuer": issuer,
                "audience": audience,
                "clock_skew_seconds": clock_skew_seconds,
            },
        )

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and validate development JWT token.

        Validates:
        - JWT structure (3 parts)
        - HS256 signature using secret_key
        - Issuer claim matches expected issuer
        - Audience claim matches expected audience
        - Token not expired (exp claim)
        - Token not used before valid time (nbf claim)
        - Required claims present (iss, sub, aud, oid, tid, exp, iat)

        Args:
            token: JWT token string to decode

        Returns:
            IdentityContext with user identity from token claims:
            - user_id: from oid claim
            - tenant_id: from tid claim
            - roles: from roles claim (list)
            - provider: "dev-jwt"
            - issuer: from iss claim

        Raises:
            TokenInvalidError: Token format invalid, signature fails, or claims invalid
            TokenExpiredError: Token exp claim is in the past
        """
        # Validate structure first
        self._validate_token_structure(token)

        try:
            # Decode and verify signature
            claims = jwt.decode(
                token,
                self._secret_key.get_secret_value(),
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )

        except jwt.ExpiredSignatureError as e:
            logger.warning(
                "Token expired",
                extra={"error": str(e)},
            )
            raise TokenExpiredError(f"Token has expired: {e}")

        except jwt.InvalidIssuerError as e:
            logger.warning(
                "Invalid issuer",
                extra={"error": str(e), "expected_issuer": self.issuer},
            )
            raise TokenInvalidError(f"Invalid token issuer: {e}")

        except jwt.InvalidAudienceError as e:
            logger.warning(
                "Invalid audience",
                extra={"error": str(e), "expected_audience": self.audience},
            )
            raise TokenInvalidError(f"Invalid token audience: {e}")

        except jwt.InvalidSignatureError as e:
            logger.warning(
                "Invalid signature",
                extra={"error": str(e)},
            )
            raise TokenInvalidError("Token signature verification failed")

        except jwt.DecodeError as e:
            logger.warning(
                "Token decode error",
                extra={"error": str(e)},
            )
            raise TokenInvalidError(f"Failed to decode token: {e}")

        except jwt.PyJWTError as e:
            logger.warning(
                "JWT validation error",
                extra={"error": str(e)},
            )
            raise TokenInvalidError(f"Token validation failed: {e}")

        # Validate required claims
        self._validate_required_dev_claims(claims)

        # Map Azure AD-compatible claims to IdentityContext
        identity = IdentityContext(
            user_id=claims["oid"],
            tenant_id=claims["tid"],
            roles=frozenset(claims.get("roles", [])),
            permissions=frozenset(claims.get("permissions", [])),
            attributes=self._extract_attributes(claims),
            provider="dev-jwt",
            issuer=claims.get("iss"),
            provider_user_id=claims.get("sub"),
        )

        logger.info(
            "Token decoded successfully",
            extra={
                "user_id": identity.user_id,
                "tenant_id": identity.tenant_id,
                "roles": list(identity.roles),
                "provider": identity.provider,
            },
        )

        return identity

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if token is valid without full decoding.

        Performs quick validation by attempting decode() and catching exceptions.

        Args:
            token: JWT token string to validate

        Returns:
            True if token is valid, False otherwise
        """
        try:
            await self.decode(token)
            return True
        except (TokenInvalidError, TokenExpiredError):
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if token has been revoked.

        Development tokens do not support revocation - always returns False.
        For production use cases requiring revocation, use Azure AD or OIDC
        providers with proper revocation support.

        Args:
            token: JWT token string to check

        Returns:
            False (dev tokens cannot be revoked)
        """
        # Dev tokens don't support revocation
        # For actual revocation support, use production providers
        return False

    @auto_trace(logger)
    def _validate_required_dev_claims(self, claims: Dict[str, Any]) -> None:
        """Validate required claims for development JWT.

        Required claims (Azure AD compatible):
        - iss: Issuer
        - sub: Subject
        - aud: Audience
        - oid: Object ID (user identifier)
        - tid: Tenant ID
        - exp: Expiration
        - iat: Issued at

        Args:
            claims: Decoded JWT claims

        Raises:
            TokenInvalidError: If required claims are missing
        """
        # Check for oid (required for user_id)
        if "oid" not in claims:
            raise TokenInvalidError(
                "Token missing required claim 'oid' (object ID). "
                "Dev JWT tokens must include Azure AD-compatible claims."
            )

        # Check for tid (required for tenant_id)
        if "tid" not in claims:
            raise TokenInvalidError(
                "Token missing required claim 'tid' (tenant ID). "
                "Dev JWT tokens must include Azure AD-compatible claims."
            )

        # Validate roles is a list if present
        roles = claims.get("roles")
        if roles is not None and not isinstance(roles, list):
            raise TokenInvalidError(
                f"Token claim 'roles' must be a list, got {type(roles).__name__}"
            )

        # Validate permissions is a list if present
        permissions = claims.get("permissions")
        if permissions is not None and not isinstance(permissions, list):
            raise TokenInvalidError(
                f"Token claim 'permissions' must be a list, got {type(permissions).__name__}"
            )

    @auto_trace(logger)
    def _extract_attributes(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Extract additional attributes from claims.

        Maps non-standard claims to the attributes dict for ABAC support.

        Args:
            claims: Decoded JWT claims

        Returns:
            Dictionary of additional attributes
        """
        # Standard claims that are mapped elsewhere
        standard_claims = {
            "iss", "sub", "aud", "exp", "iat", "nbf",
            "oid", "tid", "roles", "permissions",
        }

        # Extract non-standard claims as attributes
        attributes = {}
        for key, value in claims.items():
            if key not in standard_claims:
                attributes[key] = value

        return attributes


# =============================================================================
# Factory Function
# =============================================================================


@auto_trace(logger, include_args=False)  # Security: don't log secret_key
def create_dev_jwt_decoder(
    secret_key: Optional[str] = None,
    algorithm: str = "HS256",
    issuer: str = "dev-auth",
    audience: str = "dev",
    clock_skew_seconds: int = DEFAULT_TOKEN_CLOCK_SKEW_SECONDS,
) -> DevJWTDecoder:
    """Factory function to create DevJWTDecoder.

    Creates a DevJWTDecoder instance, optionally reading the secret key from
    the DEV_JWT_SECRET_KEY environment variable if not provided.

    Args:
        secret_key: HS256 signing secret (reads from DEV_JWT_SECRET_KEY env var if None)
        algorithm: JWT algorithm (HS256, HS384, HS512)
        issuer: Expected token issuer
        audience: Expected token audience
        clock_skew_seconds: Max clock skew for exp/nbf validation

    Returns:
        Configured DevJWTDecoder instance

    Raises:
        SecurityError: If NEO_ENV is unset or not in allowlist
        ValueError: If secret_key is not provided and DEV_JWT_SECRET_KEY env var is unset

    Example:
        # Using environment variable (recommended)
        os.environ["DEV_JWT_SECRET_KEY"] = "your-secret"
        decoder = create_dev_jwt_decoder()

        # Using explicit secret
        decoder = create_dev_jwt_decoder(secret_key="your-secret")
    """
    # Read secret from environment if not provided
    if secret_key is None:
        secret_key = os.getenv("DEV_JWT_SECRET_KEY")
        if not secret_key:
            raise ValueError(
                "secret_key is required. Either pass it explicitly or set "
                "the DEV_JWT_SECRET_KEY environment variable."
            )

    return DevJWTDecoder(
        secret_key=secret_key,
        algorithm=algorithm,
        issuer=issuer,
        audience=audience,
        clock_skew_seconds=clock_skew_seconds,
    )
