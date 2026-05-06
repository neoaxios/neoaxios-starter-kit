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

"""Base decoder abstract class for token validation.

Defines the abstract base class that all provider-specific token decoders
must extend. Provides common validation helpers for JWT token structure,
payload decoding, and claims extraction.

This base class establishes the interface contract for:
- Token decoding and validation
- Revocation checking
- Common JWT parsing utilities

Provider-specific implementations (Azure, Cognito, Google, etc.) extend
this base and implement provider-specific signature verification, key
rotation, and claims mapping.

Usage:
    from neoaxios_fastapi_kit.auth.decoders.base import BaseDecoder
    from neoaxios_fastapi_kit.auth.context import IdentityContext

    class MyProviderDecoder(BaseDecoder):
        async def decode(self, token: str) -> IdentityContext:
            # Validate structure
            self._validate_token_structure(token)

            # Extract claims
            claims = self._extract_claims(token)

            # Provider-specific validation
            await self._verify_signature(token)

            # Map to IdentityContext
            return IdentityContext(
                user_id=claims["sub"],
                tenant_id=claims["tenant_id"],
                ...
            )

        async def validate(self, token: str) -> bool:
            try:
                await self.decode(token)
                return True
            except AuthError:
                return False

        async def is_revoked(self, token: str) -> bool:
            # Check revocation list
            return False
"""

import base64
import json
from abc import ABC, abstractmethod
from typing import Any, Dict

from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
)

logger = get_telemetry(__name__)


@auto_trace(logger)
def decode_jwt_payload_unsafe(token: str) -> Dict[str, Any]:
    """Decode JWT payload without signature verification.

    Shared utility for extracting claims before expensive verification.
    Used by BaseDecoder._decode_payload() and MultiProviderTokenDecoder.

    WARNING: Returned claims are untrusted until signature verification.

    Args:
        token: JWT token string to decode

    Returns:
        Dictionary of decoded claims from payload

    Raises:
        TokenInvalidError: If payload cannot be base64 decoded or JSON parsed
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            error = TokenInvalidError(
                f"Invalid JWT format: expected 3 parts, got {len(parts)}"
            )
            logger.log_error(error)
            raise error

        # Get payload (middle part)
        payload_b64 = parts[1]

        # Add padding if needed (base64 requires length to be multiple of 4)
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        # Decode from base64
        payload_bytes = base64.urlsafe_b64decode(payload_b64)

        # Parse JSON
        claims = json.loads(payload_bytes)

        logger.debug(
            "Payload decoded successfully",
            claims_count=len(claims),
            has_issuer=("iss" in claims),
            has_subject=("sub" in claims),
        )

        return claims

    except (ValueError, json.JSONDecodeError) as e:
        error = TokenInvalidError(f"Failed to decode JWT payload: {str(e)}")
        logger.log_error(error)
        raise error


class BaseDecoder(ABC):
    """Abstract base class for token decoders.

    All provider-specific decoders (Azure, AWS, Google, etc.) must extend
    this base class and implement the abstract methods for token validation.

    This base class provides:
    - Abstract interface for decode(), validate(), is_revoked()
    - Helper methods for JWT structure validation
    - Common payload decoding utilities
    - Error handling patterns

    Subclasses must implement:
    - decode(): Full token validation and identity extraction
    - validate(): Quick validation check
    - is_revoked(): Revocation status check

    Common Validation Flow:
    1. Call _validate_token_structure() to check JWT format
    2. Call _decode_payload() to extract claims without verification
    3. Perform provider-specific signature verification
    4. Check expiration and other time-based claims
    5. Call _extract_claims() to parse all claims
    6. Map claims to IdentityContext
    7. Check revocation status if needed
    """

    @abstractmethod
    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode and fully validate token, returning identity context.

        This method must perform complete token validation including:
        - JWT structure validation
        - Signature verification against provider's public keys
        - Expiration and time-based claim validation
        - Required claims presence validation
        - Claims mapping to IdentityContext

        Args:
            token: JWT token string to decode and validate

        Returns:
            IdentityContext with user identity, roles, permissions, and metadata

        Raises:
            TokenInvalidError: Token format invalid, signature fails, or required claims missing
            TokenExpiredError: Token expiration (exp) claim is in the past
            TokenRevokedError: Token appears on revocation list
            AuthError: Other authentication/authorization failures

        Example:
            identity = await decoder.decode(token)
            logger.info("Token decoded", user_id=identity.user_id, tenant_id=identity.tenant_id)
        """
        pass

    @abstractmethod
    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if token is valid without full decoding.

        This method performs lightweight validation to check if a token
        is structurally valid and not expired. It may skip expensive
        operations like full claims extraction.

        Implementation typically calls decode() and catches exceptions,
        or performs subset validation for performance.

        Args:
            token: JWT token string to validate

        Returns:
            True if token is valid, False otherwise

        Example:
            if await decoder.validate(token):
                # Token is valid, proceed with decode()
                identity = await decoder.decode(token)
        """
        pass

    @abstractmethod
    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if token has been explicitly revoked.

        This method checks if the token has been revoked through:
        - Token introspection endpoint
        - Revocation list lookup
        - User logout/password change events
        - Explicit token invalidation

        Implementation is provider-specific and may involve:
        - Cache lookup for revoked token IDs
        - HTTP call to introspection endpoint
        - Database query for revocation status

        Args:
            token: JWT token string to check

        Returns:
            True if token is revoked, False otherwise

        Raises:
            TokenInvalidError: If token cannot be parsed to extract ID/claims

        Example:
            if await decoder.is_revoked(token):
                raise TokenRevokedError("Token has been revoked")
        """
        pass

    @auto_trace(logger)
    def _validate_token_structure(self, token: str) -> None:
        """Validate JWT token has correct structure (3 parts).

        Helper method to check that the token string follows JWT format:
        header.payload.signature (3 base64-encoded parts separated by dots).

        This is a fast structural check performed before expensive operations
        like signature verification. It does not validate the actual contents
        or cryptographic signature.

        Args:
            token: JWT token string to validate

        Raises:
            TokenInvalidError: If token does not have exactly 3 parts

        Example:
            self._validate_token_structure(token)
            # Token has correct JWT structure, proceed with validation
        """
        parts = token.split(".")
        if len(parts) != 3:
            error = TokenInvalidError(
                f"Invalid JWT format: expected 3 parts (header.payload.signature), "
                f"got {len(parts)} parts"
            )
            logger.log_error(error)
            raise error

        logger.debug("Token structure validation passed", parts_count=len(parts))

    @auto_trace(logger)
    def _decode_payload(self, token: str) -> Dict[str, Any]:
        """Decode JWT payload without signature verification.

        Delegates to module-level decode_jwt_payload_unsafe() to avoid
        code duplication.

        WARNING: Returned claims are untrusted until signature verification.

        Args:
            token: JWT token string to decode

        Returns:
            Dictionary of decoded claims from payload

        Raises:
            TokenInvalidError: If payload cannot be base64 decoded or JSON parsed
        """
        return decode_jwt_payload_unsafe(token)

    @auto_trace(logger)
    def _extract_claims(self, token: str) -> Dict[str, Any]:
        """Extract all claims from token payload.

        This is a convenience method that combines structure validation and
        payload decoding. Use this when you need to extract claims after
        verifying the token structure.

        This method does NOT perform signature verification. It only extracts
        the claims for inspection. Signature verification must be done separately.

        Args:
            token: JWT token string

        Returns:
            Dictionary of all claims from token payload

        Raises:
            TokenInvalidError: If token structure is invalid or payload cannot be decoded

        Example:
            claims = self._extract_claims(token)
            user_id = claims.get("sub")
            email = claims.get("email")
            # Verify signature before trusting these claims
        """
        # Validate structure first
        self._validate_token_structure(token)

        # Decode payload
        claims = self._decode_payload(token)

        logger.debug(
            "Claims extracted",
            token_prefix=token[:20] + "...",
            claims_keys=list(claims.keys()),
        )

        return claims

    @auto_trace(logger)
    def _validate_required_claims(
        self, claims: Dict[str, Any], required: list[str]
    ) -> None:
        """Validate that all required claims are present.

        Helper method to check that the decoded claims contain all required
        fields. Common required claims include:
        - sub (subject/user ID)
        - iss (issuer)
        - exp (expiration)
        - aud (audience)

        Args:
            claims: Dictionary of decoded claims
            required: List of required claim names

        Raises:
            TokenInvalidError: If any required claim is missing

        Example:
            claims = self._decode_payload(token)
            self._validate_required_claims(claims, ["sub", "iss", "exp"])
            # All required claims are present
        """
        missing = [claim for claim in required if claim not in claims]

        if missing:
            error = TokenInvalidError(
                f"Token missing required claims: {', '.join(missing)}. "
                f"Present claims: {', '.join(claims.keys())}"
            )
            logger.log_error(error)
            raise error

        logger.debug(
            "Required claims validation passed",
            required_claims=required,
            claims_count=len(claims),
        )
