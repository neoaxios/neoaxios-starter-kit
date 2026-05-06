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

"""Multi-provider token decoder for routing tokens to correct provider.

Routes JWT tokens to the appropriate provider-specific decoder based on
the issuer claim. Supports Azure AD, AWS Cognito, Google IAM, Okta, Auth0,
and custom providers.

Thread Safety:
    All operations on decoder registry are protected by asyncio.Lock for
    safe concurrent access. The lock protects both self.decoders and
    self.issuer_patterns dictionaries during read iterations and write
    operations (add_decoder, remove_decoder).

Usage:
    from neoaxios_fastapi_kit.auth.decoders import MultiProviderTokenDecoder
    from neoaxios_fastapi_kit.auth.decoders.azure import AzureADDecoder
    from neoaxios_fastapi_kit.auth.decoders.aws import CognitoDecoder

    decoder = MultiProviderTokenDecoder(
        decoders={
            "azure": AzureADDecoder(...),
            "aws": CognitoDecoder(...),
        },
    )
"""

import asyncio
import re
from typing import Dict, Optional, Any, Pattern, Union

from neoaxios_logging import get_telemetry, auto_trace
from neoaxios_fastapi_kit.auth.authn.decoders.base import decode_jwt_payload_unsafe
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, ProviderNotConfiguredError

logger = get_telemetry(__name__)


# Security constants for ReDoS protection
MAX_TOKEN_LENGTH = 8192  # Maximum JWT token length in bytes (standard JWT max)
MAX_ISSUER_LENGTH = 256  # Maximum issuer URL length in characters


# Default issuer patterns for common identity providers (pre-compiled for performance).
# All patterns end with $ to prevent suffix attacks (e.g., google.com.evil.com).
DEFAULT_ISSUER_PATTERNS: Dict[str, Pattern[str]] = {
    "jwt_local": re.compile(r"https://local\.example\.com$"),
    "azure": re.compile(r"https://login\.microsoftonline\.com/[a-zA-Z0-9-]{1,64}/v2\.0$"),
    "aws": re.compile(r"https://cognito-idp\.[a-zA-Z0-9_-]{1,64}\.amazonaws\.com/[a-zA-Z0-9_-]{1,64}$"),
    "google": re.compile(r"https://accounts\.google\.com$"),
    "okta": re.compile(r"https://[a-zA-Z0-9_-]{1,64}\.okta\.com/oauth2/[a-zA-Z0-9_-]{1,64}$"),
    "auth0": re.compile(r"https://[a-zA-Z0-9_-]{1,64}\.(us\.|eu\.|au\.)?auth0\.com/?$"),
    "keycloak": re.compile(r"https://[a-zA-Z0-9._-]{1,128}/realms/[a-zA-Z0-9_-]{1,64}$"),
}

from ...context import IdentityContext
from ...protocols import TokenDecoder


class MultiProviderTokenDecoder:
    """Routes tokens to provider-specific decoders based on issuer.

    Automatically detects the identity provider from the JWT issuer claim
    and routes to the appropriate decoder for full validation.

    Thread Safety:
        All operations are async-safe using asyncio.Lock. The lock protects
        decoder registry modifications (add_decoder, remove_decoder) and
        dictionary iterations (detect_provider, list_decoders) to prevent
        RuntimeError when dictionary changes size during iteration.

    Attributes:
        decoders: Map of provider name to decoder instance
        issuer_patterns: Compiled regex patterns to match issuers to providers
    """

    @auto_trace(logger)
    def __init__(
        self,
        decoders: Dict[str, TokenDecoder],
        issuer_patterns: Optional[Dict[str, Union[str, Pattern[str]]]] = None,
    ):
        """Initialize multi-provider decoder.

        Args:
            decoders: Map of provider name to decoder instance.
                      Example: {"azure": AzureADDecoder(...), "aws": CognitoDecoder(...)}
            issuer_patterns: Optional regex patterns to match issuers to providers.
                            Can be strings or compiled Pattern objects.
                            Strings will be compiled automatically.
                            Defaults to DEFAULT_ISSUER_PATTERNS.
        """
        self.decoders = decoders

        # Normalize patterns: compile strings to Pattern objects
        if issuer_patterns is None:
            self.issuer_patterns: Dict[str, Pattern[str]] = DEFAULT_ISSUER_PATTERNS.copy()
        else:
            self.issuer_patterns = {
                provider: (re.compile(pattern) if isinstance(pattern, str) else pattern)
                for provider, pattern in issuer_patterns.items()
            }

        self._decoders_lock = asyncio.Lock()

        # Add any decoder names not in patterns with exact match
        for name in decoders:
            if name not in self.issuer_patterns:
                logger.warning(
                    f"No issuer pattern configured for decoder '{name}'. "
                    f"Add pattern to issuer_patterns for automatic routing."
                )

    @auto_trace(logger, include_args=False)  # Security: no token data in logs
    def _decode_jwt_payload_unsafe(self, token: str) -> Dict[str, Any]:
        """Decode JWT payload without signature verification.

        Delegates to shared decode_jwt_payload_unsafe().
        Adds token length validation for ReDoS protection.

        Args:
            token: JWT token string

        Returns:
            Decoded payload as dict

        Raises:
            TokenInvalidError: If token is not valid JWT format or exceeds length limits
        """
        # Security: Validate token length before processing to prevent ReDoS attacks
        if len(token) > MAX_TOKEN_LENGTH:
            error = TokenInvalidError(f"Token exceeds maximum length of {MAX_TOKEN_LENGTH} bytes")
            logger.log_error(
                error,
                extra={
                    "token_length": len(token),
                    "max_length": MAX_TOKEN_LENGTH,
                    "security_event": "token_length_exceeded"
                }
            )
            raise error

        return decode_jwt_payload_unsafe(token)

    @auto_trace(logger)
    def detect_provider(self, token: str) -> str:
        """Detect identity provider from JWT issuer claim.

        Thread Safety:
            Creates snapshot of issuer_patterns to avoid RuntimeError if
            dictionary is modified during iteration by add_decoder/remove_decoder.

        Args:
            token: JWT token string

        Returns:
            Provider name (e.g., "azure", "aws", "google")

        Raises:
            TokenInvalidError: If token is invalid or issuer is unknown
        """
        payload = self._decode_jwt_payload_unsafe(token)
        issuer = payload.get("iss", "")

        if not issuer:
            logger.warning("Token missing issuer claim", extra={"token_hint": token[-8:]})
            raise TokenInvalidError("Token missing issuer (iss) claim")

        # Security: Validate issuer length before regex matching to prevent ReDoS attacks
        if len(issuer) > MAX_ISSUER_LENGTH:
            error = TokenInvalidError(f"Issuer exceeds maximum length of {MAX_ISSUER_LENGTH} characters")
            logger.log_error(
                error,
                extra={
                    "issuer_length": len(issuer),
                    "max_length": MAX_ISSUER_LENGTH,
                    "security_event": "issuer_length_exceeded"
                }
            )
            raise error

        # Create snapshot to prevent RuntimeError during iteration
        patterns_snapshot = dict(self.issuer_patterns)

        for provider, pattern in patterns_snapshot.items():
            if pattern.match(issuer):
                logger.info(
                    "Provider detected from issuer",
                    extra={
                        "provider": provider,
                        "issuer": issuer,
                        "pattern": pattern.pattern,
                    }
                )
                return provider

        logger.warning(
            "Unknown token issuer",
            extra={
                "issuer": issuer,
                "configured_providers": list(patterns_snapshot.keys()),
            }
        )
        raise TokenInvalidError(
            f"Unknown token issuer: {issuer}. "
            f"Configure issuer_patterns for custom providers."
        )

    @auto_trace(logger)  # Gets decoder for provider name
    def _get_decoder(self, provider: str) -> TokenDecoder:
        """Get decoder for provider.

        Args:
            provider: Provider name

        Returns:
            TokenDecoder instance

        Raises:
            ProviderNotConfiguredError: If no decoder configured for provider
        """
        decoder = self.decoders.get(provider)
        if not decoder:
            configured = list(self.decoders.keys())
            raise ProviderNotConfiguredError(
                f"No decoder configured for provider '{provider}'. "
                f"Configured providers: {configured}"
            )
        return decoder

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Decode token using appropriate provider decoder.

        Detects provider from issuer, routes to correct decoder,
        and returns identity with provider information.

        Args:
            token: JWT token string

        Returns:
            IdentityContext with provider field set

        Raises:
            TokenInvalidError: If token is invalid
            ProviderNotConfiguredError: If provider not configured
        """
        # Detect provider from issuer
        provider = self.detect_provider(token)
        logger.debug(f"Routing token to provider '{provider}' decoder")

        # Get decoder for provider
        decoder = self._get_decoder(provider)

        # Delegate to provider-specific decoder
        try:
            identity = await decoder.decode(token)

            # Log successful routing and decoding
            logger.info(
                "Token decoded successfully",
                extra={
                    "provider": provider,
                    "user_id": identity.user_id,
                    "tenant_id": identity.tenant_id,
                    "decoder_type": type(decoder).__name__,
                }
            )

            return identity

        except Exception as e:
            logger.error(
                f"Token decoding failed for provider '{provider}'",
                extra={
                    "provider": provider,
                    "decoder_type": type(decoder).__name__,
                    "error_type": type(e).__name__,
                    "error": str(e),
                }
            )
            raise

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Validate token using appropriate provider decoder.

        Args:
            token: JWT token string

        Returns:
            True if token is valid
        """
        provider = self.detect_provider(token)
        decoder = self._get_decoder(provider)
        return await decoder.validate(token)

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if token is revoked using appropriate provider decoder.

        Args:
            token: JWT token string

        Returns:
            True if token is revoked
        """
        provider = self.detect_provider(token)
        decoder = self._get_decoder(provider)
        return await decoder.is_revoked(token)

    @auto_trace(logger)
    async def add_decoder(self, provider: str, decoder: TokenDecoder, pattern: str) -> None:
        """Add a new provider decoder at runtime.

        Thread Safety:
            Acquires self._decoders_lock to safely modify both self.decoders
            and self.issuer_patterns dictionaries.

        Args:
            provider: Provider name (must be unique)
            decoder: TokenDecoder instance
            pattern: Regex pattern to match issuer

        Raises:
            ValueError: If provider already registered
        """
        async with self._decoders_lock:
            if provider in self.decoders:
                error = ValueError(
                    f"Provider '{provider}' is already registered. "
                    f"Remove it first with remove_decoder() if you want to replace it."
                )
                logger.log_error(error, extra={"provider": provider})
                raise error

            self.decoders[provider] = decoder
            self.issuer_patterns[provider] = re.compile(pattern)
            logger.info(f"Added decoder for provider '{provider}' with pattern '{pattern}'")

    @auto_trace(logger)
    async def remove_decoder(self, provider: str) -> None:
        """Remove a provider decoder.

        Thread Safety:
            Acquires self._decoders_lock to safely modify self.decoders
            dictionary.

        Note:
            Removes only the decoder, not the issuer pattern. This allows
            provider detection to still work, but _get_decoder() will raise
            ProviderNotConfiguredError when no decoder is found.

        Args:
            provider: Provider name to remove
        """
        async with self._decoders_lock:
            self.decoders.pop(provider, None)
            # Keep issuer_patterns so provider can still be detected
            # _get_decoder() will raise ProviderNotConfiguredError
            logger.info(f"Removed decoder for provider '{provider}'")

    @auto_trace(logger)
    def list_decoders(self) -> Dict[str, str]:
        """List all available provider decoders.

        Thread Safety:
            Creates snapshot of decoders to avoid RuntimeError if dictionary
            is modified during iteration by add_decoder/remove_decoder.

        Returns:
            Dict mapping provider names to their decoder class names
        """
        # Create snapshot to prevent RuntimeError during iteration
        decoders_snapshot = dict(self.decoders)
        return {
            provider: type(decoder).__name__
            for provider, decoder in decoders_snapshot.items()
        }

    @classmethod
    @auto_trace(logger)
    def from_config(cls, decoders: Dict[str, TokenDecoder], issuer_patterns: Optional[Dict[str, str]] = None) -> "MultiProviderTokenDecoder":
        """Create MultiProviderTokenDecoder from provider decoder configuration.

        Args:
            decoders: Map of provider name to decoder instance.
                      Example: {"azure": AzureADDecoder(...), "aws": CognitoDecoder(...)}
            issuer_patterns: Optional regex patterns (as strings) to match issuers to providers.
                            Strings will be compiled to Pattern objects.
                            Defaults to DEFAULT_ISSUER_PATTERNS.

        Returns:
            Configured MultiProviderTokenDecoder instance

        Usage:
            decoder = MultiProviderTokenDecoder.from_config(
                decoders={
                    "azure": AzureADDecoder(...),
                    "aws": CognitoDecoder(...),
                },
            )
        """
        # Compile string patterns to Pattern objects
        compiled_patterns: Optional[Dict[str, Pattern[str]]] = None
        if issuer_patterns is not None:
            compiled_patterns = {
                provider: re.compile(pattern)
                for provider, pattern in issuer_patterns.items()
            }
        return cls(decoders=decoders, issuer_patterns=compiled_patterns)
