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

"""Bearer token decoder for API key authentication.

Validates bearer tokens against a configured list of API keys using
timing-safe comparison (hmac.compare_digest). Designed for service-to-service
authentication where tokens are pre-shared secrets rather than JWTs.

When api_keys is empty, any token is accepted (open access mode for local
development); an empty key list disables authentication.
"""

from __future__ import annotations

import hmac

from pydantic import SecretStr

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError
from neoaxios_fastapi_kit.auth.context import IdentityContext

logger = get_telemetry(__name__)


class BearerTokenDecoder(BaseDecoder):
    """Decoder for bearer token (API key) authentication.

    Validates raw bearer tokens against a list of pre-shared API keys using
    hmac.compare_digest for timing-safe comparison. Unlike JWT decoders, this
    decoder treats the entire token as an opaque secret -- no structure parsing,
    no claims extraction, no signature verification.

    When api_keys is empty, open access mode is activated: any token (including
    empty or missing) is accepted. This supports local development scenarios
    where authentication is not required.

    Args:
        api_keys: List of valid API keys wrapped in SecretStr. Empty list
            enables open access mode.

    Usage:
        from pydantic import SecretStr
        from neoaxios_fastapi_kit.auth.authn.decoders.bearer import BearerTokenDecoder

        # Production: validate against configured keys
        decoder = BearerTokenDecoder(api_keys=[SecretStr("my-secret-key")])
        identity = await decoder.decode("my-secret-key")

        # Development: open access (empty key list)
        decoder = BearerTokenDecoder(api_keys=[])
        identity = await decoder.decode("")  # accepted
    """

    def __init__(self, api_keys: list[SecretStr]) -> None:
        """Initialize with list of valid API keys.

        Args:
            api_keys: List of SecretStr-wrapped API keys. Empty list
                enables open access mode where any token is accepted.
        """
        self._api_keys = api_keys

    @auto_trace(logger)
    async def decode(self, token: str) -> IdentityContext:
        """Validate bearer token and return identity context.

        Extracts the raw token string and compares it against each configured
        API key using hmac.compare_digest for timing-safe comparison. All keys
        are checked even after a match to prevent timing side-channels that
        could reveal which key position matched.

        When api_keys is empty (open access mode), returns identity immediately
        without validation.

        Args:
            token: Raw bearer token string (without "Bearer " prefix).

        Returns:
            IdentityContext with user_id="bearer", tenant_id="default",
            provider="bearer".

        Raises:
            TokenInvalidError: When token is None/empty (in authenticated mode)
                or does not match any configured key.
        """
        if not self._api_keys:
            logger.info("open_access_mode", detail="No API keys configured, accepting token")
            return self._build_identity()

        if not token:
            error = TokenInvalidError("Missing bearer token")
            logger.log_error(error)
            raise error

        matched = False
        for key in self._api_keys:
            if hmac.compare_digest(key.get_secret_value(), token):
                matched = True

        if not matched:
            error = TokenInvalidError("Invalid bearer token")
            logger.log_error(error)
            raise error

        logger.info("bearer_token_validated", key_count=len(self._api_keys))
        return self._build_identity()

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Check if bearer token is valid without raising exceptions.

        Args:
            token: Raw bearer token string.

        Returns:
            True if token matches a configured key or open access is enabled.
        """
        try:
            await self.decode(token)
            return True
        except TokenInvalidError:
            return False

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Check if bearer token has been revoked.

        Bearer tokens are pre-shared secrets with no revocation mechanism.
        Revocation is handled by removing the key from the configured list.

        Args:
            token: Raw bearer token string.

        Returns:
            Always False -- bearer tokens have no revocation list.
        """
        return False

    @auto_trace(logger)
    def _build_identity(self) -> IdentityContext:
        """Build the standard bearer token identity context.

        Returns:
            IdentityContext with bearer-specific defaults.
        """
        return IdentityContext(
            user_id="bearer",
            tenant_id="default",
            roles=frozenset(["service"]),
            permissions=frozenset(["*"]),
            provider="bearer",
        )
