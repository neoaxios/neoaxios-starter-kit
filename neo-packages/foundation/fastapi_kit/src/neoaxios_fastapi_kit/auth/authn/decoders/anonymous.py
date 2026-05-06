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

"""Anonymous decoder for DISABLED auth mode.

Returns a fixed anonymous identity with wildcard permissions for
development and testing environments. Tenant ID is hardcoded to
prevent header spoofing attacks.
"""

from __future__ import annotations

from neoaxios_logging import auto_trace, get_telemetry

from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.context import IdentityContext

logger = get_telemetry(__name__)


class AnonymousDecoder(BaseDecoder):
    """Decoder for disabled auth mode - returns anonymous identity.

    Always returns a fixed anonymous identity with wildcard permissions.
    Used when auth mode is 'disabled' for development/testing.

    Security: Tenant ID is fixed ('dev-tenant'), not from headers.
    Headers can be spoofed, and tenant isolation is a security boundary.
    """

    @auto_trace(logger)
    async def decode(self, token: str | None = None) -> IdentityContext:
        """Return anonymous identity regardless of token.

        Args:
            token: Ignored - anonymous identity always returned.

        Returns:
            Anonymous IdentityContext with wildcard permissions.
        """
        return IdentityContext(
            user_id="anonymous",
            tenant_id="dev-tenant",
            roles=frozenset(["anonymous"]),
            permissions=frozenset(["*"]),
            provider="anonymous",
        )

    @auto_trace(logger)
    async def validate(self, token: str) -> bool:
        """Always returns True for anonymous mode."""
        return True

    @auto_trace(logger)
    async def is_revoked(self, token: str) -> bool:
        """Always returns False for anonymous mode."""
        return False
