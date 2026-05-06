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

"""Authentication (AuthN) module - "Who are you?"

Provides token decoding, identity verification, and authentication infrastructure.

Components:
    - decoders/: Token decoder implementations (JWT, OIDC, multi-provider)
    - clients/: External API clients (Microsoft Graph API, etc.)
    - errors.py: Authentication-specific error types

Usage:
    from neoaxios_fastapi_kit.auth.authn import (
        BaseDecoder,
        JWTDecoder,
        MultiProviderTokenDecoder,
        TokenExpiredError,
        TokenInvalidError,
    )

    # Graph API client for Azure AD token introspection
    from neoaxios_fastapi_kit.auth.authn.clients import GraphAPIClient, create_graph_api_client
"""

# Token Decoders
from neoaxios_fastapi_kit.auth.authn.decoders import (
    BaseDecoder,
    JWTDecoder,
    MultiProviderTokenDecoder,
    DEFAULT_ISSUER_PATTERNS,
    TokenDecoder,
    ProviderNotConfiguredError as DecoderProviderNotConfiguredError,
    TokenInvalidError as DecoderTokenInvalidError,
)

# Authentication Errors
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    TokenExpiredError,
    TokenRevokedError,
    ProviderNotConfiguredError,
    RateLimitExceededError,
)

# External API Clients
from neoaxios_fastapi_kit.auth.authn.clients import (
    GraphAPIClient,
    create_graph_api_client,
)

__all__ = [
    # Decoders
    "BaseDecoder",
    "JWTDecoder",
    "MultiProviderTokenDecoder",
    "DEFAULT_ISSUER_PATTERNS",
    "TokenDecoder",
    # Clients
    "GraphAPIClient",
    "create_graph_api_client",
    # Decoder aliases
    "DecoderProviderNotConfiguredError",
    "DecoderTokenInvalidError",
    # Errors
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenRevokedError",
    "ProviderNotConfiguredError",
    "RateLimitExceededError",
]
