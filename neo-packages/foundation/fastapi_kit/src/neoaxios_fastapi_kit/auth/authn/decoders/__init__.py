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

"""Token decoders for JWT validation.

Provides base decoder infrastructure and multi-provider routing.
Provider-specific decoders (Azure, AWS, Google) can be added as needed.

Usage:
    from neoaxios_fastapi_kit.auth.authn.decoders import MultiProviderTokenDecoder, BaseDecoder
    from neoaxios_fastapi_kit.auth.authn.decoders import create_jwt_decoder, create_oidc_decoder
    from neoaxios_fastapi_kit.auth.authn.decoders import DevJWTDecoder, create_dev_jwt_decoder
    from neoaxios_fastapi_kit.auth.authn.decoders import AnonymousDecoder
    from neoaxios_fastapi_kit.auth.authn.decoders import JWKSCache, create_jwks_cache
"""

from neoaxios_fastapi_kit.auth.authn.decoders.anonymous import AnonymousDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.base import BaseDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.bearer import BearerTokenDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.jwt import JWTDecoder, create_jwt_decoder
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder, create_oidc_decoder
from neoaxios_fastapi_kit.auth.authn.decoders.dev_jwt import (
    DevJWTDecoder,
    create_dev_jwt_decoder,
)
# ALLOWED_DEV_ENVIRONMENTS canonical source is auth.config
from neoaxios_fastapi_kit.auth.config import ALLOWED_DEV_ENVIRONMENTS
from neoaxios_fastapi_kit.auth.authn.decoders.multi_provider import (
    MultiProviderTokenDecoder,
    DEFAULT_ISSUER_PATTERNS,
    TokenDecoder,
)
from neoaxios_fastapi_kit.auth.authn.decoders.oidc_cache import (
    JWKSCache,
    JWKSEntry,
    create_jwks_cache,
)
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenInvalidError,
    ProviderNotConfiguredError,
    SecurityError,
)

__all__ = [
    "AnonymousDecoder",
    "BaseDecoder",
    "BearerTokenDecoder",
    "JWTDecoder",
    "create_jwt_decoder",
    "OIDCDecoder",
    "create_oidc_decoder",
    "DevJWTDecoder",
    "create_dev_jwt_decoder",
    "ALLOWED_DEV_ENVIRONMENTS",
    "MultiProviderTokenDecoder",
    "DEFAULT_ISSUER_PATTERNS",
    "TokenDecoder",
    "JWKSCache",
    "JWKSEntry",
    "create_jwks_cache",
    "TokenInvalidError",
    "ProviderNotConfiguredError",
    "SecurityError",
]
