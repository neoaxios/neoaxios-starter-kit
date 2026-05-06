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

"""Authentication error types.

Defines errors related to identity verification and token handling.
All errors inherit from AuthError in the parent auth module.

Usage:
    from neoaxios_fastapi_kit.auth.authn.errors import TokenExpiredError, TokenInvalidError

    raise TokenInvalidError("Token signature verification failed")
"""

from neoaxios_fastapi_kit.auth.errors import AuthError


class TokenInvalidError(AuthError):
    """Token is malformed, has invalid signature, or cannot be decoded.

    Raised when:
    - JWT format is invalid (not 3 parts)
    - Signature verification fails
    - Required claims are missing
    - Token payload cannot be parsed
    """

    status_code: int = 401
    error_code: str = "TOKEN_INVALID"


class TokenExpiredError(AuthError):
    """Token has expired and is no longer valid.

    Raised when the token's exp (expiration) claim is in the past,
    accounting for clock skew tolerance.
    """

    status_code: int = 401
    error_code: str = "TOKEN_EXPIRED"


class TokenRevokedError(AuthError):
    """Token has been explicitly revoked and cannot be used.

    Raised when:
    - Token appears on revocation list
    - Token introspection endpoint indicates revocation
    - User's tokens were invalidated (logout, password change)
    """

    status_code: int = 401
    error_code: str = "TOKEN_REVOKED"


class ProviderNotConfiguredError(AuthError):
    """No decoder configured for the detected identity provider.

    Raised when:
    - Token issuer matches known pattern but no decoder is configured
    - MultiProviderTokenDecoder cannot find decoder for provider
    """

    status_code: int = 401
    error_code: str = "PROVIDER_NOT_CONFIGURED"


class RateLimitExceededError(AuthError):
    """Too many authentication failures from this source.

    Raised when:
    - IP address exceeds auth failure threshold
    - User account is temporarily locked due to failed attempts
    - Token introspection rate limit exceeded
    """

    status_code: int = 429
    error_code: str = "RATE_LIMIT_EXCEEDED"


class SecurityError(AuthError):
    """Security violation detected.

    Raised when:
    - Development authentication is attempted in production environment
    - Security-critical configuration is invalid
    - Environment allowlist check fails
    """

    status_code: int = 403
    error_code: str = "SECURITY_ERROR"
