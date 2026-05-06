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

"""Error types for auth framework.

Provides the AuthError base class and re-exports all error types for
backwards compatibility.

Error Hierarchy:
    AuthError (base)
    ├── authn/errors.py - Authentication errors (Token*, Provider*, RateLimit*)
    └── authz/errors.py - Authorization errors (Permission*, Policy*, Tenant*, etc.)

Usage:
    # Import from main auth module (recommended)
    from neoaxios_fastapi_kit.auth import TokenExpiredError, PermissionDeniedError

    # Import from this module (backwards compatible)
    from neoaxios_fastapi_kit.auth.errors import TokenExpiredError, PermissionDeniedError

    # Import from specific modules (explicit)
    from neoaxios_fastapi_kit.auth.authn.errors import TokenExpiredError
    from neoaxios_fastapi_kit.auth.authz.errors import PermissionDeniedError
"""

from typing import TYPE_CHECKING, List, Type, overload

from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)


class AuthError(Exception):
    """Base exception for all auth framework errors.

    All auth errors include status_code and error_code for consistent
    error handling and HTTP responses.

    Attributes:
        status_code: HTTP status code for this error
        error_code: Machine-readable error code
        message: Human-readable error message
    """

    status_code: int = 401
    error_code: str = "AUTH_ERROR"

    def __init__(self, message: str):
        """Initialize auth error with message.

        Args:
            message: Human-readable error description
        """
        super().__init__(message)
        self.message = message


# Type hints for lazy imports (IDE support)
if TYPE_CHECKING:
    from typing import Literal

    from neoaxios_fastapi_kit.auth.authn.errors import (
        TokenInvalidError as _TokenInvalidError,
        TokenExpiredError as _TokenExpiredError,
        TokenRevokedError as _TokenRevokedError,
        ProviderNotConfiguredError as _ProviderNotConfiguredError,
        RateLimitExceededError as _RateLimitExceededError,
        SecurityError as _SecurityError,
    )
    from neoaxios_fastapi_kit.auth.authz.errors import (
        PermissionDeniedError as _PermissionDeniedError,
        PolicyDeniedError as _PolicyDeniedError,
        TenantMismatchError as _TenantMismatchError,
        OwnershipRequiredError as _OwnershipRequiredError,
        ResourceNotFoundError as _ResourceNotFoundError,
        ImpersonationNotAllowedError as _ImpersonationNotAllowedError,
        ValidationError as _ValidationError,
        CacheSecurityError as _CacheSecurityError,
        SignatureVerificationError as _SignatureVerificationError,
        DecryptionError as _DecryptionError,
        ReplayAttackError as _ReplayAttackError,
        CanaryMismatchError as _CanaryMismatchError,
        KeyValidationError as _KeyValidationError,
        TamperDetectionActiveError as _TamperDetectionActiveError,
    )


# Lazy re-exports to avoid circular imports
_AUTHN_ERRORS = frozenset({
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenRevokedError",
    "ProviderNotConfiguredError",
    "RateLimitExceededError",
    "SecurityError",
})

_AUTHZ_ERRORS = frozenset({
    "PermissionDeniedError",
    "PolicyDeniedError",
    "TenantMismatchError",
    "OwnershipRequiredError",
    "ResourceNotFoundError",
    "ImpersonationNotAllowedError",
    "ValidationError",
    "CacheSecurityError",
    "SignatureVerificationError",
    "DecryptionError",
    "ReplayAttackError",
    "CanaryMismatchError",
    "KeyValidationError",
    "TamperDetectionActiveError",
})


# Type stubs for overloaded __getattr__ (IDE autocomplete support)
@overload
def __getattr__(name: "Literal['TokenInvalidError']") -> "Type[_TokenInvalidError]": ...
@overload
def __getattr__(name: "Literal['TokenExpiredError']") -> "Type[_TokenExpiredError]": ...
@overload
def __getattr__(name: "Literal['TokenRevokedError']") -> "Type[_TokenRevokedError]": ...
@overload
def __getattr__(name: "Literal['ProviderNotConfiguredError']") -> "Type[_ProviderNotConfiguredError]": ...
@overload
def __getattr__(name: "Literal['RateLimitExceededError']") -> "Type[_RateLimitExceededError]": ...
@overload
def __getattr__(name: "Literal['SecurityError']") -> "Type[_SecurityError]": ...
@overload
def __getattr__(name: "Literal['PermissionDeniedError']") -> "Type[_PermissionDeniedError]": ...
@overload
def __getattr__(name: "Literal['PolicyDeniedError']") -> "Type[_PolicyDeniedError]": ...
@overload
def __getattr__(name: "Literal['TenantMismatchError']") -> "Type[_TenantMismatchError]": ...
@overload
def __getattr__(name: "Literal['OwnershipRequiredError']") -> "Type[_OwnershipRequiredError]": ...
@overload
def __getattr__(name: "Literal['ResourceNotFoundError']") -> "Type[_ResourceNotFoundError]": ...
@overload
def __getattr__(name: "Literal['ImpersonationNotAllowedError']") -> "Type[_ImpersonationNotAllowedError]": ...
@overload
def __getattr__(name: "Literal['ValidationError']") -> "Type[_ValidationError]": ...
@overload
def __getattr__(name: "Literal['CacheSecurityError']") -> "Type[_CacheSecurityError]": ...
@overload
def __getattr__(name: "Literal['SignatureVerificationError']") -> "Type[_SignatureVerificationError]": ...
@overload
def __getattr__(name: "Literal['DecryptionError']") -> "Type[_DecryptionError]": ...
@overload
def __getattr__(name: "Literal['ReplayAttackError']") -> "Type[_ReplayAttackError]": ...
@overload
def __getattr__(name: "Literal['CanaryMismatchError']") -> "Type[_CanaryMismatchError]": ...
@overload
def __getattr__(name: "Literal['KeyValidationError']") -> "Type[_KeyValidationError]": ...
@overload
def __getattr__(name: "Literal['TamperDetectionActiveError']") -> "Type[_TamperDetectionActiveError]": ...
@overload
def __getattr__(name: str) -> object: ...


def __getattr__(name: str):
    """Lazy import for error types to avoid circular imports."""
    if name in _AUTHN_ERRORS:
        from neoaxios_fastapi_kit.auth.authn import errors as authn_errors
        return getattr(authn_errors, name)

    if name in _AUTHZ_ERRORS:
        from neoaxios_fastapi_kit.auth.authz import errors as authz_errors
        return getattr(authz_errors, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> List[str]:
    """Return list of module attributes for introspection and IDE support."""
    return __all__


__all__ = [  # noqa: F822 — names resolved via __getattr__ lazy imports
    "AuthError",
    # AuthN errors (lazy)
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenRevokedError",
    "ProviderNotConfiguredError",
    "RateLimitExceededError",
    "SecurityError",
    # AuthZ errors (lazy)
    "PermissionDeniedError",
    "PolicyDeniedError",
    "TenantMismatchError",
    "OwnershipRequiredError",
    "ResourceNotFoundError",
    "ImpersonationNotAllowedError",
    "ValidationError",
    "CacheSecurityError",
    "SignatureVerificationError",
    "DecryptionError",
    "ReplayAttackError",
    "CanaryMismatchError",
    "KeyValidationError",
    "TamperDetectionActiveError",
]
