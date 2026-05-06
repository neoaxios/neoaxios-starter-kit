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

"""Authorization error types.

Defines errors related to access control, permissions, and policies.
All errors inherit from AuthError in the parent auth module.

Usage:
    from neoaxios_fastapi_kit.auth.authz.errors import PermissionDeniedError

    raise PermissionDeniedError("User lacks required permission: document:write")
"""

from neoaxios_fastapi_kit.auth.errors import AuthError


class PermissionDeniedError(AuthError):
    """User lacks the required permission for this operation.

    Raised when require_permission() dependency check fails.
    Status 403 indicates authentication succeeded but authorization failed.
    """

    status_code: int = 403
    error_code: str = "PERMISSION_DENIED"


class PolicyDeniedError(AuthError):
    """ABAC policy evaluation denied access to this operation.

    Raised when require_policy() dependency check fails due to
    attribute-based access control policy conditions not being met.
    """

    status_code: int = 403
    error_code: str = "POLICY_DENIED"


class TenantMismatchError(AuthError):
    """Resource belongs to a different tenant than the requesting user.

    Raised when require_tenant_access() detects cross-tenant access attempt.
    Returns 404 (not 403) to prevent resource enumeration (OWASP API1:2023, ASVS V4.2.1, CWE-204).

    Attributes:
        identity_tenant: Tenant ID from the authenticated identity
        resource_tenant: Tenant ID of the resource being accessed
    """

    status_code: int = 404
    error_code: str = "TENANT_MISMATCH"

    def __init__(
        self,
        identity_tenant: str,
        resource_tenant: str,
        message: str | None = None
    ):
        """Initialize TenantMismatchError.

        Args:
            identity_tenant: Tenant ID from identity context
            resource_tenant: Tenant ID of the resource
            message: Optional custom error message. If not provided,
                    generates default message from tenant IDs
        """
        self.identity_tenant = identity_tenant
        self.resource_tenant = resource_tenant

        if message is None:
            message = (
                f"Tenant mismatch: identity tenant '{identity_tenant}' "
                f"cannot access resource in tenant '{resource_tenant}'"
            )

        super().__init__(message)


class OwnershipRequiredError(AuthError):
    """User does not own the resource and ownership is required.

    Raised when require_ownership() dependency check fails.
    User is authenticated but is not the resource owner.
    """

    status_code: int = 403
    error_code: str = "OWNERSHIP_REQUIRED"


class ResourceNotFoundError(AuthError):
    """Requested resource does not exist.

    Raised when ownership or tenant resolver cannot find the resource.
    Status 404 indicates resource does not exist (or user cannot see it).
    """

    status_code: int = 404
    error_code: str = "RESOURCE_NOT_FOUND"


class ImpersonationNotAllowedError(AuthError):
    """User is not permitted to impersonate other users.

    Raised when:
    - User attempts impersonation without required role
    - Impersonation is disabled in config
    - Target user cannot be impersonated
    """

    status_code: int = 403
    error_code: str = "IMPERSONATION_NOT_ALLOWED"


class ValidationError(AuthError):
    """Input validation failed for authorization parameter.

    Raised when:
    - UUID format is invalid
    - Permission format is invalid
    - Role format is invalid
    - Path traversal attempt detected
    """

    status_code: int = 400
    error_code: str = "VALIDATION_ERROR"


# =============================================================================
# Cache Security Errors (for SecureCacheBackend)
# =============================================================================


class CacheSecurityError(AuthError):
    """Base exception for cache security violations.

    Raised when cryptographic verification or security checks fail
    on cached data. All cache security errors should be treated as
    potential attack indicators and logged accordingly.
    """

    status_code: int = 500
    error_code: str = "CACHE_SECURITY_ERROR"


class SignatureVerificationError(CacheSecurityError):
    """HMAC signature verification failed on cached value.

    Indicates potential cache poisoning attack. The cached value
    has been tampered with or was created with a different signing key.

    Security Response:
    - Log as security event with full context
    - Return None (cache miss) to caller
    - Increment cache.signature.invalid metric
    - Consider entering fallback mode if frequent
    """

    error_code: str = "SIGNATURE_VERIFICATION_FAILED"


class DecryptionError(CacheSecurityError):
    """AES-GCM decryption failed on cached value.

    Indicates either:
    - Cache value encrypted with different tenant key
    - Cache value corrupted or tampered
    - Cross-tenant access attempt

    Security Response:
    - Log as security event
    - Return None (cache miss) to caller
    - Increment cache.decryption.failed metric
    """

    error_code: str = "DECRYPTION_FAILED"


class ReplayAttackError(CacheSecurityError):
    """Sequence number validation failed - potential replay attack.

    Raised when a cache value has a sequence number less than or equal
    to the last-seen sequence for this user. This indicates an attacker
    may be attempting to replay an older cache value.

    Security Response:
    - Log as HIGH severity security event
    - Return None (cache miss) to caller
    - Increment cache.replay.detected metric
    - Alert security team if frequent
    """

    error_code: str = "REPLAY_ATTACK_DETECTED"


class CanaryMismatchError(CacheSecurityError):
    """Canary integrity check failed - cache may be compromised.

    Raised when the canary value stored in Redis does not match
    the expected HMAC. This indicates potential Redis compromise
    or unauthorized cache modification.

    Security Response:
    - Enter fallback mode immediately
    - Log as CRITICAL security event
    - Alert on-call security team
    - Set cache.canary.mismatch metric to 1
    """

    error_code: str = "CANARY_MISMATCH"


class KeyValidationError(CacheSecurityError):
    """Master key validation failed.

    Raised during SecureCacheBackend initialization when:
    - Master key length != 32 bytes
    - Master key has insufficient entropy
    - Master key is all zeros or predictable pattern

    Security Response:
    - Refuse to start application
    - Log configuration error
    - Do NOT log the key material
    """

    status_code: int = 500
    error_code: str = "KEY_VALIDATION_FAILED"


class TamperDetectionActiveError(CacheSecurityError):
    """Cache integrity violation is active due to canary tampering detection.

    Raised when cache operations are attempted while tamper detection is active.
    Not typically raised to callers - used internally to signal
    that a cache integrity violation has been detected.
    """

    status_code: int = 503
    error_code: str = "CACHE_TAMPER_DETECTION_ACTIVE"
