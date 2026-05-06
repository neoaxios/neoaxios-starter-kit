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

"""Default configuration values for authorization framework.

All defaults are centralized here and overridable by callers via AuthConfig.
Import from this module to ensure consistent defaults across the codebase.

Usage:
    from neoaxios_fastapi_kit.auth.defaults import (
        DEFAULT_CACHE_TTL_SECONDS,
        DEFAULT_PERMISSION_PATTERN,
    )
"""

import re
from typing import FrozenSet

# =============================================================================
# Cache Configuration
# =============================================================================

# TTL for cached permission sets (seconds)
DEFAULT_CACHE_TTL_SECONDS: int = 300

# TTL for negative cache entries (permission denied results)
# Shorter to limit exposure window if permissions change
DEFAULT_CACHE_NEGATIVE_TTL_SECONDS: int = 60


# =============================================================================
# Sensitive Permissions (bypass cache - LOCKED)
# =============================================================================

# Permissions that MUST bypass cache and always resolve from source
# Format: prefix patterns that match via startswith()
DEFAULT_SENSITIVE_PERMISSION_PREFIXES: FrozenSet[str] = frozenset({
    "admin:",      # All admin operations
    "delete:",     # All delete operations
    "sudo:",       # Super-user operations
    "system:",     # System-level operations
    "tenant:",     # Tenant management
    "user:delete", # User deletion specifically
    "role:grant",  # Role assignment
    "role:revoke", # Role removal
})


# =============================================================================
# Token Configuration
# =============================================================================

# HTTP header for bearer token
DEFAULT_TOKEN_HEADER: str = "Authorization"

# Token prefix (e.g., "Bearer ")
DEFAULT_TOKEN_PREFIX: str = "Bearer "

# Token clock skew tolerance (seconds) for expiry checks
DEFAULT_TOKEN_CLOCK_SKEW_SECONDS: int = 30


# =============================================================================
# Validation Patterns
# =============================================================================

# Regex pattern for valid permission strings
# Format: resource:action (e.g., "document:read", "user:delete")
# Pre-compiled for performance and ReDoS protection
DEFAULT_PERMISSION_PATTERN: re.Pattern = re.compile(
    r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$"
)

# Regex pattern for valid role strings
# Pre-compiled for performance and ReDoS protection
DEFAULT_ROLE_PATTERN: re.Pattern = re.compile(r"^[a-z][a-z0-9_]*$")

# UUID v4 pattern for user_id and tenant_id validation
# Pre-compiled for performance and ReDoS protection
DEFAULT_UUID_PATTERN: re.Pattern = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Path traversal patterns to block
DEFAULT_PATH_TRAVERSAL_PATTERNS: FrozenSet[str] = frozenset({
    "..",
    "../",
    "..\\",
    "%2e%2e",
    "%2e%2e/",
    "%2e%2e%2f",
    "%252e%252e",
})


# =============================================================================
# Behavior Flags
# =============================================================================

# Require tenant isolation by default
DEFAULT_REQUIRE_TENANT_ISOLATION: bool = True

# Audit all access decisions (verbose logging)
DEFAULT_AUDIT_ALL_ACCESS: bool = False

# Allow admin impersonation
DEFAULT_ALLOW_IMPERSONATION: bool = False

# Roles allowed to impersonate other users
DEFAULT_IMPERSONATION_ROLES: FrozenSet[str] = frozenset({"admin", "support"})

# =============================================================================
# Rate Limiting (for auth failure tracking)
# =============================================================================

# Max auth failures before blocking (per IP)
DEFAULT_AUTH_FAILURE_THRESHOLD: int = 10

# Window for counting auth failures (seconds)
DEFAULT_AUTH_FAILURE_WINDOW_SECONDS: int = 300

# Block duration after exceeding threshold (seconds)
DEFAULT_AUTH_BLOCK_DURATION_SECONDS: int = 900


# =============================================================================
# ABAC Policy Defaults
# =============================================================================

# Default policy effect when no policies match
DEFAULT_POLICY_EFFECT_ON_NO_MATCH: str = "deny"

# Maximum policies to evaluate per request (prevent DoS)
DEFAULT_MAX_POLICIES_PER_REQUEST: int = 100


# =============================================================================
# HTTP Response Defaults
# =============================================================================

# Status codes for auth errors
DEFAULT_STATUS_UNAUTHORIZED: int = 401
DEFAULT_STATUS_FORBIDDEN: int = 403
DEFAULT_STATUS_NOT_FOUND: int = 404
DEFAULT_STATUS_RATE_LIMITED: int = 429

# Error response format
DEFAULT_ERROR_CODE_UNAUTHORIZED: str = "UNAUTHORIZED"
DEFAULT_ERROR_CODE_FORBIDDEN: str = "FORBIDDEN"
DEFAULT_ERROR_CODE_PERMISSION_DENIED: str = "PERMISSION_DENIED"
DEFAULT_ERROR_CODE_TENANT_MISMATCH: str = "TENANT_MISMATCH"
DEFAULT_ERROR_CODE_OWNERSHIP_REQUIRED: str = "OWNERSHIP_REQUIRED"
DEFAULT_ERROR_CODE_RATE_LIMITED: str = "RATE_LIMITED"


# =============================================================================
# Merge Strategy Defaults
# =============================================================================

# Default merge strategy for federated resolvers
DEFAULT_MERGE_STRATEGY: str = "union"  # "union" | "intersection" | "local" | "enterprise"
