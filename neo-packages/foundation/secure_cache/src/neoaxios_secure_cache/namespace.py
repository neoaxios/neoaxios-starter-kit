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

"""Cache namespace for hierarchical key prefixing.

This module provides `CacheNamespace`, a domain-agnostic primitive for encoding
organizational hierarchy into cache key prefixes with tiered scope methods.
Key builders in domain-specific modules (e.g., neoaxios_fastapi_kit.auth.cache_keys)
consume scope tiers to produce fully-qualified keys.

Key Format (tiered scopes):
    org:{org}[:div:{division}]:env:{env}:svc:{service}:app:{app}:{version}[:d:{domain}][:t:{tenant}[:u:{user}]]

Scope Tier Hierarchy:
    | Tier    | Method         | Format                                             |
    |---------|----------------|-----------------------------------------------------|
    | org     | org_scope()    | org:{org}                                           |
    | div     | div_scope()    | org:{org}:div:{division} (when division set)        |
    | env     | env_scope()    | {div_or_org}:env:{env}                              |
    | svc     | svc_scope()    | {env_scope}:svc:{service}                           |
    | base    | base()         | {svc_scope}:app:{app}:{version}                     |
    | domain  | domain_scope() | {base}:d:{domain} (when domain set, else base())    |
    | tenant  | tenant(t)      | {domain_scope}:t:{tenant_id}                        |
    | user    | user(t, u)     | {tenant}:u:{user_id}                                |

Every scope method produces a valid prefix for invalidate_by_prefix():
    - ns.org_scope() + ":" → invalidate entire org
    - ns.svc_scope() + ":" → invalidate entire service
    - ns.domain_scope() + ":" → invalidate entire domain
    - ns.tenant(t) + ":" → invalidate everything for a tenant
    - ns.user(t, u) + ":" → invalidate everything for a user

Utility Methods:
    - ns.make_key(suffix) → full key: {domain_scope}:{suffix}
    - ns.owns_key(key) → True if key belongs to this namespace
    - ns.cleanup_pattern() → SCAN pattern: {domain_scope}:*

Usage:
    from neoaxios_secure_cache.namespace import CacheNamespace

    ns = CacheNamespace(
        org="neo",
        env="prod",
        service="auth-api",
        app="gateway",
    )

    # Produces: "org:neo:env:prod:svc:auth-api:app:gateway:v1"
    prefix = ns.base()

    # Tenant-scoped: "org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123"
    t_prefix = ns.tenant("tenant123")

    # User-scoped: "...v1:t:tenant123:u:user456"
    u_prefix = ns.user("tenant123", "user456")

    # Domain-scoped (e.g., ratelimit):
    ns_rl = CacheNamespace(
        org="neo", env="prod", service="api", app="checkout", domain="ratelimit",
    )
    # Produces: "org:neo:env:prod:svc:api:app:checkout:v1:d:ratelimit"
    rl_prefix = ns_rl.domain_scope()

    # Make a full key: "org:neo:env:prod:svc:api:app:checkout:v1:d:ratelimit:user:123"
    key = ns_rl.make_key("user:123")
"""

import enum
from dataclasses import dataclass

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

logger = get_telemetry(__name__)

# Characters that could enable key injection or break colon-delimited format
_FORBIDDEN_CHARS = frozenset(":*?[]\\")

# Suffix-only forbidden chars: glob characters that interfere with SCAN patterns.
# Colons are allowed in suffixes (used as segment delimiters).
_SUFFIX_FORBIDDEN_CHARS = frozenset("*?[]\\")


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def _validate_field(field_name: str, value: str) -> None:
    """Validate a namespace field value.

    Args:
        field_name: Name of the field for error messages
        value: Field value to validate

    Raises:
        ValueError: If value is empty, contains control characters,
                    or contains forbidden characters
    """
    if not value:
        raise ValueError(f"CacheNamespace.{field_name} cannot be empty")

    # Check for control characters (ASCII 0-31)
    if any(ord(c) < 32 for c in value):
        raise ValueError(
            f"CacheNamespace.{field_name} cannot contain control characters"
        )

    # Check for forbidden characters that could enable injection
    if any(c in _FORBIDDEN_CHARS for c in value):
        raise ValueError(
            f"CacheNamespace.{field_name} cannot contain characters: "
            f"{sorted(c for c in value if c in _FORBIDDEN_CHARS)}"
        )


@auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
def _validate_suffix(suffix: str) -> None:
    """Validate a key suffix for use with make_key() and make_key_at().

    Colons are allowed (used as segment delimiters). Glob characters
    (*?[]\\) and control characters are rejected.

    Args:
        suffix: Key suffix to validate

    Raises:
        ValueError: If suffix is empty, contains glob characters,
                    or contains control characters
    """
    if not suffix:
        raise ValueError("suffix must be non-empty")

    if any(ord(c) < 32 for c in suffix):
        raise ValueError("suffix: control characters not allowed")

    if any(c in _SUFFIX_FORBIDDEN_CHARS for c in suffix):
        raise ValueError(
            f"suffix: forbidden characters {sorted(c for c in suffix if c in _SUFFIX_FORBIDDEN_CHARS)}"
        )


class KeyTier(str, enum.Enum):
    """Scope tiers for make_key_at().

    Each member maps to a CacheNamespace scope method that produces
    the prefix at that tier level.

    Members:
        ORG: org_scope() — org:{org}
        DIV: div_scope() — org:{org}[:div:{division}]
        ENV: env_scope() — {div_scope}:env:{env}
        SVC: svc_scope() — {env_scope}:svc:{service}
        BASE: base() — {svc_scope}:app:{app}:{version}
        DOMAIN: domain_scope() — {base}[:d:{domain}]
    """

    ORG = "org"
    DIV = "div"
    ENV = "env"
    SVC = "svc"
    BASE = "base"
    DOMAIN = "domain"


@dataclass(frozen=True)
class CacheNamespace:
    """Immutable namespace container for hierarchical cache key prefixes.

    Encodes organizational hierarchy and provides tiered scope methods that
    produce deterministic prefixes at every level. Key builders in domain-specific
    modules accept a namespace and use scope tiers to produce fully-qualified keys.

    This is a domain-agnostic primitive. Auth-specific key shapes (permissions,
    JWKS, roles, tokens) belong in `neoaxios_fastapi_kit.auth.cache_keys`.

    Attributes:
        org: Organization identifier (e.g., "neo", "acme")
        env: Environment (e.g., "prod", "staging", "dev")
        service: Service name (e.g., "auth-api", "billing")
        app: Application/deployment unit (e.g., "gateway", "worker")
        version: Namespace version for key format migration (default: "v1")
        division: Optional division within org (e.g., "apps", "billing").
                  Omitted from prefix when empty.
        domain: Optional domain within an app (e.g., "ratelimit", "cache").
                Subdivides the app's key space. Omitted from prefix when empty.
                Tenant/user tiers chain through domain_scope().

    Example:
        >>> ns = CacheNamespace(
        ...     org="neo",
        ...     env="prod",
        ...     service="auth-api",
        ...     app="gateway",
        ... )
        >>> ns.base()
        'org:neo:env:prod:svc:auth-api:app:gateway:v1'
        >>> ns.tenant("t123")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:t123'
        >>> ns.user("t123", "u456")
        'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:t123:u:u456'

    Multi-Organization Shared Redis:
        When multiple organizations share a Redis cluster:
        - Each organization configures a unique `org` value
        - Keys are completely isolated: `org:neo:...` never collides with `org:globex:...`
        - SCAN operations with prefix `org:{org}:*` affect only that organization's keys
    """

    org: str
    env: str
    service: str
    app: str
    version: str = "v1"
    division: str = ""
    domain: str = ""

    def __post_init__(self) -> None:
        """Validate all fields on construction."""
        _validate_field("org", self.org)
        _validate_field("env", self.env)
        _validate_field("service", self.service)
        _validate_field("app", self.app)
        _validate_field("version", self.version)
        if self.division:
            _validate_field("division", self.division)
        if self.domain:
            _validate_field("domain", self.domain)

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def org_scope(self) -> str:
        """Generate the organization-level prefix.

        Returns:
            Prefix: `org:{org}`

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway")
            >>> ns.org_scope()
            'org:neo'
        """
        return f"org:{self.org}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def div_scope(self) -> str:
        """Generate the division-level prefix.

        When division is set, includes the division segment. Otherwise
        returns org_scope().

        Returns:
            Prefix: `org:{org}:div:{division}` or `org:{org}`

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway", division="apps")
            >>> ns.div_scope()
            'org:neo:div:apps'
        """
        if self.division:
            return f"{self.org_scope()}:div:{self.division}"
        return self.org_scope()

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def env_scope(self) -> str:
        """Generate the environment-level prefix.

        Returns:
            Prefix: `{div_scope}:env:{env}`

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway")
            >>> ns.env_scope()
            'org:neo:env:prod'
        """
        return f"{self.div_scope()}:env:{self.env}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def svc_scope(self) -> str:
        """Generate the service-level prefix.

        Returns:
            Prefix: `{env_scope}:svc:{service}`

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway")
            >>> ns.svc_scope()
            'org:neo:env:prod:svc:auth-api'
        """
        return f"{self.env_scope()}:svc:{self.service}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def base(self) -> str:
        """Generate the base prefix for cache keys (app-level scope).

        Returns:
            Deterministic prefix in format:
            `{svc_scope}:app:{app}:{version}`

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway", "v1")
            >>> ns.base()
            'org:neo:env:prod:svc:auth-api:app:gateway:v1'
        """
        return f"{self.svc_scope()}:app:{self.app}:{self.version}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def domain_scope(self) -> str:
        """Generate the domain-level prefix.

        When domain is set, includes the domain segment. Otherwise
        returns base().

        Returns:
            Prefix: `{base}:d:{domain}` or `{base}` when domain is empty

        Example:
            >>> ns = CacheNamespace("neo","prod", "api", "checkout", domain="ratelimit")
            >>> ns.domain_scope()
            'org:neo:env:prod:svc:api:app:checkout:v1:d:ratelimit'
            >>> ns2 = CacheNamespace("neo","prod", "api", "checkout")
            >>> ns2.domain_scope() == ns2.base()
            True
        """
        if self.domain:
            return f"{self.base()}:d:{self.domain}"
        return self.base()

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def tenant(self, tenant_id: str) -> str:
        """Generate the tenant-level prefix.

        Chains through domain_scope(), so when domain is set the tenant
        prefix includes the domain segment.

        Args:
            tenant_id: Tenant identifier

        Returns:
            Prefix: `{domain_scope}:t:{tenant_id}`

        Raises:
            ValueError: If tenant_id is empty or contains forbidden characters

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway")
            >>> ns.tenant("tenant123")
            'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123'
        """
        _validate_field("tenant_id", tenant_id)
        return f"{self.domain_scope()}:t:{tenant_id}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def user(self, tenant_id: str, user_id: str) -> str:
        """Generate the user-level prefix.

        Args:
            tenant_id: Tenant identifier
            user_id: User identifier

        Returns:
            Prefix: `{tenant}:u:{user_id}`

        Raises:
            ValueError: If tenant_id or user_id is empty or contains forbidden characters

        Example:
            >>> ns = CacheNamespace("neo","prod", "auth-api", "gateway")
            >>> ns.user("tenant123", "user456")
            'org:neo:env:prod:svc:auth-api:app:gateway:v1:t:tenant123:u:user456'
        """
        _validate_field("tenant_id", tenant_id)
        _validate_field("user_id", user_id)
        return f"{self.tenant(tenant_id)}:u:{user_id}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def make_key(self, suffix: str) -> str:
        """Create a full namespaced key from a suffix.

        The suffix is appended to domain_scope() with a colon separator.
        Colons are allowed in suffixes (used as segment delimiters), but
        glob characters (*?[]\\ ) are rejected to prevent SCAN pattern
        interference.

        Args:
            suffix: Key suffix (e.g., "user:123:endpoint")

        Returns:
            Full key: `{domain_scope}:{suffix}`

        Raises:
            ValueError: If suffix is empty, contains glob characters,
                        or contains control characters

        Example:
            >>> ns = CacheNamespace("neo","prod", "api", "checkout", domain="ratelimit")
            >>> ns.make_key("user:123")
            'org:neo:env:prod:svc:api:app:checkout:v1:d:ratelimit:user:123'
        """
        _validate_suffix(suffix)
        return f"{self.domain_scope()}:{suffix}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def make_key_at(self, tier: "KeyTier", suffix: str) -> str:
        """Create a full namespaced key anchored at a specific scope tier.

        Unlike make_key() which always anchors at domain_scope(), this method
        lets callers choose the anchoring tier. This is needed for keys that
        must anchor above or below the domain level (e.g., security keys at
        domain scope, org-wide config at org scope).

        Args:
            tier: The scope tier to anchor the key at
            suffix: Key suffix (e.g., "perm_seq:tenant1:user1")

        Returns:
            Full key: `{tier_scope}:{suffix}`

        Raises:
            ValueError: If suffix is empty, contains glob characters,
                        or contains control characters

        Example:
            >>> ns = CacheNamespace("neo","prod", "api", "checkout", domain="security")
            >>> ns.make_key_at(KeyTier.DOMAIN, "perm_seq:t1:u1")
            'org:neo:env:prod:svc:api:app:checkout:v1:d:security:perm_seq:t1:u1'
            >>> ns.make_key_at(KeyTier.ORG, "config:global")
            'org:neo:config:global'
        """
        _validate_suffix(suffix)

        scope_methods = {
            KeyTier.ORG: self.org_scope,
            KeyTier.DIV: self.div_scope,
            KeyTier.ENV: self.env_scope,
            KeyTier.SVC: self.svc_scope,
            KeyTier.BASE: self.base,
            KeyTier.DOMAIN: self.domain_scope,
        }

        scope_method = scope_methods[tier]
        return f"{scope_method()}:{suffix}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def make_slot_key(self, slot_group: str, suffix: str) -> str:
        """Create a full namespaced key with a Redis hash tag for slot co-location.

        The slot_group is embedded in literal braces ``{slot_group}`` so that
        Redis Cluster computes the hash slot from the slot_group value alone.
        All keys sharing the same slot_group resolve to the same hash slot,
        enabling multi-key operations (Lua EVAL, pipelines) without CROSSSLOT
        errors.

        Args:
            slot_group: Value placed inside Redis hash tag braces.  Must be
                non-empty, contain no control characters, no characters from
                ``_SUFFIX_FORBIDDEN_CHARS`` (``*?[]\\``), and no ``{`` or ``}``
                (prevents nested braces / hash tag injection).  Colons are
                allowed for composite groups (e.g., ``workflow_id:attempt_id``).
            suffix: Key suffix after the hash tag.  Same validation rules as
                :meth:`make_key` (via ``_validate_suffix()``).

        Returns:
            Full key: ``{domain_scope}:{{slot_group}}:{suffix}``

        Raises:
            ValueError: If *slot_group* is empty, contains forbidden characters,
                control characters, or literal braces.
            ValueError: If *suffix* fails ``_validate_suffix()`` checks.

        Example:
            >>> ns = CacheNamespace("neo", "prod", "api", "checkout", domain="transition")
            >>> ns.make_slot_key("order:1:item:1", "state")
            'org:neo:env:prod:svc:api:app:checkout:v1:d:transition:{order:1:item:1}:state'
        """
        if not slot_group:
            raise ValueError("slot_group must be non-empty")

        if any(ord(c) < 32 for c in slot_group):
            raise ValueError("slot_group: control characters not allowed")

        brace_found = {c for c in slot_group if c in "{}"}
        if brace_found:
            raise ValueError(
                f"slot_group: braces not allowed {sorted(brace_found)}"
            )

        if any(c in _SUFFIX_FORBIDDEN_CHARS for c in slot_group):
            raise ValueError(
                f"slot_group: forbidden characters {sorted(c for c in slot_group if c in _SUFFIX_FORBIDDEN_CHARS)}"
            )

        _validate_suffix(suffix)
        return f"{self.domain_scope()}:{{{slot_group}}}:{suffix}"

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def owns_key(self, key: str) -> bool:
        """Check if this namespace owns a key.

        Args:
            key: Full Redis key

        Returns:
            True if key starts with this namespace's domain_scope prefix

        Example:
            >>> ns = CacheNamespace("neo","prod", "api", "checkout", domain="ratelimit")
            >>> ns.owns_key(ns.make_key("user:123"))
            True
        """
        return key.startswith(f"{self.domain_scope()}:")

    @auto_trace(logger, disabled=TraceDisabledReason.HOTPATH)
    def cleanup_pattern(self) -> str:
        """Get the SCAN pattern for this namespace's keys only.

        Returns:
            Pattern: `{domain_scope}:*`

        Example:
            >>> ns = CacheNamespace("neo","prod", "api", "checkout", domain="ratelimit")
            >>> ns.cleanup_pattern()
            'org:neo:env:prod:svc:api:app:checkout:v1:d:ratelimit:*'
        """
        return f"{self.domain_scope()}:*"


__all__ = ["CacheNamespace", "KeyTier"]
