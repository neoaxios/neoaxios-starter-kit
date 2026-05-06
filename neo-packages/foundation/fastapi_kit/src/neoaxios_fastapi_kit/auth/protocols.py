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

"""Protocol interfaces for authorization framework.

Defines all the protocol (interface) types used across the authorization
framework. Protocols define the contracts that implementations must satisfy.

Cache protocols have been consolidated into the canonical
secure_cache.protocols.CacheBackend. See cache-protocol-unification.design.md.

All protocols are runtime checkable and can be used with isinstance() checks.

Usage:
    from neoaxios_fastapi_kit.auth.protocols import (
        PrivilegeResolver,
        OwnershipResolver,
        TokenDecoder,
        PolicyEvaluator,
        AuditLogger,
        TenantQueryFilter,
    )

    # Implement a protocol
    class MyResolver(PrivilegeResolver):
        async def resolve_permissions(self, identity: IdentityContext) -> FrozenSet[str]:
            ...
"""

from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    FrozenSet,
    Generic,
    List,
    Optional,
    Protocol,
    TypeVar,
    runtime_checkable,
)

from neoaxios_fastapi_kit.auth.context import IdentityContext

# Type variable for query types (SQLAlchemy, MongoDB, etc.)
Q = TypeVar("Q")


@runtime_checkable
class PrivilegeResolver(Protocol):
    """Abstract interface for privilege resolution.

    Implementations resolve roles and permissions for an identity from
    various sources (database, LDAP, Azure AD, AWS Cognito, etc.).

    All methods are async to support network calls to external identity providers.
    """

    async def resolve_permissions(
        self,
        identity: IdentityContext,
    ) -> FrozenSet[str]:
        """Resolve all permissions for identity.

        Args:
            identity: Identity context to resolve permissions for

        Returns:
            Set of permission strings in "resource:action" format

        Example:
            permissions = await resolver.resolve_permissions(identity)
            # Returns: frozenset({"document:read", "document:write"})
        """
        ...

    async def resolve_roles(
        self,
        identity: IdentityContext,
    ) -> FrozenSet[str]:
        """Resolve all roles for identity.

        Args:
            identity: Identity context to resolve roles for

        Returns:
            Set of role names

        Example:
            roles = await resolver.resolve_roles(identity)
            # Returns: frozenset({"admin", "editor"})
        """
        ...

    async def check_permission(
        self,
        identity: IdentityContext,
        permission: str,
    ) -> bool:
        """Check if identity has specific permission.

        Args:
            identity: Identity context to check
            permission: Permission string in "resource:action" format

        Returns:
            True if permission is granted, False otherwise

        Example:
            allowed = await resolver.check_permission(identity, "document:write")
        """
        ...

    async def check_resource_access(
        self,
        identity: IdentityContext,
        resource_type: str,
        resource_id: str,
        action: str,
    ) -> bool:
        """Check if identity can perform action on resource.

        Args:
            identity: Identity context to check
            resource_type: Type of resource (e.g., "document", "project")
            resource_id: Unique identifier for the resource
            action: Action to perform (e.g., "read", "write", "delete")

        Returns:
            True if access is granted, False otherwise

        Example:
            allowed = await resolver.check_resource_access(
                identity, "document", "doc-123", "write"
            )
        """
        ...


@runtime_checkable
class OwnershipResolver(Protocol):
    """Abstract interface for resource ownership lookup.

    Implementations query the application's data store to determine
    resource ownership, tenant membership, and collaboration relationships.

    All methods are async to support database queries.
    """

    async def get_owner(
        self,
        resource_type: str,
        resource_id: str,
    ) -> Optional[str]:
        """Return owner user_id for resource, or None if not found.

        Fail-closed: Raises AuthError if unable to verify ownership.
        This prevents incomplete access checks when database is unavailable.

        Args:
            resource_type: Type of resource (e.g., "document", "project")
            resource_id: Unique identifier for the resource

        Returns:
            Owner's user_id or None if resource doesn't exist

        Raises:
            AuthError: If unable to query ownership from database (fail-closed)

        Example:
            owner_id = await resolver.get_owner("document", "doc-123")
            if owner_id == identity.user_id:
                # User owns this document
        """
        ...

    async def get_tenant(
        self,
        resource_type: str,
        resource_id: str,
    ) -> Optional[str]:
        """Return tenant_id for resource, or None if not found.

        Fail-closed: Raises AuthError if unable to verify tenant.
        This prevents incomplete access checks when database is unavailable.

        Args:
            resource_type: Type of resource (e.g., "document", "project")
            resource_id: Unique identifier for the resource

        Returns:
            Resource's tenant_id or None if resource doesn't exist

        Raises:
            AuthError: If unable to query tenant from database (fail-closed)

        Example:
            tenant_id = await resolver.get_tenant("document", "doc-123")
            if tenant_id == identity.tenant_id:
                # Resource belongs to user's tenant
        """
        ...

    async def get_collaborators(
        self,
        resource_type: str,
        resource_id: str,
    ) -> FrozenSet[str]:
        """Return user_ids with access to resource (for cooperation).

        Args:
            resource_type: Type of resource (e.g., "document", "project")
            resource_id: Unique identifier for the resource

        Returns:
            Set of user_ids that have collaborative access to the resource

        Example:
            collaborators = await resolver.get_collaborators("document", "doc-123")
            if identity.user_id in collaborators:
                # User is a collaborator on this document
        """
        ...


@runtime_checkable
class TokenDecoder(Protocol):
    """Abstract interface for token decoding.

    Implementations decode and validate tokens from various identity providers
    (JWT, OAuth2, OIDC, etc.).

    Scope: Decoding and validation only. Token refresh and revocation
    are handled by the identity provider (OAuth2/OIDC server).

    All methods are async to support network calls for token validation.
    """

    async def decode(
        self,
        token: str,
    ) -> IdentityContext:
        """Decode token to identity context.

        Args:
            token: Token string to decode (JWT, opaque token, etc.)

        Returns:
            Identity context extracted from token

        Raises:
            TokenInvalidError: Token format is invalid or cannot be decoded
            TokenExpiredError: Token has expired
            TokenRevokedError: Token has been revoked

        Example:
            identity = await decoder.decode(bearer_token)
        """
        ...

    async def validate(
        self,
        token: str,
    ) -> bool:
        """Check if token is valid (not expired, not revoked).

        Args:
            token: Token string to validate

        Returns:
            True if token is valid, False otherwise

        Example:
            if await decoder.validate(token):
                # Token is valid
        """
        ...

    async def is_revoked(
        self,
        token: str,
    ) -> bool:
        """Check token against revocation list/introspection endpoint.

        Args:
            token: Token string to check

        Returns:
            True if token has been revoked, False otherwise

        Example:
            if await decoder.is_revoked(token):
                raise TokenRevokedError("Token has been revoked")
        """
        ...


@dataclass(frozen=True)
class PolicyDecision:
    """Result of ABAC policy evaluation.

    Attributes:
        allowed: Whether access is allowed
        reason: Human-readable explanation for the decision
        matched_policy: ID of the policy that made the decision (if any)

    Example:
        decision = PolicyDecision(
            allowed=False,
            reason="User clearance level insufficient",
            matched_policy="policy-secret-docs",
        )
    """

    allowed: bool
    reason: str
    matched_policy: Optional[str] = None


@dataclass(frozen=True)
class Policy:
    """ABAC policy definition.

    Attributes:
        id: Unique policy identifier
        name: Human-readable policy name
        resource_type: Type of resource this policy applies to
        actions: Set of actions this policy governs
        conditions: Dictionary of attribute conditions
        effect: Policy effect ("allow" or "deny")

    Example:
        policy = Policy(
            id="policy-secret-docs",
            name="Secret Document Access",
            resource_type="document",
            actions=frozenset({"read", "write"}),
            conditions={
                "clearance": {"min": 3},
                "department": {"in": ["security", "executive"]},
            },
            effect="allow",
        )
    """

    id: str
    name: str
    resource_type: str
    actions: FrozenSet[str]
    conditions: Dict[str, Any]
    effect: str  # "allow" | "deny"


@runtime_checkable
class PolicyEvaluator(Protocol):
    """Abstract interface for attribute-based access control policy evaluation.

    Implementations evaluate ABAC policies based on identity attributes
    and resource attributes. Can integrate with external policy engines
    like Open Policy Agent (OPA).

    All methods are async to support network calls to policy engines.
    """

    async def evaluate(
        self,
        identity: IdentityContext,
        resource: Dict[str, Any],
        action: str,
    ) -> PolicyDecision:
        """Evaluate ABAC policy. Returns decision with reason.

        Args:
            identity: Identity context with attributes
            resource: Resource attributes dictionary
            action: Action being attempted

        Returns:
            Policy decision with reason and matched policy

        Example:
            decision = await evaluator.evaluate(
                identity,
                resource={"type": "document", "classification": "secret"},
                action="read",
            )
            if not decision.allowed:
                raise PolicyDeniedError(decision.reason)
        """
        ...

    async def get_applicable_policies(
        self,
        resource_type: str,
        action: str,
    ) -> List[Policy]:
        """Get policies applicable to resource type and action.

        Args:
            resource_type: Type of resource (e.g., "document")
            action: Action being attempted (e.g., "read")

        Returns:
            List of applicable policies

        Example:
            policies = await evaluator.get_applicable_policies("document", "read")
        """
        ...


@runtime_checkable
class AuditLogger(Protocol):
    """Abstract interface for compliance audit logging.

    Implementations log all authorization decisions for compliance
    requirements (SOC2, GDPR, HIPAA, etc.).

    All methods are async and should not raise exceptions to avoid
    breaking authorization flows. Implementations must be fail-safe.
    """

    async def log_access(
        self,
        identity: IdentityContext,
        resource_type: str,
        resource_id: str,
        action: str,
        outcome: str,
        reason: Optional[str] = None,
    ) -> None:
        """Log access attempt for compliance.

        Args:
            identity: Identity that attempted access
            resource_type: Type of resource accessed
            resource_id: Resource identifier
            action: Action attempted
            outcome: "allowed" or "denied"
            reason: Optional reason for the outcome

        Example:
            await audit.log_access(
                identity,
                resource_type="document",
                resource_id="doc-123",
                action="write",
                outcome="denied",
                reason="User lacks document:write permission",
            )
        """
        ...

    async def log_impersonation(
        self,
        admin_id: str,
        target_user_id: str,
        action: str,
        reason: str,
    ) -> None:
        """Log impersonation events.

        Args:
            admin_id: User ID of the admin performing impersonation
            target_user_id: User ID being impersonated
            action: "start" or "end"
            reason: Reason for impersonation

        Example:
            await audit.log_impersonation(
                admin_id="admin-123",
                target_user_id="user-456",
                action="start",
                reason="Customer support ticket #789",
            )
        """
        ...

    async def log_auth_failure(
        self,
        source_ip: str,
        failure_type: str,
        token_hint: Optional[str] = None,
    ) -> None:
        """Log authentication failures for security monitoring.

        Args:
            source_ip: IP address of the request
            failure_type: "invalid_token" | "expired" | "revoked"
            token_hint: Last 8 chars of token for debugging (optional)

        Example:
            await audit.log_auth_failure(
                source_ip="192.168.1.100",
                failure_type="expired",
                token_hint="...xyz123",
            )
        """
        ...


@runtime_checkable
class TenantQueryFilter(Protocol, Generic[Q]):
    """Abstract interface for automatic tenant scoping.

    Implementations automatically filter queries to enforce tenant isolation.
    Generic type Q represents the query type (SQLAlchemy Query, MongoDB
    filter dict, etc.).

    This ensures that users can only access resources within their tenant.
    """

    def apply_filter(
        self,
        query: Q,
        identity: IdentityContext,
    ) -> Q:
        """Apply tenant_id filter to query. Returns modified query.

        Args:
            query: Query object to filter
            identity: Identity context containing tenant_id

        Returns:
            Modified query with tenant filter applied

        Example (SQLAlchemy):
            query = session.query(Document)
            query = filter.apply_filter(query, identity)
            # Automatically adds: .filter(Document.tenant_id == identity.tenant_id)
        """
        ...

    def get_filter_clause(
        self,
        identity: IdentityContext,
    ) -> Dict[str, Any]:
        """Return filter dict for manual application.

        Args:
            identity: Identity context containing tenant_id

        Returns:
            Filter dictionary (e.g., for MongoDB queries)

        Example (MongoDB):
            filter_clause = filter.get_filter_clause(identity)
            # Returns: {"tenant_id": identity.tenant_id}
            documents = db.documents.find(filter_clause)
        """
        ...
