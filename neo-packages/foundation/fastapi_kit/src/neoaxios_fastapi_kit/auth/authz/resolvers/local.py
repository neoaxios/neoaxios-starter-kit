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

"""Local database resolver for permission and ownership lookup.

Implements PrivilegeResolver and OwnershipResolver protocols using
a local database. Supports SQLAlchemy async sessions.

Usage:
    from neoaxios_fastapi_kit.auth.resolvers import LocalResolver

    resolver = LocalResolver(
        session_factory=async_session_maker,
        role_permissions=ROLE_PERMISSIONS,
    )
"""

from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Optional,
    Protocol,
)

from neoaxios_logging import get_telemetry, auto_trace
from neoaxios_fastapi_kit.auth.validators import validate_uuid, validate_resource_id

from ...context import IdentityContext
from ..authz_utils import raise_auth_error

logger = get_telemetry(__name__)


class AsyncSession(Protocol):
    """Protocol for async database session."""

    async def execute(self, statement: Any) -> Any:
        """Execute a SQL statement."""
        ...

    async def scalar(self, statement: Any) -> Any:
        """Execute and return scalar result."""
        ...


# Type alias for session factory
SessionFactory = Callable[[], AsyncSession]


@dataclass
class UserRoleRow:
    """Database row for user roles."""

    user_id: str
    tenant_id: str
    role_name: str


@dataclass
class ResourceOwnerRow:
    """Database row for resource ownership."""

    resource_type: str
    resource_id: str
    owner_id: str
    tenant_id: str


@dataclass
class CollaboratorRow:
    """Database row for resource collaborators."""

    resource_type: str
    resource_id: str
    user_id: str
    permission_level: str  # "read" | "write" | "admin"


class LocalResolver:
    """Permission resolver using local database.

    Implements both PrivilegeResolver and OwnershipResolver protocols.
    Queries local database for user roles and resource ownership.

    Attributes:
        session_factory: Factory for creating async database sessions
        role_permissions: Static mapping of role names to permission sets
    """

    @auto_trace(logger)
    def __init__(
        self,
        session_factory: SessionFactory,
        role_permissions: Optional[Dict[str, FrozenSet[str]]] = None,
    ):
        """Initialize local resolver.

        Args:
            session_factory: Callable that returns an async database session.
                            Example: async_session_maker from SQLAlchemy
            role_permissions: Static mapping of role name to permissions.
                            Example: {"admin": frozenset(["read", "write", "delete"])}
        """
        self._session_factory = session_factory
        self._role_permissions = role_permissions or {}

        logger.info(
            f"Initialized LocalResolver with {len(self._role_permissions)} role mappings"
        )

    @auto_trace(logger)
    async def _get_user_roles(
        self, session: AsyncSession, user_id: str, tenant_id: str
    ) -> FrozenSet[str]:
        """Query database for user roles.

        Args:
            session: Database session
            user_id: User identifier
            tenant_id: Tenant identifier

        Returns:
            Set of role names
        """
        # SQL query to fetch user roles - uses parameterized queries
        # Note: Using raw SQL with parameterized queries (:user_id, :tenant_id)
        # to prevent SQL injection. SQLAlchemy ORM conversion not performed as
        # it would require model definitions not available in this layer.
        query = """
            SELECT role_name FROM user_roles
            WHERE user_id = :user_id AND tenant_id = :tenant_id
        """
        logger.debug(f"Querying roles for user '{user_id}' in tenant '{tenant_id}'")

        try:
            result = await session.execute(
                query, {"user_id": user_id, "tenant_id": tenant_id}
            )
            roles = frozenset(row.role_name for row in result)
            logger.debug(f"Found {len(roles)} roles for user '{user_id}'")
            return roles
        except Exception as e:
            # Fail-closed: Deny access when unable to query roles from database
            # This prevents ambiguous behavior where empty permissions could allow or deny access
            raise_auth_error(
                f"query user roles for user '{user_id}'",
                e,
                "Unable to query user roles from database"
            )

    @auto_trace(logger)
    def _expand_permissions(self, roles: FrozenSet[str]) -> FrozenSet[str]:
        """Expand roles to permissions using role_permissions mapping.

        Args:
            roles: Set of role names

        Returns:
            Set of permissions from all roles
        """
        permissions: set[str] = set()
        for role in roles:
            role_perms = self._role_permissions.get(role, frozenset())
            permissions.update(role_perms)
        return frozenset(permissions)

    @auto_trace(logger)
    async def resolve_permissions(
        self, identity: IdentityContext
    ) -> FrozenSet[str]:
        """Resolve all permissions for identity from local database.

        Fetches user roles from database and expands to permissions
        using the role_permissions mapping.

        Args:
            identity: Identity context with user_id and tenant_id

        Returns:
            Set of permission strings
        """
        # Validate inputs to prevent injection attacks
        validate_uuid(identity.user_id)
        validate_uuid(identity.tenant_id)

        async with self._session_factory() as session:
            roles = await self._get_user_roles(
                session, identity.user_id, identity.tenant_id
            )

        # Start with identity's existing permissions
        permissions = set(identity.permissions)

        # Add permissions from database roles
        expanded = self._expand_permissions(roles)
        permissions.update(expanded)

        logger.info(
            f"Resolved {len(permissions)} permissions for user '{identity.user_id}' "
            f"from {len(roles)} local roles"
        )
        return frozenset(permissions)

    @auto_trace(logger)
    async def resolve_roles(self, identity: IdentityContext) -> FrozenSet[str]:
        """Resolve all roles for identity from local database.

        Args:
            identity: Identity context with user_id and tenant_id

        Returns:
            Set of role names
        """
        # Validate inputs to prevent injection attacks
        validate_uuid(identity.user_id)
        validate_uuid(identity.tenant_id)

        async with self._session_factory() as session:
            roles = await self._get_user_roles(
                session, identity.user_id, identity.tenant_id
            )

        # Combine with identity's existing roles
        all_roles = identity.roles | roles

        logger.info(
            f"Resolved {len(all_roles)} roles for user '{identity.user_id}'"
        )
        return all_roles

    @auto_trace(logger)
    async def check_permission(
        self, identity: IdentityContext, permission: str
    ) -> bool:
        """Check if identity has specific permission.

        Args:
            identity: Identity context
            permission: Permission string to check (e.g., "document:read")

        Returns:
            True if permission is granted
        """
        # Quick check against identity's existing permissions
        if permission in identity.permissions:
            logger.debug(
                f"Permission '{permission}' found in identity for user '{identity.user_id}'"
            )
            return True

        # Resolve full permissions and check
        permissions = await self.resolve_permissions(identity)
        granted = permission in permissions

        logger.debug(
            f"Permission '{permission}' {'granted' if granted else 'denied'} "
            f"for user '{identity.user_id}'"
        )
        return granted

    @auto_trace(logger)
    async def check_resource_access(
        self,
        identity: IdentityContext,
        resource_type: str,
        resource_id: str,
        action: str,
    ) -> bool:
        """Check if identity can perform action on resource.

        Checks ownership, collaboration, and role-based permissions.

        Args:
            identity: Identity context
            resource_type: Type of resource (e.g., "document")
            resource_id: Resource identifier
            action: Action to perform (e.g., "read", "write", "delete")

        Returns:
            True if access is granted
        """
        # Validate inputs to prevent injection attacks
        validate_uuid(identity.user_id)
        validate_resource_id(resource_id)

        # Check if user owns the resource
        owner_id = await self.get_owner(resource_type, resource_id)
        if owner_id == identity.user_id:
            logger.debug(
                f"User '{identity.user_id}' is owner of {resource_type}:{resource_id}"
            )
            return True

        # Check if user is a collaborator
        collaborators = await self.get_collaborators(resource_type, resource_id)
        if identity.user_id in collaborators:
            logger.debug(
                f"User '{identity.user_id}' is collaborator on {resource_type}:{resource_id}"
            )
            # Check collaborator permission level
            return await self._check_collaborator_permission(
                identity.user_id, resource_type, resource_id, action
            )

        # Check role-based permission
        permission = f"{resource_type}:{action}"
        return await self.check_permission(identity, permission)

    @auto_trace(logger)
    async def _check_collaborator_permission(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
    ) -> bool:
        """Check if collaborator has permission for action.

        Args:
            user_id: Collaborator user ID
            resource_type: Type of resource
            resource_id: Resource identifier
            action: Action to check

        Returns:
            True if collaborator has permission
        """
        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                SELECT permission_level FROM resource_collaborators
                WHERE resource_type = :resource_type
                AND resource_id = :resource_id
                AND user_id = :user_id
            """
            try:
                result = await session.scalar(
                    query,
                    {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "user_id": user_id,
                    },
                )

                if not result:
                    return False

                # Permission level hierarchy
                level = result.lower()
                if level == "admin":
                    return True
                if level == "write" and action in ("read", "write", "update"):
                    return True
                if level == "read" and action == "read":
                    return True

                return False
            except Exception as e:
                # Fail-closed: Deny access when unable to verify collaborator permissions
                raise_auth_error(
                    f"check collaborator permission for user '{user_id}'",
                    e,
                    "Unable to verify collaborator permissions"
                )

    @auto_trace(logger)
    async def get_owner(
        self, resource_type: str, resource_id: str
    ) -> Optional[str]:
        """Get owner user_id for resource.

        Fail-closed: Raises AuthError if unable to verify ownership.
        This prevents ambiguous authorization when database is unavailable.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier

        Returns:
            Owner user_id or None if resource not found

        Raises:
            AuthError: If unable to query ownership from database
        """
        # Validate inputs to prevent injection attacks
        validate_resource_id(resource_id)

        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                SELECT owner_id FROM resource_ownership
                WHERE resource_type = :resource_type AND resource_id = :resource_id
            """
            try:
                result = await session.scalar(
                    query,
                    {"resource_type": resource_type, "resource_id": resource_id},
                )
                return result
            except Exception as e:
                # Fail-closed: Deny access when unable to verify ownership
                # This prevents incomplete access checks when database is unavailable
                raise_auth_error(
                    f"get resource owner for {resource_type}:{resource_id}",
                    e,
                    "Unable to verify resource ownership"
                )

    @auto_trace(logger)
    async def get_tenant(
        self, resource_type: str, resource_id: str
    ) -> Optional[str]:
        """Get tenant_id for resource.

        Fail-closed: Raises AuthError if unable to verify tenant.
        This prevents ambiguous authorization when database is unavailable.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier

        Returns:
            Tenant_id or None if resource not found

        Raises:
            AuthError: If unable to query tenant from database
        """
        # Validate inputs to prevent injection attacks
        validate_resource_id(resource_id)

        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                SELECT tenant_id FROM resource_ownership
                WHERE resource_type = :resource_type AND resource_id = :resource_id
            """
            try:
                result = await session.scalar(
                    query,
                    {"resource_type": resource_type, "resource_id": resource_id},
                )
                return result
            except Exception as e:
                # Fail-closed: Deny access when unable to verify tenant
                # This prevents incomplete access checks when database is unavailable
                raise_auth_error(
                    f"get resource tenant for {resource_type}:{resource_id}",
                    e,
                    "Unable to verify resource tenant"
                )

    @auto_trace(logger)
    async def get_collaborators(
        self, resource_type: str, resource_id: str
    ) -> FrozenSet[str]:
        """Get user_ids with access to resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier

        Returns:
            Set of collaborator user_ids
        """
        # Validate inputs to prevent injection attacks
        validate_resource_id(resource_id)

        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                SELECT user_id FROM resource_collaborators
                WHERE resource_type = :resource_type AND resource_id = :resource_id
            """
            try:
                result = await session.execute(
                    query,
                    {"resource_type": resource_type, "resource_id": resource_id},
                )
                return frozenset(row.user_id for row in result)
            except Exception as e:
                # Fail-closed: Deny access when unable to query collaborators
                # This prevents incomplete access checks when database is unavailable
                raise_auth_error(
                    f"get resource collaborators for {resource_type}:{resource_id}",
                    e,
                    "Unable to query resource collaborators from database"
                )

    @auto_trace(logger)
    async def add_role(
        self, user_id: str, tenant_id: str, role_name: str
    ) -> bool:
        """Add role to user.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            role_name: Role to add

        Returns:
            True if successful
        """
        # Validate inputs to prevent injection attacks
        validate_uuid(user_id)
        validate_uuid(tenant_id)

        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                INSERT INTO user_roles (user_id, tenant_id, role_name)
                VALUES (:user_id, :tenant_id, :role_name)
                ON CONFLICT DO NOTHING
            """
            try:
                await session.execute(
                    query,
                    {
                        "user_id": user_id,
                        "tenant_id": tenant_id,
                        "role_name": role_name,
                    },
                )
                logger.info(f"Added role '{role_name}' to user '{user_id}'")
                return True
            except Exception as e:
                logger.error(f"Failed to add role: {e}")
                return False

    @auto_trace(logger)
    async def remove_role(
        self, user_id: str, tenant_id: str, role_name: str
    ) -> bool:
        """Remove role from user.

        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            role_name: Role to remove

        Returns:
            True if successful
        """
        # Validate inputs to prevent injection attacks
        validate_uuid(user_id)
        validate_uuid(tenant_id)

        async with self._session_factory() as session:
            # Uses parameterized queries
            query = """
                DELETE FROM user_roles
                WHERE user_id = :user_id
                AND tenant_id = :tenant_id
                AND role_name = :role_name
            """
            try:
                await session.execute(
                    query,
                    {
                        "user_id": user_id,
                        "tenant_id": tenant_id,
                        "role_name": role_name,
                    },
                )
                logger.info(f"Removed role '{role_name}' from user '{user_id}'")
                return True
            except Exception as e:
                logger.error(f"Failed to remove role: {e}")
                return False
