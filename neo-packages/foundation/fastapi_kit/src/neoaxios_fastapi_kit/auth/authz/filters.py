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

"""Tenant query filters for multi-tenant database isolation.

Automatically applies tenant isolation filters to database queries to prevent
cross-tenant data access. All queries are filtered by tenant_id from the
authenticated identity context.

Usage:
    from neoaxios_fastapi_kit.auth.filters import TenantQueryFilter, create_tenant_filter

    # Create filter instance
    filter = TenantQueryFilter()

    # Apply to SQLAlchemy query
    query = session.query(Document)
    filtered_query = filter.apply_filter(query, identity)

    # Or get filter clause dict
    filter_clause = filter.get_filter_clause(identity)
    # Returns: {"tenant_id": "uuid-string"}
"""

from typing import Any, Dict

from neoaxios_logging import get_telemetry, auto_trace

from ..context import IdentityContext
from .errors import TenantMismatchError

logger = get_telemetry(__name__)


class TenantQueryFilter:
    """Automatically applies tenant isolation to database queries.

    Ensures all queries include tenant_id filter to prevent
    cross-tenant data access. This is a critical security component
    for multi-tenant applications.

    Security Considerations:
        - Filter MUST be applied to ALL queries for tenant isolation
        - Never allow tenant_id from user input to override identity.tenant_id
        - All filter applications are logged for audit trail

    Attributes:
        tenant_column: Name of the tenant column in database tables
    """

    @auto_trace(logger)
    def __init__(self, tenant_column: str = "tenant_id"):
        """Initialize filter with tenant column name.

        Args:
            tenant_column: Name of the tenant column in database tables.
                          Defaults to "tenant_id".
        """
        self.tenant_column = tenant_column
        logger.info(
            f"Initialized TenantQueryFilter with column '{tenant_column}'"
        )

    @auto_trace(logger)
    def get_filter_clause(self, identity: IdentityContext) -> Dict[str, str]:
        """Get filter clause for tenant isolation.

        Returns a dictionary suitable for use with SQLAlchemy filter_by()
        or as a filter condition.

        Args:
            identity: Identity context with tenant_id

        Returns:
            Dict with tenant filter: {"tenant_id": identity.tenant_id}

        Example:
            clause = filter.get_filter_clause(identity)
            query = session.query(Document).filter_by(**clause)
        """
        filter_clause = {self.tenant_column: identity.tenant_id}
        logger.debug(
            f"Generated filter clause for tenant '{identity.tenant_id}': "
            f"{filter_clause}"
        )
        return filter_clause

    @auto_trace(logger)
    def apply_filter(
        self,
        query: Any,
        identity: IdentityContext
    ) -> Any:
        """Apply tenant filter to SQLAlchemy query.

        Adds a WHERE clause filtering by tenant_id. This method is applied
        regardless of any existing query conditions to ensure tenant isolation.

        Args:
            query: SQLAlchemy query or select statement
            identity: Identity context with tenant_id

        Returns:
            Query with tenant filter applied

        Example:
            query = session.query(Document)
            filtered_query = filter.apply_filter(query, identity)
            results = filtered_query.all()

        Security Note:
            This filter is applied in ADDITION to any existing filters.
            It does not replace or override existing conditions.
        """
        filter_clause = self.get_filter_clause(identity)

        # Apply filter using filter_by for cleaner syntax
        filtered_query = query.filter_by(**filter_clause)

        logger.info(
            f"Applied tenant filter for tenant '{identity.tenant_id}' "
            f"to query (column: '{self.tenant_column}')"
        )

        return filtered_query

    @auto_trace(logger)
    def validate_tenant_access(
        self,
        identity: IdentityContext,
        resource_tenant_id: str,
    ) -> None:
        """Validate identity can access resource in given tenant.

        Verifies that the identity's tenant_id matches the resource's tenant_id.
        This is used for explicit tenant validation before allowing operations
        on specific resources.

        Args:
            identity: Identity context with tenant_id
            resource_tenant_id: Tenant ID of the resource being accessed

        Raises:
            TenantMismatchError: If tenant IDs don't match

        Example:
            # Before updating a document
            filter.validate_tenant_access(identity, document.tenant_id)
            document.update(new_data)

        Security Note:
            Always call this before performing operations on resources
            when you have direct access to the resource object.
        """
        if identity.tenant_id != resource_tenant_id:
            logger.warning(
                f"Tenant access violation: identity tenant '{identity.tenant_id}' "
                f"attempted to access resource in tenant '{resource_tenant_id}' "
                f"for user '{identity.user_id}'"
            )
            raise TenantMismatchError(
                identity_tenant=identity.tenant_id,
                resource_tenant=resource_tenant_id
            )

        logger.debug(
            f"Tenant access validated: identity tenant '{identity.tenant_id}' "
            f"matches resource tenant '{resource_tenant_id}'"
        )


@auto_trace(logger)
def create_tenant_filter(identity: IdentityContext) -> Dict[str, str]:
    """Convenience function to create tenant filter dict.

    Creates a filter clause dictionary for the default "tenant_id" column.
    This is a shorthand for creating a TenantQueryFilter instance and
    calling get_filter_clause().

    Args:
        identity: Identity context with tenant_id

    Returns:
        Dict with tenant filter: {"tenant_id": identity.tenant_id}

    Example:
        filter_clause = create_tenant_filter(identity)
        query = session.query(Document).filter_by(**filter_clause)
    """
    logger.debug(f"Created tenant filter for tenant '{identity.tenant_id}'")
    return {"tenant_id": identity.tenant_id}
