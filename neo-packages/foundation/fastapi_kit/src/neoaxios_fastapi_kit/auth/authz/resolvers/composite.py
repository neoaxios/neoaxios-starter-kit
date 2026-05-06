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

"""Composite resolver for aggregating permissions from multiple sources.

Supports N authorization sources with configurable merge strategies.
Can selectively query resolvers based on identity provider.

Usage:
    from neoaxios_fastapi_kit.auth.resolvers import CompositeResolver, provider_based_selector

    resolver = CompositeResolver(
        resolvers={
            "azure": azure_resolver,
            "aws": aws_resolver,
            "local": local_resolver,
        },
        merge_strategy="union",
        resolver_selector=provider_based_selector,
    )
"""

import asyncio
from typing import (
    Dict,
    FrozenSet,
    List,
    Optional,
    Callable,
)

from neoaxios_logging import get_telemetry, auto_trace

from ...context import IdentityContext
from ...protocols import PrivilegeResolver
from ..authz_utils import raise_auth_error

logger = get_telemetry(__name__)


# Type alias for resolver selector function
ResolverSelector = Callable[[IdentityContext], List[str]]


@auto_trace(logger)  # Selects resolver matching identity provider
def provider_based_selector(identity: IdentityContext) -> List[str]:
    """Select resolver matching identity provider, plus local.

    Args:
        identity: Identity context with provider field

    Returns:
        List of resolver names to query (provider first, then local)
    """
    resolvers = []
    if hasattr(identity, "provider") and identity.provider:
        resolvers.append(identity.provider)
    resolvers.append("local")
    return resolvers


@auto_trace(logger)  # Returns empty list to use all resolvers
def all_resolvers_selector(identity: IdentityContext) -> List[str]:
    """Select all configured resolvers.

    Note: This is a placeholder. The actual resolver names are set
    by CompositeResolver based on configured resolvers.

    Args:
        identity: Identity context (unused in this selector)

    Returns:
        Empty list (CompositeResolver uses all resolvers when empty)
    """
    return []  # Empty means "use all"


class CompositeResolver:
    """Aggregates permissions from multiple resolvers.

    Supports N authorization sources with configurable merge strategies.
    Can selectively query resolvers based on identity provider.
    Thread-safe async operations using asyncio.Lock.

    Merge Strategies:
        - "union": All permissions from all resolvers (default)
        - "intersection": Only permissions granted by all resolvers
        - "first_match": Use first resolver that returns permissions
        - "provider_primary": Primary from token provider, supplemented by local

    Attributes:
        resolvers: Map of resolver name to resolver instance
        merge_strategy: How to combine results from multiple resolvers
        resolver_selector: Function to select which resolvers to query
    """

    VALID_STRATEGIES = {"union", "intersection", "first_match", "provider_primary"}

    @auto_trace(logger)
    def __init__(
        self,
        resolvers: Dict[str, PrivilegeResolver],
        merge_strategy: str = "union",
        resolver_selector: Optional[ResolverSelector] = None,
    ):
        """Initialize composite resolver.

        Args:
            resolvers: Map of resolver name to resolver instance.
                      Example: {"azure": AzureADResolver(...), "local": LocalResolver(...)}
            merge_strategy: How to combine results:
                - "union": All permissions from all resolvers (default)
                - "intersection": Only permissions granted by all resolvers
                - "first_match": Use first resolver that returns permissions
                - "provider_primary": Primary from token provider, supplemented by local
            resolver_selector: Function to select which resolvers to query.
                              Default: query all resolvers.

        Raises:
            ValueError: If merge_strategy is not valid
        """
        if merge_strategy not in self.VALID_STRATEGIES:
            raise ValueError(
                f"Invalid merge_strategy '{merge_strategy}'. "
                f"Valid strategies: {self.VALID_STRATEGIES}"
            )

        self.resolvers = resolvers
        self.merge_strategy = merge_strategy
        self.resolver_selector = resolver_selector
        self._resolver_names = list(resolvers.keys())
        self._resolvers_lock = asyncio.Lock()

        logger.info(
            f"Initialized CompositeResolver with {len(resolvers)} resolvers: "
            f"{self._resolver_names}, strategy: {merge_strategy}"
        )

    @auto_trace(logger)  # Gets resolver names for identity
    def _get_resolvers_to_query(self, identity: IdentityContext) -> List[str]:
        """Get list of resolver names to query for this identity.

        Args:
            identity: Identity context

        Returns:
            List of resolver names
        """
        if self.resolver_selector:
            selected = self.resolver_selector(identity)
            # Filter to only configured resolvers
            return [name for name in selected if name in self.resolvers]
        # Default: query all resolvers
        return self._resolver_names

    @auto_trace(logger)  # Merges sets according to merge strategy
    def _merge_sets(self, sets: List[FrozenSet[str]]) -> FrozenSet[str]:
        """Merge multiple sets according to merge strategy.

        Args:
            sets: List of frozen sets to merge

        Returns:
            Merged frozen set
        """
        if not sets:
            return frozenset()

        if self.merge_strategy == "union":
            return frozenset().union(*sets)

        elif self.merge_strategy == "intersection":
            result = sets[0]
            for s in sets[1:]:
                result = result.intersection(s)
            return result

        elif self.merge_strategy == "first_match":
            for s in sets:
                if s:  # Return first non-empty set
                    return s
            return frozenset()

        elif self.merge_strategy == "provider_primary":
            # First set is primary, union with rest
            if len(sets) == 1:
                return sets[0]
            primary = sets[0]
            supplements = frozenset().union(*sets[1:])
            return primary.union(supplements)

        return frozenset()

    @auto_trace(logger)
    async def resolve_permissions(
        self, identity: IdentityContext
    ) -> FrozenSet[str]:
        """Resolve permissions from all applicable resolvers.

        Args:
            identity: Identity context

        Returns:
            Merged set of permissions from all resolvers
        """
        resolver_names = self._get_resolvers_to_query(identity)
        all_permissions: List[FrozenSet[str]] = []

        for name in resolver_names:
            resolver = self.resolvers.get(name)
            if resolver:
                try:
                    perms = await resolver.resolve_permissions(identity)
                    all_permissions.append(perms)
                    logger.debug(
                        f"Resolver '{name}' returned {len(perms)} permissions "
                        f"for user '{identity.user_id}'"
                    )
                except Exception as e:
                    # Fail-closed: Deny access when resolver fails
                    # This prevents incomplete permission validation when resolvers are unavailable
                    raise_auth_error(
                        f"resolve permissions from resolver '{name}' for user '{identity.user_id}'",
                        e,
                        f"Unable to resolve permissions from resolver '{name}'"
                    )

        merged = self._merge_sets(all_permissions)
        logger.info(
            f"Resolved {len(merged)} permissions for user '{identity.user_id}' "
            f"from {len(all_permissions)} resolvers using '{self.merge_strategy}'"
        )
        return merged

    @auto_trace(logger)
    async def resolve_roles(self, identity: IdentityContext) -> FrozenSet[str]:
        """Resolve roles from all applicable resolvers.

        Args:
            identity: Identity context

        Returns:
            Merged set of roles from all resolvers
        """
        resolver_names = self._get_resolvers_to_query(identity)
        all_roles: List[FrozenSet[str]] = []

        for name in resolver_names:
            resolver = self.resolvers.get(name)
            if resolver:
                try:
                    roles = await resolver.resolve_roles(identity)
                    all_roles.append(roles)
                    logger.debug(
                        f"Resolver '{name}' returned {len(roles)} roles "
                        f"for user '{identity.user_id}'"
                    )
                except Exception as e:
                    # Fail-closed: Deny access when resolver fails
                    # This prevents incomplete role validation when resolvers are unavailable
                    raise_auth_error(
                        f"resolve roles from resolver '{name}' for user '{identity.user_id}'",
                        e,
                        f"Unable to resolve roles from resolver '{name}'"
                    )

        merged = self._merge_sets(all_roles)
        logger.info(
            f"Resolved {len(merged)} roles for user '{identity.user_id}' "
            f"from {len(all_roles)} resolvers"
        )
        return merged

    @auto_trace(logger)
    async def check_permission(
        self, identity: IdentityContext, permission: str
    ) -> bool:
        """Check permission across applicable resolvers.

        Behavior depends on merge strategy:
        - "union"/"provider_primary": Any resolver granting permission is sufficient
        - "intersection": All resolvers must grant permission
        - "first_match": Only check first resolver

        Args:
            identity: Identity context
            permission: Permission string to check

        Returns:
            True if permission is granted according to merge strategy
        """
        resolver_names = self._get_resolvers_to_query(identity)

        if self.merge_strategy in ("union", "provider_primary"):
            # Any resolver granting permission is sufficient
            for name in resolver_names:
                resolver = self.resolvers.get(name)
                if resolver:
                    try:
                        if await resolver.check_permission(identity, permission):
                            logger.debug(
                                f"Permission '{permission}' granted by resolver '{name}' "
                                f"for user '{identity.user_id}'"
                            )
                            return True
                    except Exception as e:
                        logger.error(f"Resolver '{name}' check_permission failed: {e}")
            return False

        elif self.merge_strategy == "intersection":
            # All resolvers must grant permission
            for name in resolver_names:
                resolver = self.resolvers.get(name)
                if resolver:
                    try:
                        if not await resolver.check_permission(identity, permission):
                            logger.debug(
                                f"Permission '{permission}' denied by resolver '{name}' "
                                f"for user '{identity.user_id}'"
                            )
                            return False
                    except Exception as e:
                        logger.error(f"Resolver '{name}' check_permission failed: {e}")
                        return False  # Fail-safe: deny on error
            return True

        elif self.merge_strategy == "first_match":
            # Only check first resolver
            if resolver_names:
                first_name = resolver_names[0]
                resolver = self.resolvers.get(first_name)
                if resolver:
                    return await resolver.check_permission(identity, permission)
            return False

        return False

    @auto_trace(logger)
    async def check_resource_access(
        self,
        identity: IdentityContext,
        resource_type: str,
        resource_id: str,
        action: str,
    ) -> bool:
        """Check resource access across applicable resolvers.

        Args:
            identity: Identity context
            resource_type: Type of resource
            resource_id: Resource identifier
            action: Action to perform

        Returns:
            True if access is granted according to merge strategy
        """
        resolver_names = self._get_resolvers_to_query(identity)

        if self.merge_strategy in ("union", "provider_primary", "first_match"):
            # Any resolver granting access is sufficient
            for name in resolver_names:
                resolver = self.resolvers.get(name)
                if resolver:
                    try:
                        if await resolver.check_resource_access(
                            identity, resource_type, resource_id, action
                        ):
                            return True
                    except Exception as e:
                        logger.error(
                            f"Resolver '{name}' check_resource_access failed: {e}"
                        )
                if self.merge_strategy == "first_match":
                    break  # Only check first
            return False

        elif self.merge_strategy == "intersection":
            # All resolvers must grant access
            for name in resolver_names:
                resolver = self.resolvers.get(name)
                if resolver:
                    try:
                        if not await resolver.check_resource_access(
                            identity, resource_type, resource_id, action
                        ):
                            return False
                    except Exception as e:
                        logger.error(
                            f"Resolver '{name}' check_resource_access failed: {e}"
                        )
                        return False
            return True

        return False

    @auto_trace(logger)
    async def add_resolver(self, name: str, resolver: PrivilegeResolver) -> None:
        """Add a resolver at runtime.

        Thread-safe operation protected by asyncio.Lock to prevent
        concurrent modifications to resolvers dictionary.

        Args:
            name: Resolver name
            resolver: PrivilegeResolver instance
        """
        try:
            async with self._resolvers_lock:
                self.resolvers[name] = resolver
                self._resolver_names = list(self.resolvers.keys())
            logger.info(f"Added resolver '{name}'")
        except Exception as e:
            logger.log_error(e)
            raise

    @auto_trace(logger)
    async def remove_resolver(self, name: str) -> None:
        """Remove a resolver.

        Thread-safe operation protected by asyncio.Lock to prevent
        concurrent modifications to resolvers dictionary.

        Args:
            name: Resolver name to remove
        """
        try:
            async with self._resolvers_lock:
                self.resolvers.pop(name, None)
                self._resolver_names = list(self.resolvers.keys())
            logger.info(f"Removed resolver '{name}'")
        except Exception as e:
            logger.log_error(e)
            raise
