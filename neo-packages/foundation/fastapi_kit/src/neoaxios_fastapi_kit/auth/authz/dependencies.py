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

"""FastAPI dependencies for authorization framework.

Provides factory functions for creating FastAPI dependencies that handle
identity extraction, permission checks, and resource access control.

Usage:
    from fastapi import Depends, FastAPI
    from neoaxios_fastapi_kit.auth.dependencies import (
        get_identity,
        require_permission,
        require_role,
    )

    app = FastAPI(title="my-app")

    # Create dependency instances
    get_current_identity = get_identity(
        decoder=token_decoder,
        resolver=privilege_resolver,
        app_id=app.title,
    )

    # Use in route
    @app.get("/protected")
    async def protected_route(
        identity: IdentityContext = Depends(get_current_identity),
    ):
        return {"user_id": identity.user_id}

    # Require specific permission
    @app.delete("/resource/{id}")
    async def delete_resource(
        id: str,
        identity: IdentityContext = Depends(
            require_permission("resource:delete", get_current_identity)
        ),
    ):
        return {"deleted": id}
"""

from __future__ import annotations  # Enable deferred annotation evaluation

from typing import Callable, FrozenSet, Optional, TYPE_CHECKING

from fastapi import Depends, Request
from neoaxios_logging import get_telemetry, auto_trace

from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_fastapi_kit.auth.defaults import (
    DEFAULT_TOKEN_HEADER,
    DEFAULT_TOKEN_PREFIX,
)
from neoaxios_fastapi_kit.auth.errors import AuthError
from neoaxios_fastapi_kit.auth.authn.errors import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from neoaxios_fastapi_kit.auth.authz.errors import (
    OwnershipRequiredError,
    PermissionDeniedError,
    PolicyDeniedError,
    TenantMismatchError,
)
from neoaxios_fastapi_kit.auth.cache_keys import permissions_key

# Use TYPE_CHECKING pattern with __future__ annotations to avoid circular imports
if TYPE_CHECKING:
    from neoaxios_fastapi_kit.auth.protocols import (
        TokenDecoder,
        PrivilegeResolver,
        OwnershipResolver,
        AuditLogger,
        PolicyEvaluator,
    )
    from neoaxios_secure_cache import CacheBackend
    from neoaxios_secure_cache import CacheNamespace

logger = get_telemetry(__name__)



# =============================================================================
# Helper Functions
# =============================================================================


@auto_trace(logger)
def _extract_token_from_header(request: Request) -> str:
    """Extract bearer token from Authorization header.

    Args:
        request: FastAPI request object

    Returns:
        JWT token string

    Raises:
        AuthError: If authorization header is missing or malformed
    """
    auth_header = request.headers.get(DEFAULT_TOKEN_HEADER)

    if not auth_header:
        error = AuthError("Missing authorization token")
        logger.log_error(error)
        raise error

    if not auth_header.startswith(DEFAULT_TOKEN_PREFIX):
        error = AuthError(
            f"Invalid authorization header format. Expected '{DEFAULT_TOKEN_PREFIX}' prefix"
        )
        logger.log_error(error)
        raise error

    token = auth_header[len(DEFAULT_TOKEN_PREFIX) :].strip()

    if not token:
        error = AuthError("Empty authorization token")
        logger.log_error(error)
        raise error

    logger.debug("Extracted token from Authorization header")
    return token


@auto_trace(logger)
async def _resolve_and_cache_permissions(
    identity: IdentityContext,
    resolver: PrivilegeResolver,
    cache: CacheBackend,
    cache_key: str,
    cache_ttl: int,
) -> FrozenSet[str]:
    """Resolve permissions with caching.

    Args:
        identity: Identity context
        resolver: Privilege resolver
        cache: Cache backend (required)
        cache_key: Cache key for permissions
        cache_ttl: Cache TTL in seconds

    Returns:
        Resolved permissions
    """
    # Check cache first
    cached_permissions = await cache.get(cache_key)
    if cached_permissions is not None:
        logger.debug(
            f"Cache hit for permissions: {cache_key}"
        )
        return cached_permissions

    # Resolve from source
    permissions = await resolver.resolve_permissions(identity)

    # Store in cache
    await cache.set(cache_key, permissions, cache_ttl)
    logger.debug(
        f"Cached permissions for key: {cache_key}"
    )

    return permissions


# =============================================================================
# Dependency Factories
# =============================================================================


@auto_trace(logger)
def get_identity(
    decoder: TokenDecoder,
    resolver: PrivilegeResolver,
    namespace: CacheNamespace,
    cache: CacheBackend,
    audit: Optional[AuditLogger] = None,
    cache_ttl: int = 300,
) -> Callable:
    """Factory for identity extraction dependency.

    Creates a FastAPI dependency that extracts and decodes identity from
    the Authorization header, resolves permissions, and caches the result.

    Args:
        decoder: Token decoder instance
        resolver: Privilege resolver instance
        namespace: Cache namespace for hierarchical key prefixing
        cache: Cache backend for permissions (required - fail fast on misconfiguration)
        audit: Optional audit logger
        cache_ttl: Cache TTL in seconds (default: 300)

    Returns:
        FastAPI dependency function

    Raises:
        TypeError: If cache or namespace is not provided (fail fast on misconfiguration)

    Example:
        from neoaxios_secure_cache import CacheNamespace

        ns = CacheNamespace(
            org="neo",
            env="prod",
            service="auth-api",
            app="gateway",
        )

        get_current_identity = get_identity(
            decoder=token_decoder,
            resolver=privilege_resolver,
            namespace=ns,
            cache=cache_backend,
        )

        @app.get("/me")
        async def get_me(identity: IdentityContext = Depends(get_current_identity)):
            return {"user_id": identity.user_id}
    """

    @auto_trace(logger)
    async def dependency(request: Request) -> IdentityContext:
        """Extract and decode identity from request.

        If AuthMiddleware has already validated the token and set
        request.state.identity, returns the pre-validated identity
        directly (skipping redundant token validation).

        Args:
            request: FastAPI request object

        Returns:
            Identity context with resolved permissions

        Raises:
            AuthError: If token is missing or invalid
            TokenExpiredError: If token has expired
            TokenRevokedError: If token has been revoked
        """
        # Phase 1: Determine identity (authentication).
        # Pre-validated path skips token decoding (AuthMiddleware already validated).
        # Fresh path extracts token, decodes it, and checks revocation.
        # Phase 2 (permission resolution) always runs regardless of source.
        identity = None

        if getattr(request.state, "_identity_validated", False) is True:
            pre_validated = getattr(request.state, "identity", None)
            if pre_validated is not None:
                # Unwrap ReadOnlyIdentityWrapper if needed
                unwrapped = getattr(pre_validated, "identity", pre_validated)
                # Duck-type check: any object with tenant_id and user_id
                # as string attributes satisfies the identity contract
                # (supports IdentityContext, dataclass implementations,
                # and protocol-conformant objects).
                tenant_id = getattr(unwrapped, "tenant_id", None)
                user_id = getattr(unwrapped, "user_id", None)
                if isinstance(tenant_id, str) and isinstance(user_id, str):
                    identity = unwrapped
                    logger.info(
                        "identity_source",
                        source="pre-validated",
                        user_id=identity.user_id,
                    )

        if identity is None:
            # Fresh validation: extract, decode, check revocation
            logger.info("identity_source", source="fresh-validation")
            token = _extract_token_from_header(request)

            # Decode token
            try:
                identity = await decoder.decode(token)
                logger.info(
                    f"Decoded token for user '{identity.user_id}' "
                    f"from provider '{identity.provider}'"
                )
            except TokenInvalidError as e:
                logger.log_error(e)
                raise
            except TokenExpiredError as e:
                logger.log_error(e)
                raise
            except Exception as e:
                error = AuthError(f"Token decoding failed: {str(e)}")
                logger.log_error(error)
                raise error

            # Check if token is revoked (fail-closed: deny on check failure)
            try:
                if await decoder.is_revoked(token):
                    error = TokenRevokedError("Token has been revoked")
                    logger.log_error(error)
                    raise error
            except TokenRevokedError:
                raise
            except Exception as e:
                # Fail-closed: deny access on revocation check failure
                logger.log_error(Exception(f"Revocation check failed (fail-closed): {e}"))
                error = AuthError("Unable to verify token revocation status")
                logger.log_error(error)
                raise error

        # Phase 2: Resolve permissions (always, regardless of identity source).
        # AuthMiddleware validates authentication only; permission resolution
        # via PrivilegeResolver must always occur.
        # permissions_key uses CacheNamespace for hierarchical key format:
        # org:{org}:env:{env}:svc:{service}:app:{app}:{version}:{tenant_id}:{user_id}:permissions
        cache_key = permissions_key(namespace, identity.tenant_id, identity.user_id)
        try:
            resolved_permissions = await _resolve_and_cache_permissions(
                identity, resolver, cache, cache_key, cache_ttl
            )

            # Merge resolved permissions with identity's existing permissions
            merged_permissions = identity.permissions | resolved_permissions

            # Create new IdentityContext with merged permissions (Pydantic model)
            identity = identity.model_copy(update={"permissions": merged_permissions})

            logger.info(
                f"Resolved {len(resolved_permissions)} permissions for user '{identity.user_id}', "
                f"total: {len(merged_permissions)}"
            )
        except Exception as e:
            # Fail-closed: Deny access on permission resolution failure
            # This prevents stale permissions from being used when:
            # - Database is down
            # - External identity provider (LDAP, AD) is unreachable
            # - Resolver is misconfigured
            # - Backend service is unavailable
            error_msg = (
                f"Permission resolution failed for user '{identity.user_id}'. "
                f"Failing closed to prevent stale permission enforcement. "
                f"Error: {str(e)}"
            )
            logger.log_error(Exception(error_msg))
            logger.log_error(e)

            # Create AuthError to deny access
            error = AuthError(
                "Unable to resolve current permissions. Access denied for security."
            )
            raise error

        return identity

    return dependency


@auto_trace(logger)
def require_permission(
    permission: str,
    get_identity_dep: Callable,
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for permission check dependency.

    Creates a FastAPI dependency that checks if the identity has a specific
    permission. Raises PermissionDeniedError if not.

    Args:
        permission: Required permission string (e.g., "document:read")
        get_identity_dep: The get_identity dependency to use for identity extraction
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        @app.delete("/document/{id}")
        async def delete_doc(
            id: str,
            identity: IdentityContext = Depends(require_permission("document:delete", get_current_identity)),
        ):
            return {"deleted": id}
    """

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Check if identity has required permission.

        Args:
            request: FastAPI request object (for audit context)
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            PermissionDeniedError: If identity lacks permission
        """
        if permission not in identity.permissions:
            error = PermissionDeniedError(
                f"Permission '{permission}' required for user '{identity.user_id}'"
            )
            logger.log_error(error)

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type="permission",
                        resource_id=permission,
                        action="check",
                        outcome="denied",
                        reason=f"Missing permission: {permission}",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            raise error

        logger.debug(
            f"Permission '{permission}' granted for user '{identity.user_id}'"
        )

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type="permission",
                    resource_id=permission,
                    action="check",
                    outcome="allowed",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        return identity

    return dependency


@auto_trace(logger)
def require_role(
    role: str,
    get_identity_dep: Callable,
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for role check dependency.

    Creates a FastAPI dependency that checks if the identity has a specific
    role. Raises PermissionDeniedError if not.

    Args:
        role: Required role name (e.g., "admin")
        get_identity_dep: The get_identity dependency to use for identity extraction
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        @app.post("/admin/settings")
        async def update_settings(
            settings: dict,
            identity: IdentityContext = Depends(require_role("admin", get_current_identity)),
        ):
            return {"updated": True}
    """

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Check if identity has required role.

        Args:
            request: FastAPI request object (for audit context)
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            PermissionDeniedError: If identity lacks role
        """
        if role not in identity.roles:
            error = PermissionDeniedError(
                f"Role '{role}' required for user '{identity.user_id}'"
            )
            logger.log_error(error)

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type="role",
                        resource_id=role,
                        action="check",
                        outcome="denied",
                        reason=f"Missing role: {role}",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            raise error

        logger.debug(f"Role '{role}' granted for user '{identity.user_id}'")

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type="role",
                    resource_id=role,
                    action="check",
                    outcome="allowed",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        return identity

    return dependency


@auto_trace(logger)
def require_ownership(
    resolver: OwnershipResolver,
    resource_type: str,
    get_identity_dep: Callable,
    resource_id_param: str = "resource_id",
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for ownership check dependency.

    Creates a FastAPI dependency that checks if the identity owns the
    specified resource. Raises OwnershipRequiredError if not.

    Args:
        resolver: Ownership resolver instance
        resource_type: Type of resource (e.g., "document")
        get_identity_dep: The get_identity dependency to use for identity extraction
        resource_id_param: Name of path parameter containing resource ID
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        @app.put("/document/{doc_id}")
        async def update_doc(
            doc_id: str,
            identity: IdentityContext = Depends(
                require_ownership(resolver, "document", get_current_identity, "doc_id")
            ),
        ):
            return {"updated": doc_id}
    """

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Check if identity owns the resource.

        Args:
            request: FastAPI request object
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            OwnershipRequiredError: If identity is not owner
        """
        # Extract resource_id from path parameters
        resource_id = request.path_params.get(resource_id_param)
        if not resource_id:
            error = OwnershipRequiredError(
                f"Missing path parameter: {resource_id_param}"
            )
            logger.log_error(error)
            raise error

        # Check ownership
        owner_id = await resolver.get_owner(resource_type, resource_id)

        if owner_id != identity.user_id:
            error = OwnershipRequiredError(
                f"User '{identity.user_id}' is not owner of "
                f"{resource_type}:{resource_id}"
            )
            logger.log_error(error)

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        action="ownership_check",
                        outcome="denied",
                        reason=f"Not owner. Owner: {owner_id}",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            raise error

        logger.debug(
            f"User '{identity.user_id}' is owner of {resource_type}:{resource_id}"
        )

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action="ownership_check",
                    outcome="allowed",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        return identity

    return dependency


@auto_trace(logger)
def require_tenant_access(
    resolver: OwnershipResolver,
    resource_type: str,
    get_identity_dep: Callable,
    resource_id_param: str = "resource_id",
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for tenant access check dependency.

    Creates a FastAPI dependency that checks if the resource belongs to
    the identity's tenant. Raises TenantMismatchError if not.

    Args:
        resolver: Ownership resolver instance
        resource_type: Type of resource (e.g., "document")
        get_identity_dep: The get_identity dependency to use for identity extraction
        resource_id_param: Name of path parameter containing resource ID
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        @app.get("/document/{doc_id}")
        async def get_doc(
            doc_id: str,
            identity: IdentityContext = Depends(
                require_tenant_access(resolver, "document", get_current_identity, "doc_id")
            ),
        ):
            return {"document": doc_id}
    """

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Check if resource belongs to identity's tenant.

        Args:
            request: FastAPI request object
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            TenantMismatchError: If resource tenant doesn't match identity tenant
        """
        # Extract resource_id from path parameters
        resource_id = request.path_params.get(resource_id_param)
        if not resource_id:
            # Note: Using TenantMismatchError for missing parameter is semantically incorrect
            # but maintained for backward compatibility. Consider using ValidationError instead.
            error = TenantMismatchError(
                identity_tenant=identity.tenant_id,
                resource_tenant="unknown",
                message=f"Missing path parameter: {resource_id_param}"
            )
            logger.log_error(error)
            raise error

        # Check tenant
        resource_tenant = await resolver.get_tenant(resource_type, resource_id)

        if resource_tenant != identity.tenant_id:
            error = TenantMismatchError(
                identity_tenant=identity.tenant_id,
                resource_tenant=resource_tenant
            )
            logger.log_error(error)

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        action="tenant_check",
                        outcome="denied",
                        reason=f"Tenant mismatch. Resource tenant: {resource_tenant}",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            raise error

        logger.debug(
            f"Resource {resource_type}:{resource_id} belongs to tenant "
            f"'{identity.tenant_id}'"
        )

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action="tenant_check",
                    outcome="allowed",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        return identity

    return dependency


@auto_trace(logger)
def require_collaborator(
    resolver: OwnershipResolver,
    resource_type: str,
    get_identity_dep: Callable,
    resource_id_param: str = "resource_id",
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for collaborator check dependency.

    Creates a FastAPI dependency that checks if the identity is either
    the owner or a collaborator on the resource. Raises
    OwnershipRequiredError if neither.

    Args:
        resolver: Ownership resolver instance
        resource_type: Type of resource (e.g., "document")
        get_identity_dep: The get_identity dependency to use for identity extraction
        resource_id_param: Name of path parameter containing resource ID
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        @app.get("/document/{doc_id}")
        async def get_doc(
            doc_id: str,
            identity: IdentityContext = Depends(
                require_collaborator(resolver, "document", get_current_identity, "doc_id")
            ),
        ):
            return {"document": doc_id}
    """

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Check if identity is owner or collaborator.

        Args:
            request: FastAPI request object
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            OwnershipRequiredError: If identity is neither owner nor collaborator
        """
        # Extract resource_id from path parameters
        resource_id = request.path_params.get(resource_id_param)
        if not resource_id:
            error = OwnershipRequiredError(
                f"Missing path parameter: {resource_id_param}"
            )
            logger.log_error(error)
            raise error

        # Check ownership first
        owner_id = await resolver.get_owner(resource_type, resource_id)
        if owner_id == identity.user_id:
            logger.debug(
                f"User '{identity.user_id}' is owner of {resource_type}:{resource_id}"
            )

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        action="collaborator_check",
                        outcome="allowed",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            return identity

        # Check collaborators
        collaborators = await resolver.get_collaborators(
            resource_type, resource_id
        )
        if identity.user_id in collaborators:
            logger.debug(
                f"User '{identity.user_id}' is collaborator on "
                f"{resource_type}:{resource_id}"
            )

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        action="collaborator_check",
                        outcome="allowed",
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            return identity

        # Neither owner nor collaborator
        error = OwnershipRequiredError(
            f"User '{identity.user_id}' is not owner or collaborator on "
            f"{resource_type}:{resource_id}"
        )
        logger.log_error(error)

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action="collaborator_check",
                    outcome="denied",
                    reason="Not owner or collaborator",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        raise error

    return dependency


@auto_trace(logger)
def require_policy(
    evaluator: PolicyEvaluator,
    get_identity_dep: Callable,
    resource_attrs_getter: Callable,
    action: Optional[str] = None,
    audit: Optional[AuditLogger] = None,
) -> Callable:
    """Factory for ABAC policy check dependency.

    Creates a FastAPI dependency that evaluates an ABAC policy for the
    identity and resource. Raises PolicyDeniedError if policy denies.

    Args:
        evaluator: Policy evaluator instance
        get_identity_dep: The get_identity dependency to use for identity extraction
        resource_attrs_getter: Async callable to extract resource attributes
                               from request. Must return dict with 'type' key.
                               Required — policy evaluation without resource
                               context is meaningless.
        action: Action string for policy evaluation. If None, derived from
                HTTP method (GET->read, POST->create, PUT->update,
                PATCH->update, DELETE->delete).
        audit: Optional audit logger

    Returns:
        FastAPI dependency function

    Raises:
        PolicyDeniedError: If resource_attrs_getter fails (fail-closed)

    Example:
        get_current_identity = get_identity(decoder=decoder, resolver=resolver)

        async def get_doc_attrs(request: Request) -> Dict[str, Any]:
            doc_id = request.path_params["doc_id"]
            return {"type": "document", "sensitivity": "high", "owner": "alice"}

        @app.get("/document/{doc_id}")
        async def get_doc(
            doc_id: str,
            identity: IdentityContext = Depends(
                require_policy(evaluator, get_current_identity, get_doc_attrs)
            ),
        ):
            return {"document": doc_id}
    """
    # HTTP method to action mapping
    _METHOD_ACTION_MAP = {
        "GET": "read",
        "HEAD": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
        "OPTIONS": "read",
    }

    @auto_trace(logger)
    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity_dep),
    ) -> IdentityContext:
        """Evaluate ABAC policy for identity and resource.

        Args:
            request: FastAPI request object
            identity: Identity context from get_identity dependency

        Returns:
            Identity context if authorized

        Raises:
            PolicyDeniedError: If policy evaluation denies access
        """
        # Resolve action from explicit parameter or HTTP method
        resolved_action = action or _METHOD_ACTION_MAP.get(
            request.method.upper(), "read"
        )

        # Get resource attributes (fail-closed: deny on getter failure)
        try:
            resource_attrs = await resource_attrs_getter(request)
        except Exception as e:
            logger.log_error(Exception(f"Resource attributes getter failed (fail-closed): {e}"))
            error = PolicyDeniedError(
                f"Policy denied access for user '{identity.user_id}': "
                f"unable to resolve resource attributes"
            )
            logger.log_error(error)
            raise error

        # Evaluate policy — returns PolicyDecision, check .allowed field
        try:
            decision = await evaluator.evaluate(
                identity, resource_attrs, resolved_action
            )
        except Exception as e:
            logger.log_error(Exception(f"Policy evaluation failed (fail-closed): {e}"))
            # Fail closed: deny on evaluation error
            decision = None

        allowed = decision.allowed if decision is not None else False
        reason = decision.reason if decision is not None else "Evaluation failed"

        if not allowed:
            error = PolicyDeniedError(
                f"Policy denied access for user '{identity.user_id}': {reason}"
            )
            logger.log_error(error)

            if audit:
                try:
                    await audit.log_access(
                        identity=identity,
                        resource_type="policy",
                        resource_id="abac_evaluation",
                        action=resolved_action,
                        outcome="denied",
                        reason=reason,
                    )
                except Exception as e:
                    logger.log_error(Exception(f"Audit logging failed: {e}"))

            raise error

        logger.debug(f"Policy allowed access for user '{identity.user_id}'")

        if audit:
            try:
                await audit.log_access(
                    identity=identity,
                    resource_type="policy",
                    resource_id="abac_evaluation",
                    action=resolved_action,
                    outcome="allowed",
                )
            except Exception as e:
                logger.log_error(Exception(f"Audit logging failed: {e}"))

        return identity

    return dependency
