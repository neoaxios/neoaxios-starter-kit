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

"""Multi-tenant Azure AD SaaS application example.

This example demonstrates a complete multi-tenant SaaS application with:
- Multi-tenant Azure AD configuration (accepts tokens from any tenant)
- Per-tenant data isolation with mock database
- Tenant extraction and validation from tokens
- Tenant-scoped database queries
- Tenant-scoped logging for debugging
- Multi-tenant specific error handling
- Tenant registration workflow
- Concurrent request handling across tenants
- Security verification for tenant isolation

Azure AD Multi-Tenant Configuration:
1. Register application as multi-tenant in Azure AD portal
   (Supported account types: Accounts in any organizational directory)
2. Use 'common' or 'organizations' as tenant ID for JWKS/issuer
3. Handle dynamic tenant IDs from incoming tokens

Multi-Tenant Security Considerations:
- Never allow cross-tenant data access
- Always validate tenant_id from token
- Log tenant_id on all operations for audit
- Use separate encryption keys per tenant (if using encryption)
- Implement tenant allowlist if restricting access

Environment Variables:
    AZURE_CLIENT_ID: Your Azure AD application (client) ID (required)
    AZURE_AUDIENCE: Expected audience (optional, defaults to client_id)
    ALLOWED_TENANTS: Comma-separated list of allowed tenant IDs (optional)
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)

Usage:
    # Set environment variables
    export AZURE_CLIENT_ID=your-client-id

    # Optionally restrict to specific tenants
    export ALLOWED_TENANTS=tenant-id-1,tenant-id-2

    # Run the service
    python azure_service_multitenant.py

Testing:
    # Register a tenant (for demo purposes)
    curl -X POST http://localhost:8000/register \
        -H "Content-Type: application/json" \
        -d '{"tenant_id": "your-tenant-id", "name": "Acme Corp"}'

    # Get tenant configuration (requires token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/tenant/config

    # Get tenant data (requires token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/tenant/data

    # List tenant users (requires token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/tenant/users

    # Add tenant user (requires token)
    curl -X POST -H "Authorization: Bearer TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"user_id": "user-123", "email": "user@example.com", "name": "John Doe"}' \
        http://localhost:8000/tenant/users

    # Remove tenant user (requires token)
    curl -X DELETE -H "Authorization: Bearer TOKEN" \
        http://localhost:8000/tenant/users/user-123
"""

import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import from neoaxios_fastapi_kit auth framework
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.authz.errors import TenantMismatchError
from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_logging import get_telemetry

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================


class MultiTenantConfig:
    """Multi-tenant Azure AD configuration.

    For multi-tenant apps:
    - Use 'common' endpoint for JWKS (accepts tokens from any Azure AD tenant)
    - Use 'organizations' if only accepting organizational accounts
    - Use 'consumers' if only accepting Microsoft accounts (MSA)

    The actual tenant ID comes from the token's 'tid' claim.
    """

    def __init__(self):
        """Load multi-tenant configuration."""
        # Required configuration
        self.client_id = os.getenv("AZURE_CLIENT_ID")

        # Optional configuration
        self.audience = os.getenv("AZURE_AUDIENCE")
        allowed_tenants_env = os.getenv("ALLOWED_TENANTS", "")
        self.allowed_tenants: Optional[Set[str]] = None
        if allowed_tenants_env:
            self.allowed_tenants = set(t.strip() for t in allowed_tenants_env.split(",") if t.strip())

        # Server configuration
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))

        # Validate
        self._validate()

        # Multi-tenant Azure AD URLs using 'common' endpoint
        # This accepts tokens from any Azure AD tenant
        self.issuer_pattern = "https://login.microsoftonline.com/{tenant}/v2.0"
        self.jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

        logger.info(
            "Multi-tenant configuration loaded",
            client_id=self.client_id,
            allowed_tenants=list(self.allowed_tenants) if self.allowed_tenants else "all",
            jwks_uri=self.jwks_uri,
        )

    def _validate(self) -> None:
        """Validate required configuration."""
        if not self.client_id:
            raise ValueError("AZURE_CLIENT_ID environment variable is required")

    def is_tenant_allowed(self, tenant_id: str) -> bool:
        """Check if tenant is in allowlist (if configured)."""
        if self.allowed_tenants is None:
            return True  # No restriction, all tenants allowed
        return tenant_id in self.allowed_tenants


# =============================================================================
# Mock Database (Per-Tenant Data Isolation)
# =============================================================================


class TenantDatabase:
    """Thread-safe mock database with per-tenant data isolation.

    In a real application, this would be replaced with actual database
    queries that always include tenant_id in WHERE clauses.

    Data Structure:
    {
        "tenant-1": {
            "config": {"name": "Tenant 1", ...},
            "users": [{"user_id": "...", ...}],
            "data": [{"id": "...", ...}]
        }
    }
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._tenants: Dict[str, Dict[str, Any]] = {}

    def register_tenant(self, tenant_id: str, name: str, settings: Optional[Dict] = None) -> Dict[str, Any]:
        """Register a new tenant with initial configuration."""
        with self._lock:
            if tenant_id in self._tenants:
                raise ValueError(f"Tenant {tenant_id} already registered")

            self._tenants[tenant_id] = {
                "config": {
                    "tenant_id": tenant_id,
                    "name": name,
                    "settings": settings or {},
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                "users": [],
                "data": [
                    # Sample data for new tenants
                    {"id": "item-1", "name": "Welcome Item", "created_by": "system"},
                ],
            }

            logger.info(
                "Tenant registered",
                tenant_id=tenant_id,
                name=name,
            )

            return self._tenants[tenant_id]["config"]

    def get_tenant_config(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant configuration (returns None if not found)."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            return tenant["config"] if tenant else None

    def get_tenant_data(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all data for a specific tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            return list(tenant["data"]) if tenant else []

    def get_tenant_users(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all users for a specific tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            return list(tenant["users"]) if tenant else []

    def add_tenant_user(
        self,
        tenant_id: str,
        user_id: str,
        email: str,
        name: str,
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a user to a tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if not tenant:
                raise ValueError(f"Tenant {tenant_id} not found")

            # Check if user already exists
            for user in tenant["users"]:
                if user["user_id"] == user_id:
                    raise ValueError(f"User {user_id} already exists in tenant")

            user_data = {
                "user_id": user_id,
                "email": email,
                "name": name,
                "roles": roles or [],
                "added_at": datetime.now(timezone.utc).isoformat(),
            }
            tenant["users"].append(user_data)

            logger.info(
                "User added to tenant",
                tenant_id=tenant_id,
                user_id=user_id,
            )

            return user_data

    def remove_tenant_user(self, tenant_id: str, user_id: str) -> bool:
        """Remove a user from a tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if not tenant:
                return False

            original_count = len(tenant["users"])
            tenant["users"] = [u for u in tenant["users"] if u["user_id"] != user_id]
            removed = len(tenant["users"]) < original_count

            if removed:
                logger.info(
                    "User removed from tenant",
                    tenant_id=tenant_id,
                    user_id=user_id,
                )

            return removed

    def tenant_exists(self, tenant_id: str) -> bool:
        """Check if tenant exists."""
        with self._lock:
            return tenant_id in self._tenants


# =============================================================================
# Response Models
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    version: str
    multi_tenant: bool = True
    registered_tenants: int


class TenantRegistrationRequest(BaseModel):
    """Tenant registration request."""

    tenant_id: str = Field(..., min_length=1, description="Azure AD tenant ID")
    name: str = Field(..., min_length=1, description="Organization name")
    settings: Optional[Dict[str, Any]] = Field(default=None, description="Optional settings")


class TenantRegistrationResponse(BaseModel):
    """Tenant registration response."""

    status: str
    tenant_id: str
    name: str
    created_at: str


class TenantConfigResponse(BaseModel):
    """Tenant configuration response."""

    tenant_id: str
    name: str
    settings: Dict[str, Any]
    created_at: str


class TenantDataResponse(BaseModel):
    """Tenant data response."""

    tenant_id: str
    item_count: int
    items: List[Dict[str, Any]]


class TenantUserRequest(BaseModel):
    """Add tenant user request."""

    user_id: str = Field(..., min_length=1)
    email: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    roles: Optional[List[str]] = None


class TenantUserResponse(BaseModel):
    """Tenant user response."""

    user_id: str
    email: str
    name: str
    roles: List[str]
    added_at: str


class TenantUsersResponse(BaseModel):
    """List of tenant users response."""

    tenant_id: str
    user_count: int
    users: List[TenantUserResponse]


class DeleteUserResponse(BaseModel):
    """Delete user response."""

    status: str
    user_id: str
    message: str


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str
    error_code: str
    message: str
    tenant_id: Optional[str] = None


# =============================================================================
# Global State
# =============================================================================


config: Optional[MultiTenantConfig] = None
azure_decoder: Optional[OIDCDecoder] = None
tenant_db: Optional[TenantDatabase] = None
security = HTTPBearer()


# =============================================================================
# Application Lifecycle
# =============================================================================


async def initialize_services() -> None:
    """Initialize multi-tenant services."""
    global config, azure_decoder, tenant_db

    logger.info("Initializing multi-tenant Azure AD services")

    # Initialize database
    tenant_db = TenantDatabase()

    # Load configuration
    config = MultiTenantConfig()

    # Create multi-tenant Azure AD decoder
    # Note: For multi-tenant, we use 'common' JWKS endpoint
    # The issuer in tokens will vary by tenant, so we configure
    # the decoder to accept tokens from the common endpoint
    # In practice, you may need a custom decoder that validates
    # the issuer format matches the Azure AD pattern
    azure_decoder = OIDCDecoder(
        issuer="https://login.microsoftonline.com/common/v2.0",
        client_id=config.client_id,
        jwks_uri=config.jwks_uri,
        audience=config.audience or config.client_id,
        clock_skew_seconds=30,
    )

    logger.info("Multi-tenant services initialized successfully")


async def shutdown_services() -> None:
    """Cleanup services."""
    global azure_decoder, tenant_db
    logger.info("Shutting down multi-tenant services")
    azure_decoder = None
    tenant_db = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await initialize_services()
    yield
    await shutdown_services()


# =============================================================================
# FastAPI Application
# =============================================================================


app = FastAPI(
    title="Multi-Tenant Azure AD SaaS Example",
    description="Multi-tenant SaaS application with per-tenant data isolation",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Dependencies
# =============================================================================


async def get_current_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> IdentityContext:
    """Extract and validate identity from Azure AD token.

    For multi-tenant apps, this also:
    1. Extracts the tenant ID from the token ('tid' claim)
    2. Validates tenant is in allowlist (if configured)
    3. Logs with tenant context for debugging
    """
    if not azure_decoder:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not available",
        )

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)

        # Azure AD includes tenant ID in the 'tid' claim
        # The IdentityContext maps this to tenant_id
        azure_tenant_id = identity.tenant_id

        # Validate tenant is allowed (if allowlist is configured)
        if config and not config.is_tenant_allowed(azure_tenant_id):
            logger.log_error(
                message="Tenant not allowed",
                tenant_id=azure_tenant_id,
                user_id=identity.user_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Tenant {azure_tenant_id} is not authorized to use this service",
            )

        # Log with tenant context
        logger.info(
            "Multi-tenant token validated",
            user_id=identity.user_id,
            tenant_id=azure_tenant_id,
            roles=list(identity.roles),
        )

        return identity

    except TokenExpiredError:
        logger.log_error(message="Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except TokenInvalidError as e:
        logger.log_error(error=e, message="Token validation failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def ensure_tenant_registered(
    identity: IdentityContext = Depends(get_current_identity),
) -> IdentityContext:
    """Ensure the tenant is registered before allowing access.

    This dependency can be used to enforce tenant registration
    before accessing tenant-specific resources.
    """
    if not tenant_db:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )

    if not tenant_db.tenant_exists(identity.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant {identity.tenant_id} not registered. Please register first.",
        )

    return identity


def verify_tenant_isolation(requested_tenant_id: str, identity: IdentityContext) -> None:
    """Verify user is accessing their own tenant's data.

    This is a critical security function that prevents cross-tenant access.
    Call this before any data operation to ensure tenant isolation.

    Args:
        requested_tenant_id: The tenant ID being accessed
        identity: The authenticated user's identity

    Raises:
        TenantMismatchError: If tenant IDs don't match
    """
    if requested_tenant_id != identity.tenant_id:
        logger.log_error(
            message="Cross-tenant access attempt blocked",
            requested_tenant_id=requested_tenant_id,
            user_tenant_id=identity.tenant_id,
            user_id=identity.user_id,
        )
        raise TenantMismatchError(
            f"Access denied: Cannot access tenant {requested_tenant_id} data"
        )


# =============================================================================
# Routes
# =============================================================================


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    registered_count = 0
    if tenant_db:
        # Count registered tenants (in real app, use a proper count query)
        registered_count = len(tenant_db._tenants)

    return HealthResponse(
        status="healthy",
        service="multi-tenant-azure-ad-example",
        version="1.0.0",
        multi_tenant=True,
        registered_tenants=registered_count,
    )


@app.post("/register", response_model=TenantRegistrationResponse, tags=["Registration"])
async def register_tenant(request: TenantRegistrationRequest):
    """Register a new tenant (for demo purposes).

    In production, tenant registration would typically:
    1. Require admin consent from the tenant's Azure AD admin
    2. Create provisioning records in your system
    3. Set up tenant-specific resources (database schema, storage, etc.)

    This endpoint is simplified for demonstration.
    """
    if not tenant_db:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )

    try:
        tenant_config = tenant_db.register_tenant(
            tenant_id=request.tenant_id,
            name=request.name,
            settings=request.settings,
        )

        return TenantRegistrationResponse(
            status="registered",
            tenant_id=tenant_config["tenant_id"],
            name=tenant_config["name"],
            created_at=tenant_config["created_at"],
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@app.get("/tenant/config", response_model=TenantConfigResponse, tags=["Tenant"])
async def get_tenant_config(
    identity: IdentityContext = Depends(ensure_tenant_registered),
):
    """Get current tenant's configuration.

    The tenant ID is extracted from the Azure AD token,
    ensuring users can only access their own tenant's config.
    """
    logger.info(
        "Tenant config requested",
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
    )

    config_data = tenant_db.get_tenant_config(identity.tenant_id)
    if not config_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant configuration not found",
        )

    return TenantConfigResponse(
        tenant_id=config_data["tenant_id"],
        name=config_data["name"],
        settings=config_data["settings"],
        created_at=config_data["created_at"],
    )


@app.get("/tenant/data", response_model=TenantDataResponse, tags=["Tenant"])
async def get_tenant_data(
    identity: IdentityContext = Depends(ensure_tenant_registered),
):
    """Get tenant-scoped data.

    All data queries are automatically scoped to the authenticated
    user's tenant, preventing cross-tenant data access.
    """
    logger.info(
        "Tenant data requested",
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
    )

    # Data is automatically scoped by tenant_id from the token
    items = tenant_db.get_tenant_data(identity.tenant_id)

    return TenantDataResponse(
        tenant_id=identity.tenant_id,
        item_count=len(items),
        items=items,
    )


@app.get("/tenant/users", response_model=TenantUsersResponse, tags=["Tenant"])
async def get_tenant_users(
    identity: IdentityContext = Depends(ensure_tenant_registered),
):
    """Get all users in the current tenant."""
    logger.info(
        "Tenant users requested",
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
    )

    users = tenant_db.get_tenant_users(identity.tenant_id)

    return TenantUsersResponse(
        tenant_id=identity.tenant_id,
        user_count=len(users),
        users=[TenantUserResponse(**u) for u in users],
    )


@app.post("/tenant/users", response_model=TenantUserResponse, tags=["Tenant"])
async def add_tenant_user(
    request: TenantUserRequest,
    identity: IdentityContext = Depends(ensure_tenant_registered),
):
    """Add a user to the current tenant."""
    logger.info(
        "Adding user to tenant",
        tenant_id=identity.tenant_id,
        added_by=identity.user_id,
        new_user_id=request.user_id,
    )

    try:
        user = tenant_db.add_tenant_user(
            tenant_id=identity.tenant_id,
            user_id=request.user_id,
            email=request.email,
            name=request.name,
            roles=request.roles,
        )

        return TenantUserResponse(**user)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@app.delete("/tenant/users/{user_id}", response_model=DeleteUserResponse, tags=["Tenant"])
async def remove_tenant_user(
    user_id: str,
    identity: IdentityContext = Depends(ensure_tenant_registered),
):
    """Remove a user from the current tenant."""
    logger.info(
        "Removing user from tenant",
        tenant_id=identity.tenant_id,
        removed_by=identity.user_id,
        user_id=user_id,
    )

    removed = tenant_db.remove_tenant_user(identity.tenant_id, user_id)

    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found in tenant",
        )

    return DeleteUserResponse(
        status="deleted",
        user_id=user_id,
        message="User removed from tenant",
    )


# =============================================================================
# Security Verification Endpoint (for testing)
# =============================================================================


@app.get("/tenant/verify-isolation", tags=["Security"])
async def verify_isolation_endpoint(
    target_tenant_id: str,
    identity: IdentityContext = Depends(get_current_identity),
):
    """Test endpoint to verify tenant isolation is enforced.

    This endpoint demonstrates that cross-tenant access is blocked.
    Attempting to access another tenant's ID will result in 404 Not Found
    to prevent resource enumeration.

    Args:
        target_tenant_id: The tenant ID to try to access
        identity: Current user's identity

    Returns:
        Success message if accessing own tenant, 404 if cross-tenant
    """
    try:
        verify_tenant_isolation(target_tenant_id, identity)
        return {
            "status": "verified",
            "message": "Tenant isolation check passed",
            "your_tenant_id": identity.tenant_id,
            "requested_tenant_id": target_tenant_id,
        }
    except TenantMismatchError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# =============================================================================
# Error Handlers
# =============================================================================


@app.exception_handler(TenantMismatchError)
async def handle_tenant_mismatch(request: Request, exc: TenantMismatchError):
    """Handle tenant mismatch errors (cross-tenant access attempts).

    Returns 404 (not 403) to prevent resource enumeration.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="tenant_mismatch",
            error_code="TENANT_MISMATCH",
            message=str(exc),
        ).model_dump(),
    )


@app.exception_handler(TokenInvalidError)
async def handle_invalid_token(request: Request, exc: TokenInvalidError):
    """Handle invalid token errors."""
    return JSONResponse(
        status_code=401,
        content=ErrorResponse(
            error="invalid_token",
            error_code="TOKEN_INVALID",
            message=str(exc),
        ).model_dump(),
    )


@app.exception_handler(TokenExpiredError)
async def handle_expired_token(request: Request, exc: TokenExpiredError):
    """Handle expired token errors."""
    return JSONResponse(
        status_code=401,
        content=ErrorResponse(
            error="token_expired",
            error_code="TOKEN_EXPIRED",
            message=str(exc),
        ).model_dump(),
    )


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Run the FastAPI service."""
    import uvicorn

    try:
        startup_config = MultiTenantConfig()
    except ValueError as e:
        logger.log_error(error=e, message="Failed to start service")
        raise SystemExit(1)

    logger.info(
        "Starting Multi-Tenant Azure AD SaaS service",
        host=startup_config.host,
        port=startup_config.port,
    )

    uvicorn.run(
        "azure_service_multitenant:app",
        host=startup_config.host,
        port=startup_config.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
