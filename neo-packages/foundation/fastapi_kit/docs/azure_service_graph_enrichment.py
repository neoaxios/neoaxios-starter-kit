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

"""Azure AD with Microsoft Graph API role enrichment example.

This advanced example demonstrates integrating Microsoft Graph API for:
- Group membership enrichment from Graph API
- Directory role mapping from Azure AD
- Token introspection with Graph enrichment
- Caching strategy for role data (reduces Graph API calls)
- Graceful degradation when Graph API is unavailable
- Performance monitoring for Graph API latency

Graph API Integration Benefits:
- Get group memberships not included in token (large group scenarios)
- Retrieve directory roles (Global Admin, User Admin, etc.)
- Enrich user profile with photo, manager, department
- Access organizational data for ABAC policies

Azure AD Configuration Required:
1. Register application in Azure AD portal
2. Configure API permissions for Microsoft Graph:
   - User.Read (for profile)
   - GroupMember.Read.All (for group memberships)
   - Directory.Read.All (for directory roles)
3. Grant admin consent for the permissions
4. Create a client secret for Graph API authentication

Environment Variables:
    AZURE_TENANT_ID: Your Azure AD tenant ID (required)
    AZURE_CLIENT_ID: Your Azure AD application (client) ID (required)
    AZURE_CLIENT_SECRET: Client secret for Graph API calls (required)
    AZURE_AUDIENCE: Expected audience (optional, defaults to client_id)
    GRAPH_API_ENABLED: Enable Graph API enrichment (default: true)
    GRAPH_CACHE_TTL: Cache TTL for Graph data in seconds (default: 300)
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)

Usage:
    # Set environment variables
    export AZURE_TENANT_ID=your-tenant-id
    export AZURE_CLIENT_ID=your-client-id
    export AZURE_CLIENT_SECRET=your-client-secret

    # Run the service
    python azure_service_graph_enrichment.py

Testing:
    # User profile (same as complete example)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/user/profile

    # User groups from Graph API
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/user/groups

    # User directory roles from Graph API
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/user/directory-roles

    # Graph API stats (admin only)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/admin/graph-stats

Microsoft Graph API Reference:
    - Group memberships: GET https://graph.microsoft.com/v1.0/me/memberOf
    - Directory roles: GET https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole
    - User profile: GET https://graph.microsoft.com/v1.0/me
"""

import asyncio
import os
import time
import threading
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import from neoaxios_fastapi_kit auth framework
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.oidc_cache import create_jwks_cache
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_logging import get_telemetry

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================


class GraphEnrichmentConfig:
    """Configuration for Graph API enrichment."""

    def __init__(self):
        """Load configuration from environment."""
        # Azure AD configuration
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.audience = os.getenv("AZURE_AUDIENCE")

        # Graph API configuration
        self.graph_enabled = os.getenv("GRAPH_API_ENABLED", "true").lower() == "true"
        self.graph_cache_ttl = int(os.getenv("GRAPH_CACHE_TTL", "300"))

        # Server configuration
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))

        # Validate
        self._validate()

        # Azure AD URLs
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        self.jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        # Graph API URL
        self.graph_base_url = "https://graph.microsoft.com/v1.0"

        logger.info(
            "Graph enrichment configuration loaded",
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            graph_enabled=self.graph_enabled,
            graph_cache_ttl=self.graph_cache_ttl,
        )

    def _validate(self) -> None:
        """Validate required configuration."""
        errors = []

        if not self.tenant_id:
            errors.append("AZURE_TENANT_ID is required")
        if not self.client_id:
            errors.append("AZURE_CLIENT_ID is required")
        if self.graph_enabled and not self.client_secret:
            errors.append("AZURE_CLIENT_SECRET is required when Graph API is enabled")

        if errors:
            error_msg = "\n".join(errors)
            logger.log_error(message=f"Configuration validation failed:\n{error_msg}")
            raise ValueError(f"Invalid configuration:\n{error_msg}")


# =============================================================================
# Graph API Client with Caching
# =============================================================================


class GraphAPIClient:
    """Microsoft Graph API client with caching and metrics.

    This client handles:
    - OAuth2 client credentials flow for Graph API authentication
    - Group membership retrieval
    - Directory role retrieval
    - Caching of Graph API responses
    - Performance metrics tracking
    - Graceful degradation on failures
    """

    def __init__(self, config: GraphEnrichmentConfig):
        self.config = config
        self._lock = threading.Lock()

        # OAuth2 token for Graph API
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0

        # In-memory cache for Graph data
        # Format: {user_id: {"groups": [...], "roles": [...], "expires_at": timestamp}}
        self._cache: Dict[str, Dict[str, Any]] = {}

        # Metrics
        self._total_requests: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._total_latency_ms: float = 0.0
        self._errors: int = 0
        self._last_error: Optional[str] = None

        logger.info("Graph API client initialized")

    async def _get_access_token(self) -> Optional[str]:
        """Get OAuth2 access token for Graph API using client credentials.

        Uses the OAuth2 client credentials flow:
        POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        grant_type=client_credentials
        client_id={client_id}
        client_secret={client_secret}
        scope=https://graph.microsoft.com/.default
        """
        # Check if current token is still valid
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.config.client_id,
                        "client_secret": self.config.client_secret,
                        "scope": "https://graph.microsoft.com/.default",
                    },
                )
                response.raise_for_status()

                token_data = response.json()
                self._access_token = token_data["access_token"]
                # Token typically valid for 1 hour
                self._token_expires_at = time.time() + token_data.get("expires_in", 3600)

                logger.info("Graph API access token acquired")
                return self._access_token

        except Exception as e:
            logger.log_error(error=e, message="Failed to acquire Graph API token")
            self._errors += 1
            self._last_error = str(e)
            return None

    async def get_user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user's group memberships from Graph API.

        Uses: GET https://graph.microsoft.com/v1.0/users/{user_id}/memberOf
        Requires: GroupMember.Read.All or Directory.Read.All permission

        Returns list of groups with id, displayName, and type.
        """
        if not self.config.graph_enabled:
            return []

        # Check cache
        cached = self._get_cached(user_id, "groups")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        self._total_requests += 1

        start_time = time.time()
        try:
            token = await self._get_access_token()
            if not token:
                return []  # Graceful degradation

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.config.graph_base_url}/users/{user_id}/memberOf",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"$select": "id,displayName,@odata.type"},
                )
                response.raise_for_status()

                data = response.json()
                groups = []
                for item in data.get("value", []):
                    # Filter to only groups (not roles)
                    odata_type = item.get("@odata.type", "")
                    if "group" in odata_type.lower():
                        groups.append({
                            "id": item.get("id"),
                            "displayName": item.get("displayName"),
                            "type": "group",
                        })

                # Cache the result
                self._set_cached(user_id, "groups", groups)

                elapsed_ms = (time.time() - start_time) * 1000
                self._total_latency_ms += elapsed_ms

                logger.info(
                    "Retrieved user groups from Graph API",
                    user_id=user_id,
                    group_count=len(groups),
                    latency_ms=round(elapsed_ms, 2),
                )

                return groups

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._total_latency_ms += elapsed_ms
            self._errors += 1
            self._last_error = str(e)
            logger.log_error(
                error=e,
                message="Failed to get user groups from Graph API",
                user_id=user_id,
            )
            return []  # Graceful degradation

    async def get_user_directory_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Get user's Azure AD directory roles from Graph API.

        Uses: GET https://graph.microsoft.com/v1.0/users/{user_id}/memberOf/microsoft.graph.directoryRole
        Requires: Directory.Read.All permission

        Returns list of directory roles (Global Admin, User Admin, etc.)
        """
        if not self.config.graph_enabled:
            return []

        # Check cache
        cached = self._get_cached(user_id, "directory_roles")
        if cached is not None:
            self._cache_hits += 1
            return cached

        self._cache_misses += 1
        self._total_requests += 1

        start_time = time.time()
        try:
            token = await self._get_access_token()
            if not token:
                return []  # Graceful degradation

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.config.graph_base_url}/users/{user_id}/memberOf/microsoft.graph.directoryRole",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"$select": "id,displayName,roleTemplateId"},
                )
                response.raise_for_status()

                data = response.json()
                roles = []
                for item in data.get("value", []):
                    roles.append({
                        "id": item.get("id"),
                        "displayName": item.get("displayName"),
                        "roleTemplateId": item.get("roleTemplateId"),
                        "type": "directoryRole",
                    })

                # Cache the result
                self._set_cached(user_id, "directory_roles", roles)

                elapsed_ms = (time.time() - start_time) * 1000
                self._total_latency_ms += elapsed_ms

                logger.info(
                    "Retrieved user directory roles from Graph API",
                    user_id=user_id,
                    role_count=len(roles),
                    latency_ms=round(elapsed_ms, 2),
                )

                return roles

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._total_latency_ms += elapsed_ms
            self._errors += 1
            self._last_error = str(e)
            logger.log_error(
                error=e,
                message="Failed to get user directory roles from Graph API",
                user_id=user_id,
            )
            return []  # Graceful degradation

    def _get_cached(self, user_id: str, data_type: str) -> Optional[List]:
        """Get cached data for user."""
        with self._lock:
            user_cache = self._cache.get(user_id)
            if not user_cache:
                return None

            expires_at = user_cache.get("expires_at", 0)
            if time.time() > expires_at:
                # Cache expired
                del self._cache[user_id]
                return None

            return user_cache.get(data_type)

    def _set_cached(self, user_id: str, data_type: str, data: List) -> None:
        """Set cached data for user."""
        with self._lock:
            if user_id not in self._cache:
                self._cache[user_id] = {
                    "expires_at": time.time() + self.config.graph_cache_ttl
                }
            self._cache[user_id][data_type] = data

    def get_stats(self) -> Dict[str, Any]:
        """Get Graph API client statistics."""
        with self._lock:
            total_cache_requests = self._cache_hits + self._cache_misses
            cache_hit_rate = (
                self._cache_hits / total_cache_requests if total_cache_requests > 0 else 0.0
            )
            avg_latency = (
                self._total_latency_ms / self._total_requests if self._total_requests > 0 else 0.0
            )

            return {
                "enabled": self.config.graph_enabled,
                "total_requests": self._total_requests,
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "cache_hit_rate": round(cache_hit_rate, 3),
                "average_latency_ms": round(avg_latency, 2),
                "errors": self._errors,
                "last_error": self._last_error,
                "cached_users": len(self._cache),
            }


# =============================================================================
# Response Models
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    version: str
    graph_api_enabled: bool


class UserProfileResponse(BaseModel):
    """User profile response."""

    user_id: str
    tenant_id: str
    provider: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str]
    permissions: List[str]


class UserGroupsResponse(BaseModel):
    """User groups from Graph API response."""

    user_id: str
    group_count: int
    groups: List[Dict[str, Any]]
    source: str  # 'graph_api' or 'cache'
    graph_available: bool


class UserDirectoryRolesResponse(BaseModel):
    """User directory roles from Graph API response."""

    user_id: str
    role_count: int
    directory_roles: List[Dict[str, Any]]
    source: str  # 'graph_api' or 'cache'
    graph_available: bool


class GraphStatsResponse(BaseModel):
    """Graph API statistics response."""

    enabled: bool
    total_requests: int
    cache_hits: int
    cache_misses: int
    cache_hit_rate: float
    average_latency_ms: float
    errors: int
    last_error: Optional[str]
    cached_users: int


class TokenIntrospectionResponse(BaseModel):
    """Token introspection with Graph enrichment response."""

    valid: bool
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    issuer: Optional[str] = None
    token_roles: List[str] = []
    graph_groups: List[str] = []
    graph_directory_roles: List[str] = []
    enrichment_successful: bool = False


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str
    error_code: str
    message: str


# =============================================================================
# Global State
# =============================================================================


config: Optional[GraphEnrichmentConfig] = None
azure_decoder: Optional[OIDCDecoder] = None
graph_client: Optional[GraphAPIClient] = None
security = HTTPBearer()


# =============================================================================
# Application Lifecycle
# =============================================================================


async def initialize_services() -> None:
    """Initialize services including Graph API client."""
    global config, azure_decoder, graph_client

    logger.info("Initializing Graph enrichment services")

    # Load configuration
    config = GraphEnrichmentConfig()

    # Create JWKS cache
    jwks_cache = create_jwks_cache(
        backend=None,
        default_ttl_seconds=86400,
    )

    # Create Azure AD decoder
    azure_decoder = OIDCDecoder(
        issuer=config.issuer,
        client_id=config.client_id,
        jwks_uri=config.jwks_uri,
        audience=config.audience or config.client_id,
        clock_skew_seconds=30,
        key_cache=jwks_cache,
    )

    # Create Graph API client
    graph_client = GraphAPIClient(config)

    logger.info("Graph enrichment services initialized successfully")


async def shutdown_services() -> None:
    """Cleanup services."""
    global azure_decoder, graph_client
    logger.info("Shutting down Graph enrichment services")
    azure_decoder = None
    graph_client = None


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
    title="Azure AD Graph Enrichment Example",
    description="Azure AD authentication with Microsoft Graph API role enrichment",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Dependencies
# =============================================================================


async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> IdentityContext:
    """Extract and validate identity from Azure AD token."""
    if not azure_decoder:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not available",
        )

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)
        logger.info(
            "Token validated",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
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


async def require_admin(
    identity: IdentityContext = Depends(get_current_identity),
) -> IdentityContext:
    """Require admin role for access."""
    admin_roles = {"Admin", "admin", "Administrator", "administrator"}
    if not identity.roles.intersection(admin_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return identity


# =============================================================================
# Routes
# =============================================================================


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="azure-ad-graph-enrichment-example",
        version="1.0.0",
        graph_api_enabled=config.graph_enabled if config else False,
    )


@app.get("/user/profile", response_model=UserProfileResponse, tags=["User"])
async def get_user_profile(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user profile from token."""
    return UserProfileResponse(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        provider=identity.provider,
        email=identity.attributes.get("email"),
        name=identity.attributes.get("name"),
        roles=sorted(identity.roles),
        permissions=sorted(identity.permissions),
    )


@app.get("/user/groups", response_model=UserGroupsResponse, tags=["User"])
async def get_user_groups(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get user's group memberships from Microsoft Graph API.

    This endpoint calls Microsoft Graph API to retrieve all group
    memberships for the user. Results are cached to reduce API calls.

    This is useful when:
    - The token doesn't include groups (large group scenario)
    - You need group details not in the token
    - Implementing group-based access control
    """
    if not graph_client:
        return UserGroupsResponse(
            user_id=identity.user_id,
            group_count=0,
            groups=[],
            source="unavailable",
            graph_available=False,
        )

    logger.info(
        "Fetching user groups from Graph API",
        user_id=identity.user_id,
    )

    groups = await graph_client.get_user_groups(identity.user_id)

    return UserGroupsResponse(
        user_id=identity.user_id,
        group_count=len(groups),
        groups=groups,
        source="graph_api",
        graph_available=True,
    )


@app.get("/user/directory-roles", response_model=UserDirectoryRolesResponse, tags=["User"])
async def get_user_directory_roles(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get user's Azure AD directory roles from Microsoft Graph API.

    Directory roles include:
    - Global Administrator
    - User Administrator
    - Application Administrator
    - Security Administrator
    - etc.

    These roles are typically not included in tokens and must be
    fetched via Graph API for fine-grained admin access control.
    """
    if not graph_client:
        return UserDirectoryRolesResponse(
            user_id=identity.user_id,
            role_count=0,
            directory_roles=[],
            source="unavailable",
            graph_available=False,
        )

    logger.info(
        "Fetching user directory roles from Graph API",
        user_id=identity.user_id,
    )

    roles = await graph_client.get_user_directory_roles(identity.user_id)

    return UserDirectoryRolesResponse(
        user_id=identity.user_id,
        role_count=len(roles),
        directory_roles=roles,
        source="graph_api",
        graph_available=True,
    )


@app.get("/admin/graph-stats", response_model=GraphStatsResponse, tags=["Admin"])
async def get_graph_stats(
    identity: IdentityContext = Depends(require_admin),
):
    """Get Microsoft Graph API performance statistics (admin only).

    Returns metrics including:
    - Total API requests
    - Cache hit/miss rates
    - Average latency
    - Error counts
    """
    if not graph_client:
        return GraphStatsResponse(
            enabled=False,
            total_requests=0,
            cache_hits=0,
            cache_misses=0,
            cache_hit_rate=0.0,
            average_latency_ms=0.0,
            errors=0,
            last_error=None,
            cached_users=0,
        )

    logger.info(
        "Graph stats requested",
        user_id=identity.user_id,
    )

    stats = graph_client.get_stats()
    return GraphStatsResponse(**stats)


@app.post("/token/introspect", response_model=TokenIntrospectionResponse, tags=["Token"])
async def introspect_token_with_enrichment(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Introspect token with Graph API enrichment.

    This endpoint:
    1. Validates the Azure AD token
    2. Extracts roles from the token
    3. Enriches with group memberships from Graph API
    4. Enriches with directory roles from Graph API

    Returns combined authorization information from both
    the token and Graph API.
    """
    if not azure_decoder:
        return TokenIntrospectionResponse(valid=False)

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)

        # Get enrichment from Graph API
        graph_groups: List[str] = []
        graph_directory_roles: List[str] = []
        enrichment_successful = False

        if graph_client and config and config.graph_enabled:
            try:
                # Fetch groups and roles in parallel
                groups_task = graph_client.get_user_groups(identity.user_id)
                roles_task = graph_client.get_user_directory_roles(identity.user_id)

                groups_data, roles_data = await asyncio.gather(
                    groups_task, roles_task,
                    return_exceptions=True
                )

                if isinstance(groups_data, list):
                    graph_groups = [g.get("displayName", "") for g in groups_data if g.get("displayName")]
                if isinstance(roles_data, list):
                    graph_directory_roles = [r.get("displayName", "") for r in roles_data if r.get("displayName")]

                enrichment_successful = True

            except Exception as e:
                logger.log_error(error=e, message="Graph enrichment failed during introspection")

        return TokenIntrospectionResponse(
            valid=True,
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            issuer=identity.issuer,
            token_roles=sorted(identity.roles),
            graph_groups=sorted(graph_groups),
            graph_directory_roles=sorted(graph_directory_roles),
            enrichment_successful=enrichment_successful,
        )

    except (TokenInvalidError, TokenExpiredError):
        return TokenIntrospectionResponse(valid=False)


# =============================================================================
# Error Handlers
# =============================================================================


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
        startup_config = GraphEnrichmentConfig()
    except ValueError as e:
        logger.log_error(error=e, message="Failed to start service")
        raise SystemExit(1)

    logger.info(
        "Starting Graph Enrichment service",
        host=startup_config.host,
        port=startup_config.port,
        graph_enabled=startup_config.graph_enabled,
    )

    uvicorn.run(
        "azure_service_graph_enrichment:app",
        host=startup_config.host,
        port=startup_config.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
