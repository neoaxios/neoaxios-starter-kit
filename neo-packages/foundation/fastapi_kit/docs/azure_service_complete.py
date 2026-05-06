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

"""Complete Azure AD authentication example with all features.

This comprehensive example demonstrates a full-featured Azure AD integration:
- Complete Azure AD OIDC decoder configuration
- JWKS caching for performance optimization
- Role-based access control (RBAC)
- Token introspection and validation endpoints
- Request context with user logging
- Comprehensive error handling
- Health check with dependency status
- Configuration via YAML file with environment override
- Performance metrics logging
- Proper CORS handling

This example serves as a production-ready template for building
Azure AD authenticated APIs.

Azure AD Configuration Required:
1. Register an application in Azure AD portal
2. Configure App Roles for RBAC (Settings > App Roles)
3. Assign users to roles in Enterprise Applications
4. Configure API permissions as needed
5. Note tenant ID, client ID, and optionally client secret

Environment Variables:
    AZURE_TENANT_ID: Your Azure AD tenant ID (required)
    AZURE_CLIENT_ID: Your Azure AD application (client) ID (required)
    AZURE_AUDIENCE: Expected audience (optional, defaults to client_id)
    CONFIG_PATH: Path to YAML config file (optional)
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)
    LOG_LEVEL: Logging level (default: INFO)
    CORS_ORIGINS: Comma-separated allowed origins (default: *)

Usage:
    # Set environment variables
    export AZURE_TENANT_ID=your-tenant-id
    export AZURE_CLIENT_ID=your-client-id

    # Run the service
    python azure_service_complete.py

Testing:
    # Health check with auth system status
    curl http://localhost:8000/health

    # Public landing page
    curl http://localhost:8000/

    # User profile (requires valid token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/user/profile

    # User roles (requires valid token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/user/roles

    # Admin stats (requires 'Admin' role in token)
    curl -H "Authorization: Bearer TOKEN" http://localhost:8000/admin/stats

    # Validate token (for debugging)
    curl -X POST -H "Authorization: Bearer TOKEN" http://localhost:8000/token/validate

    # Logout placeholder
    curl -X POST -H "Authorization: Bearer TOKEN" http://localhost:8000/logout
"""

import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import from neoaxios_fastapi_kit auth framework
from neoaxios_fastapi_kit import add_cors_config
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


class AzureADCompleteConfig:
    """Complete Azure AD configuration with YAML file support.

    Configuration is loaded in the following order (later overrides earlier):
    1. Default values
    2. YAML configuration file (if CONFIG_PATH is set)
    3. Environment variables

    This follows a predictable configuration discovery order.
    """

    def __init__(self):
        """Load configuration from YAML and environment."""
        # Start with defaults
        self._config: Dict[str, Any] = {
            "azure": {
                "tenant_id": None,
                "client_id": None,
                "audience": None,
                "clock_skew_seconds": 30,
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "log_level": "INFO",
            },
            "cors": {
                "allowed_origins": ["*"],
                "allowed_methods": ["*"],
                "allowed_headers": ["*"],
            },
            "cache": {
                "jwks_ttl_seconds": 86400,  # 24 hours
                "enabled": True,
            },
        }

        # Load from YAML file if specified
        config_path = os.getenv("CONFIG_PATH")
        if config_path:
            self._load_yaml_config(config_path)

        # Override with environment variables
        self._load_env_overrides()

        # Validate required configuration
        self._validate()

        # Construct Azure AD URLs
        self._construct_urls()

        logger.info(
            "Azure AD Complete configuration loaded",
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            issuer=self.issuer,
            cache_enabled=self.cache_enabled,
        )

    def _load_yaml_config(self, config_path: str) -> None:
        """Load configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return

        with open(path) as f:
            yaml_config = yaml.safe_load(f)

        if yaml_config:
            self._deep_merge(self._config, yaml_config)
            logger.info(f"Loaded configuration from {config_path}")

    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge override into base configuration."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _load_env_overrides(self) -> None:
        """Override configuration with environment variables."""
        # Azure configuration
        if tenant_id := os.getenv("AZURE_TENANT_ID"):
            self._config["azure"]["tenant_id"] = tenant_id
        if client_id := os.getenv("AZURE_CLIENT_ID"):
            self._config["azure"]["client_id"] = client_id
        if audience := os.getenv("AZURE_AUDIENCE"):
            self._config["azure"]["audience"] = audience

        # Server configuration
        if host := os.getenv("HOST"):
            self._config["server"]["host"] = host
        if port := os.getenv("PORT"):
            self._config["server"]["port"] = int(port)
        if log_level := os.getenv("LOG_LEVEL"):
            self._config["server"]["log_level"] = log_level

        # CORS configuration
        if cors_origins := os.getenv("CORS_ORIGINS"):
            self._config["cors"]["allowed_origins"] = cors_origins.split(",")

    def _validate(self) -> None:
        """Validate required configuration is present."""
        errors = []

        if not self._config["azure"]["tenant_id"]:
            errors.append("AZURE_TENANT_ID is required")
        if not self._config["azure"]["client_id"]:
            errors.append("AZURE_CLIENT_ID is required")

        if errors:
            error_msg = "\n".join(errors)
            logger.log_error(message=f"Configuration validation failed:\n{error_msg}")
            raise ValueError(f"Invalid configuration:\n{error_msg}")

    def _construct_urls(self) -> None:
        """Construct Azure AD endpoint URLs."""
        tenant_id = self._config["azure"]["tenant_id"]
        self._issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self._jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"

    # Property accessors
    @property
    def tenant_id(self) -> str:
        return self._config["azure"]["tenant_id"]

    @property
    def client_id(self) -> str:
        return self._config["azure"]["client_id"]

    @property
    def audience(self) -> Optional[str]:
        return self._config["azure"]["audience"] or self.client_id

    @property
    def clock_skew_seconds(self) -> int:
        return self._config["azure"]["clock_skew_seconds"]

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def jwks_uri(self) -> str:
        return self._jwks_uri

    @property
    def host(self) -> str:
        return self._config["server"]["host"]

    @property
    def port(self) -> int:
        return self._config["server"]["port"]

    @property
    def log_level(self) -> str:
        return self._config["server"]["log_level"].lower()

    @property
    def cors_origins(self) -> list:
        return self._config["cors"]["allowed_origins"]

    @property
    def cors_methods(self) -> list:
        return self._config["cors"]["allowed_methods"]

    @property
    def cors_headers(self) -> list:
        return self._config["cors"]["allowed_headers"]

    @property
    def jwks_ttl_seconds(self) -> int:
        return self._config["cache"]["jwks_ttl_seconds"]

    @property
    def cache_enabled(self) -> bool:
        return self._config["cache"]["enabled"]


# =============================================================================
# Response Models
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response with dependency status."""

    status: str
    service: str
    version: str
    timestamp: str
    auth_system: str  # 'ready' or 'unavailable'
    uptime_seconds: float


class LandingResponse(BaseModel):
    """Public landing page response."""

    message: str
    version: str
    documentation: str
    endpoints: Dict[str, str]


class UserProfileResponse(BaseModel):
    """User profile response with Azure AD claims."""

    user_id: str
    tenant_id: str
    provider: str
    email: Optional[str] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    roles: list[str]
    permissions: list[str]


class UserRolesResponse(BaseModel):
    """User roles response."""

    user_id: str
    roles: list[str]
    permissions: list[str]
    is_admin: bool


class AdminStatsResponse(BaseModel):
    """Admin-only statistics response."""

    total_requests: int
    authenticated_requests: int
    failed_auth_attempts: int
    average_response_ms: float
    cache_hit_rate: float


class TokenValidationResponse(BaseModel):
    """Token validation details response."""

    valid: bool
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    roles: list[str] = []
    expires_at: Optional[str] = None
    issued_at: Optional[str] = None


class LogoutResponse(BaseModel):
    """Logout response."""

    status: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    error_code: str
    message: str
    request_id: Optional[str] = None


# =============================================================================
# Application State
# =============================================================================


class AppState:
    """Application state container for metrics and lifecycle."""

    def __init__(self):
        self.start_time: datetime = datetime.now(timezone.utc)
        self.total_requests: int = 0
        self.authenticated_requests: int = 0
        self.failed_auth_attempts: int = 0
        self.total_response_time_ms: float = 0.0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()

    @property
    def average_response_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_response_time_ms / self.total_requests

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0.0
        return self.cache_hits / total


# Global state
config: Optional[AzureADCompleteConfig] = None
azure_decoder: Optional[OIDCDecoder] = None
app_state: Optional[AppState] = None
security = HTTPBearer()


# =============================================================================
# Application Lifecycle
# =============================================================================


async def initialize_services() -> None:
    """Initialize all services on startup."""
    global config, azure_decoder, app_state

    logger.info("Initializing Azure AD Complete services")

    # Initialize application state
    app_state = AppState()

    # Load configuration
    config = AzureADCompleteConfig()

    # Create JWKS cache if caching is enabled
    jwks_cache = None
    if config.cache_enabled:
        jwks_cache = create_jwks_cache(
            backend=None,  # In-memory cache
            default_ttl_seconds=config.jwks_ttl_seconds,
        )
        logger.info(f"JWKS caching enabled with TTL {config.jwks_ttl_seconds}s")

    # Create Azure AD OIDC decoder
    azure_decoder = OIDCDecoder(
        issuer=config.issuer,
        client_id=config.client_id,
        jwks_uri=config.jwks_uri,
        audience=config.audience,
        clock_skew_seconds=config.clock_skew_seconds,
        key_cache=jwks_cache,
    )

    logger.info("Azure AD Complete services initialized successfully")


async def shutdown_services() -> None:
    """Cleanup services on shutdown."""
    global azure_decoder, app_state

    logger.info("Shutting down Azure AD Complete services")
    azure_decoder = None
    app_state = None


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
    title="Azure AD Complete Example",
    description="Full-featured Azure AD authentication with RBAC, caching, and metrics",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Middleware
# =============================================================================


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware to track request metrics and add request context."""
    start_time = time.time()

    # Generate request ID for tracing
    request_id = f"req_{int(start_time * 1000)}"
    request.state.request_id = request_id

    # Process request
    response = await call_next(request)

    # Record metrics
    if app_state:
        elapsed_ms = (time.time() - start_time) * 1000
        app_state.total_requests += 1
        app_state.total_response_time_ms += elapsed_ms

    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id

    return response


# Add CORS middleware (configured after app creation)
def configure_cors():
    """Configure CORS middleware with loaded configuration."""
    if config:
        add_cors_config(app, allowed_origins=config.cors_origins)


# =============================================================================
# Dependencies
# =============================================================================


async def get_current_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> IdentityContext:
    """Extract and validate identity from Azure AD token.

    This dependency performs:
    1. Token extraction from Authorization header
    2. JWKS-based signature verification (with caching)
    3. Issuer and audience validation
    4. Claims extraction into IdentityContext

    Azure AD specific claims mapped:
    - oid or sub -> user_id
    - tid -> tenant_id (Azure tenant, not app tenant)
    - roles -> roles (from App Roles)
    - scp -> permissions (from API scopes)
    """
    if not azure_decoder:
        logger.log_error(message="Azure AD decoder not initialized")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not available",
        )

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)

        # Record authenticated request
        if app_state:
            app_state.authenticated_requests += 1

        logger.info(
            "Token validated successfully",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            roles=list(identity.roles),
            request_id=getattr(request.state, "request_id", None),
        )

        return identity

    except TokenExpiredError:
        if app_state:
            app_state.failed_auth_attempts += 1
        logger.log_error(message="Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except TokenInvalidError as e:
        if app_state:
            app_state.failed_auth_attempts += 1
        logger.log_error(error=e, message="Token validation failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(
    identity: IdentityContext = Depends(get_current_identity),
) -> IdentityContext:
    """Require user to have Admin role.

    Azure AD App Roles are included in the 'roles' claim of the token.
    Configure roles in Azure AD portal under App Registrations > App Roles.
    """
    # Check for various admin role names (case-insensitive matching)
    admin_roles = {"Admin", "admin", "Administrator", "administrator"}
    if not identity.roles.intersection(admin_roles):
        logger.log_error(
            message="Admin role required",
            user_id=identity.user_id,
            roles=list(identity.roles),
        )
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
    """Health check with authentication system status.

    Returns:
        HealthResponse with service and dependency status
    """
    auth_status = "ready" if azure_decoder else "unavailable"
    uptime = app_state.uptime_seconds if app_state else 0.0

    return HealthResponse(
        status="healthy",
        service="azure-ad-complete-example",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        auth_system=auth_status,
        uptime_seconds=uptime,
    )


@app.get("/", response_model=LandingResponse, tags=["Public"])
async def landing_page():
    """Public landing page with API information.

    Returns:
        LandingResponse with API documentation links
    """
    return LandingResponse(
        message="Azure AD Complete Example API",
        version="1.0.0",
        documentation="/docs",
        endpoints={
            "health": "/health",
            "user_profile": "/user/profile",
            "user_roles": "/user/roles",
            "admin_stats": "/admin/stats",
            "validate_token": "/token/validate",
        },
    )


@app.get("/user/profile", response_model=UserProfileResponse, tags=["User"])
async def get_user_profile(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user profile from Azure AD token.

    Returns:
        UserProfileResponse with user information from token claims
    """
    logger.info(
        "User profile requested",
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
    )

    return UserProfileResponse(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        provider=identity.provider,
        email=identity.attributes.get("email"),
        name=identity.attributes.get("name"),
        preferred_username=identity.attributes.get("preferred_username"),
        roles=sorted(identity.roles),
        permissions=sorted(identity.permissions),
    )


@app.get("/user/roles", response_model=UserRolesResponse, tags=["User"])
async def get_user_roles(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user's roles and permissions.

    Returns:
        UserRolesResponse with role information
    """
    admin_roles = {"Admin", "admin", "Administrator", "administrator"}
    is_admin = bool(identity.roles.intersection(admin_roles))

    return UserRolesResponse(
        user_id=identity.user_id,
        roles=sorted(identity.roles),
        permissions=sorted(identity.permissions),
        is_admin=is_admin,
    )


@app.get("/admin/stats", response_model=AdminStatsResponse, tags=["Admin"])
async def get_admin_stats(
    identity: IdentityContext = Depends(require_admin),
):
    """Get administrative statistics (requires Admin role).

    Returns:
        AdminStatsResponse with system metrics
    """
    logger.info(
        "Admin stats requested",
        user_id=identity.user_id,
    )

    return AdminStatsResponse(
        total_requests=app_state.total_requests if app_state else 0,
        authenticated_requests=app_state.authenticated_requests if app_state else 0,
        failed_auth_attempts=app_state.failed_auth_attempts if app_state else 0,
        average_response_ms=app_state.average_response_ms if app_state else 0.0,
        cache_hit_rate=app_state.cache_hit_rate if app_state else 0.0,
    )


@app.post("/token/validate", response_model=TokenValidationResponse, tags=["Token"])
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Validate token and return detailed information (for debugging).

    Returns:
        TokenValidationResponse with token details
    """
    if not azure_decoder:
        return TokenValidationResponse(valid=False)

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)

        # Extract timestamps if available
        exp_claim = identity.attributes.get("exp")
        iat_claim = identity.attributes.get("iat")

        expires_at = None
        issued_at = None
        if exp_claim:
            expires_at = datetime.fromtimestamp(exp_claim, tz=timezone.utc).isoformat()
        if iat_claim:
            issued_at = datetime.fromtimestamp(iat_claim, tz=timezone.utc).isoformat()

        return TokenValidationResponse(
            valid=True,
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
            issuer=identity.issuer,
            audience=config.audience if config else None,
            roles=sorted(identity.roles),
            expires_at=expires_at,
            issued_at=issued_at,
        )

    except (TokenInvalidError, TokenExpiredError):
        return TokenValidationResponse(valid=False)


@app.post("/logout", response_model=LogoutResponse, tags=["Auth"])
async def logout(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Logout placeholder endpoint.

    Note: Azure AD tokens are JWTs and cannot be truly revoked server-side.
    Actual logout should:
    1. Clear client-side token storage
    2. Redirect to Azure AD logout endpoint:
       https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout

    Returns:
        LogoutResponse with logout status
    """
    logger.info(
        "Logout requested",
        user_id=identity.user_id,
    )

    return LogoutResponse(
        status="success",
        message="Please clear local token storage and redirect to Azure AD logout endpoint",
    )


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
            request_id=getattr(request.state, "request_id", None),
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
            request_id=getattr(request.state, "request_id", None),
        ).model_dump(),
    )


@app.exception_handler(HTTPException)
async def handle_http_exception(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request_id=getattr(request.state, "request_id", None),
        ).model_dump(),
    )


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Run the FastAPI service with uvicorn."""
    import uvicorn

    # Load config to validate environment before starting
    try:
        startup_config = AzureADCompleteConfig()
    except ValueError as e:
        logger.log_error(error=e, message="Failed to start service")
        raise SystemExit(1)

    logger.info(
        "Starting Azure AD Complete Example service",
        host=startup_config.host,
        port=startup_config.port,
        log_level=startup_config.log_level,
    )

    uvicorn.run(
        "azure_service_complete:app",
        host=startup_config.host,
        port=startup_config.port,
        log_level=startup_config.log_level,
    )


if __name__ == "__main__":
    main()
