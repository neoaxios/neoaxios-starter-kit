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

"""Complete FastAPI service with OIDC authentication.

This is a production-ready reference implementation showing:

- FastAPI application with OIDC authentication middleware
- Protected routes requiring valid OIDC tokens
- Claims extraction and validation
- Error handling (401 Unauthorized, 403 Forbidden)
- Telemetry and logging throughout
- Configuration from environment variables
- Health check endpoint (unauthenticated)
- User info endpoint (authenticated)
- Admin-only endpoint (role-based access)

This example can be used as a template for building authenticated APIs.

Requirements:
    pip install neoaxios-fastapi-kit fastapi uvicorn[standard]

Environment Variables:
    OIDC_ISSUER: OIDC issuer URL (required)
    OIDC_CLIENT_ID: OAuth 2.0 client ID (required)
    OIDC_JWKS_URI: JWKS endpoint URL (required)
    OIDC_AUDIENCE: Expected audience claim (optional)
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)
    LOG_LEVEL: Logging level (default: INFO)

Usage:
    # Set environment variables
    export OIDC_ISSUER=https://accounts.google.com
    export OIDC_CLIENT_ID=your-client-id.apps.googleusercontent.com
    export OIDC_JWKS_URI=https://www.googleapis.com/oauth2/v3/certs

    # Run server
    python fastapi_oidc_service.py

    # Or with uvicorn directly
    uvicorn fastapi_oidc_service:app --reload --port 8000

Testing:
    # Health check (no auth required)
    curl http://localhost:8000/health

    # User info (auth required)
    curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/v1/me

    # Admin endpoint (admin role required)
    curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" http://localhost:8000/api/v1/admin/stats

API Documentation:
    Once running, visit:
    - http://localhost:8000/docs (Swagger UI)
    - http://localhost:8000/redoc (ReDoc)
"""

import os
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn

from neoaxios_logging import get_telemetry

# Import OIDC decoder from neoaxios_fastapi_kit
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.decoders.oidc_cache import create_jwks_cache
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================

class ServiceConfig:
    """Service configuration loaded from environment variables."""

    def __init__(self):
        """Load configuration from environment."""
        # OIDC configuration
        self.oidc_issuer = os.getenv("OIDC_ISSUER")
        self.oidc_client_id = os.getenv("OIDC_CLIENT_ID")
        self.oidc_jwks_uri = os.getenv("OIDC_JWKS_URI")
        self.oidc_audience = os.getenv("OIDC_AUDIENCE")
        self.oidc_clock_skew = int(os.getenv("OIDC_CLOCK_SKEW", "30"))

        # Server configuration
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))
        self.log_level = os.getenv("LOG_LEVEL", "INFO").lower()

        # Validate required configuration
        self._validate()

    def _validate(self):
        """Validate required configuration is present.

        Raises:
            ValueError: If required configuration is missing
        """
        errors = []

        if not self.oidc_issuer:
            errors.append("OIDC_ISSUER environment variable is required")
        if not self.oidc_client_id:
            errors.append("OIDC_CLIENT_ID environment variable is required")
        if not self.oidc_jwks_uri:
            errors.append("OIDC_JWKS_URI environment variable is required")

        if errors:
            error_msg = "\n".join(errors)
            logger.log_error(message=f"Configuration validation failed:\n{error_msg}")
            raise ValueError(f"Invalid configuration:\n{error_msg}")

        logger.info(
            "Service configuration loaded successfully",
            issuer=self.oidc_issuer,
            host=self.host,
            port=self.port,
        )


# Global configuration instance
config = ServiceConfig()


# =============================================================================
# OIDC Decoder Setup
# =============================================================================

# Global decoder instance (initialized on startup)
oidc_decoder: Optional[OIDCDecoder] = None


async def initialize_oidc_decoder() -> None:
    """Initialize OIDC decoder with caching.

    Called during application startup.
    """
    global oidc_decoder

    logger.info("Initializing OIDC decoder")

    try:
        # Create JWKS cache (24 hour TTL)
        cache = create_jwks_cache(
            backend=None,  # In-memory cache
            default_ttl_seconds=86400,  # 24 hours
        )

        # Create OIDC decoder with cache
        oidc_decoder = OIDCDecoder(
            issuer=config.oidc_issuer,
            client_id=config.oidc_client_id,
            jwks_uri=config.oidc_jwks_uri,
            audience=config.oidc_audience,
            clock_skew_seconds=config.oidc_clock_skew,
            key_cache=cache,
        )

        logger.info(
            "OIDC decoder initialized successfully",
            issuer=oidc_decoder.issuer,
        )

    except Exception as e:
        logger.log_error(
            error=e,
            message="Failed to initialize OIDC decoder",
        )
        raise


async def shutdown_oidc_decoder() -> None:
    """Shutdown OIDC decoder and cleanup resources.

    Called during application shutdown.
    """
    global oidc_decoder

    logger.info("Shutting down OIDC decoder")
    oidc_decoder = None


# =============================================================================
# FastAPI Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown.

    Args:
        app: FastAPI application instance

    Yields:
        None
    """
    # Startup
    logger.info("Starting FastAPI application")
    await initialize_oidc_decoder()
    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down FastAPI application")
    await shutdown_oidc_decoder()
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="OIDC Authenticated API",
    description="Production-ready FastAPI service with OIDC authentication",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Security Dependencies
# =============================================================================

# HTTP Bearer token scheme for OpenAPI documentation
security = HTTPBearer()


async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> IdentityContext:
    """Extract and validate identity from Authorization header.

    FastAPI dependency that:
    1. Extracts Bearer token from Authorization header
    2. Validates token using OIDC decoder
    3. Returns IdentityContext for use in route handlers

    Args:
        credentials: HTTP authorization credentials from request header

    Returns:
        IdentityContext with validated user identity

    Raises:
        HTTPException: 401 if token is missing, invalid, or expired

    Example:
        @app.get("/protected")
        async def protected_route(identity: IdentityContext = Depends(get_current_identity)):
            return {"user_id": identity.user_id}
    """
    if not oidc_decoder:
        logger.log_error(message="OIDC decoder not initialized")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not available",
        )

    # Extract token from credentials
    token = credentials.credentials

    try:
        # Validate token and extract identity
        identity = await oidc_decoder.decode(token)

        logger.info(
            "Token validated successfully",
            user_id=identity.user_id,
            provider=identity.provider,
        )

        return identity

    except TokenExpiredError as e:
        logger.log_error(
            error=e,
            message="Token expired",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except TokenInvalidError as e:
        logger.log_error(
            error=e,
            message="Token validation failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.log_error(
            error=e,
            message="Unexpected error during authentication",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error",
        )


async def require_admin_role(
    identity: IdentityContext = Depends(get_current_identity)
) -> IdentityContext:
    """Require user to have admin role.

    FastAPI dependency that enforces admin role requirement.
    Use this to protect admin-only routes.

    Args:
        identity: IdentityContext from get_current_identity dependency

    Returns:
        IdentityContext if user has admin role

    Raises:
        HTTPException: 403 if user doesn't have admin role

    Example:
        @app.get("/admin/users")
        async def list_users(identity: IdentityContext = Depends(require_admin_role)):
            return {"users": [...]}
    """
    if "admin" not in identity.roles:
        logger.log_error(
            message="User attempted to access admin endpoint without admin role",
            user_id=identity.user_id,
            roles=list(identity.roles),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )

    logger.info(
        "Admin role verified",
        user_id=identity.user_id,
    )

    return identity


# =============================================================================
# Response Models
# =============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str


class UserInfoResponse(BaseModel):
    """User information response."""
    user_id: str
    tenant_id: str
    provider: str
    roles: list[str]
    permissions: list[str]
    email: Optional[str] = None


class AdminStatsResponse(BaseModel):
    """Admin statistics response."""
    total_users: int
    active_sessions: int
    uptime_seconds: float


# =============================================================================
# Routes
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint (no authentication required).

    Returns service health status.

    Returns:
        HealthResponse with service status
    """
    logger.info("Health check requested")

    return HealthResponse(
        status="healthy",
        service="oidc-authenticated-api",
        version="1.0.0",
    )


@app.get("/api/v1/me", response_model=UserInfoResponse, tags=["User"])
async def get_user_info(
    identity: IdentityContext = Depends(get_current_identity)
):
    """Get current user information (authentication required).

    Returns information about the authenticated user extracted from
    their OIDC token.

    Args:
        identity: IdentityContext from authentication

    Returns:
        UserInfoResponse with user details
    """
    logger.info(
        "User info requested",
        user_id=identity.user_id,
    )

    return UserInfoResponse(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        provider=identity.provider,
        roles=sorted(identity.roles),
        permissions=sorted(identity.permissions),
        email=identity.attributes.get("email"),
    )


@app.get("/api/v1/protected/data", tags=["Protected"])
async def get_protected_data(
    identity: IdentityContext = Depends(get_current_identity)
):
    """Protected endpoint requiring authentication.

    Returns data accessible to any authenticated user.

    Args:
        identity: IdentityContext from authentication

    Returns:
        Protected data response
    """
    logger.info(
        "Protected data requested",
        user_id=identity.user_id,
    )

    return {
        "message": "This is protected data",
        "user_id": identity.user_id,
        "data": [
            {"id": 1, "value": "Protected data item 1"},
            {"id": 2, "value": "Protected data item 2"},
        ],
    }


@app.get("/api/v1/admin/stats", response_model=AdminStatsResponse, tags=["Admin"])
async def get_admin_stats(
    identity: IdentityContext = Depends(require_admin_role)
):
    """Admin-only endpoint (requires admin role).

    Returns administrative statistics. Only accessible to users with
    the "admin" role.

    Args:
        identity: IdentityContext from authentication (admin role required)

    Returns:
        AdminStatsResponse with statistics
    """
    logger.info(
        "Admin stats requested",
        user_id=identity.user_id,
    )

    # In a real application, these would be actual statistics
    return AdminStatsResponse(
        total_users=42,
        active_sessions=15,
        uptime_seconds=3600.0,
    )


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Custom HTTP exception handler with telemetry logging.

    Args:
        request: Request that caused the exception
        exc: HTTPException that was raised

    Returns:
        JSON error response
    """
    logger.info(
        "HTTP exception occurred",
        status_code=exc.status_code,
        detail=exc.detail,
        path=str(request.url),
    )

    return {
        "error": exc.detail,
        "status_code": exc.status_code,
    }


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Run the FastAPI service with uvicorn.

    Configuration loaded from environment variables.

    Example:
        python fastapi_oidc_service.py
    """
    logger.info(
        "Starting OIDC authenticated FastAPI service",
        host=config.host,
        port=config.port,
        log_level=config.log_level,
    )

    uvicorn.run(
        "fastapi_oidc_service:app",
        host=config.host,
        port=config.port,
        log_level=config.log_level,
        reload=False,  # Set to True for development
    )


if __name__ == "__main__":
    main()
