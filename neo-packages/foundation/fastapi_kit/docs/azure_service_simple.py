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

"""Minimal Azure AD authentication example for FastAPI.

This example demonstrates the simplest setup for Azure AD authentication:
- Single-tenant Azure AD configuration
- Bearer token validation middleware
- Protected route with identity extraction
- Configuration from environment variables
- Proper error handling with 401/403 responses

This example is intentionally minimal (~200-250 lines) to help developers
understand the core concepts before exploring more complex configurations.

Azure AD Configuration Required:
1. Register an application in Azure AD portal
2. Configure API permissions (if needed)
3. Note the tenant ID, client ID, and create a client secret
4. Configure the redirect URI (if using interactive login)

Environment Variables:
    AZURE_TENANT_ID: Your Azure AD tenant ID (required)
    AZURE_CLIENT_ID: Your Azure AD application (client) ID (required)
    PORT: Server port (default: 8000)
    HOST: Server host (default: 0.0.0.0)

Usage:
    # Set environment variables
    export AZURE_TENANT_ID=your-tenant-id
    export AZURE_CLIENT_ID=your-client-id

    # Run the service
    python azure_service_simple.py

    # Or with uvicorn
    uvicorn azure_service_simple:app --reload --port 8000

Testing:
    # Health check (no auth required)
    curl http://localhost:8000/

    # User profile (auth required)
    curl -H "Authorization: Bearer YOUR_AZURE_AD_TOKEN" http://localhost:8000/user/profile

    # Validate token (for debugging)
    curl -X POST -H "Authorization: Bearer YOUR_AZURE_AD_TOKEN" http://localhost:8000/token/validate

Reference:
    Azure AD Token Endpoints:
    - Token: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
    - JWKS: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
    - Issuer: https://login.microsoftonline.com/{tenant}/v2.0
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import from neoaxios_fastapi_kit auth framework
from neoaxios_fastapi_kit.auth.authn.decoders.oidc import OIDCDecoder
from neoaxios_fastapi_kit.auth.authn.errors import TokenInvalidError, TokenExpiredError
from neoaxios_fastapi_kit.auth.context import IdentityContext
from neoaxios_logging import get_telemetry

# Initialize logger for telemetry
logger = get_telemetry(__name__)


# =============================================================================
# Configuration
# =============================================================================


class AzureADConfig:
    """Azure AD configuration loaded from environment variables.

    Azure AD v2.0 endpoints follow this pattern:
    - Issuer: https://login.microsoftonline.com/{tenant}/v2.0
    - JWKS: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys

    For single-tenant apps, use your specific tenant ID.
    For multi-tenant apps, use 'common' or 'organizations'.
    """

    def __init__(self):
        """Load Azure AD configuration from environment."""
        # Required configuration
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")

        # Server configuration
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))

        # Validate required configuration
        self._validate()

        # Construct Azure AD URLs
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        self.jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

        logger.info(
            "Azure AD configuration loaded",
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            issuer=self.issuer,
        )

    def _validate(self) -> None:
        """Validate required configuration is present."""
        errors = []

        if not self.tenant_id:
            errors.append("AZURE_TENANT_ID environment variable is required")
        if not self.client_id:
            errors.append("AZURE_CLIENT_ID environment variable is required")

        if errors:
            error_msg = "\n".join(errors)
            logger.log_error(message=f"Configuration validation failed:\n{error_msg}")
            raise ValueError(f"Invalid configuration:\n{error_msg}")


# =============================================================================
# Response Models
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    message: str
    version: str = "1.0.0"


class UserProfileResponse(BaseModel):
    """User profile response model."""

    user_id: str
    tenant_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: list[str]


class TokenValidationResponse(BaseModel):
    """Token validation response model."""

    valid: bool
    user_id: Optional[str] = None
    expires_at: Optional[int] = None
    issuer: Optional[str] = None


# =============================================================================
# Global State
# =============================================================================


# Configuration instance (initialized on startup)
config: Optional[AzureADConfig] = None

# Azure AD decoder (initialized on startup)
azure_decoder: Optional[OIDCDecoder] = None

# HTTP Bearer security scheme
security = HTTPBearer()


# =============================================================================
# Application Lifecycle
# =============================================================================


async def initialize_decoder() -> None:
    """Initialize Azure AD OIDC decoder on startup."""
    global config, azure_decoder

    logger.info("Initializing Azure AD decoder")

    config = AzureADConfig()

    # Create OIDC decoder configured for Azure AD
    # Azure AD uses standard OIDC with some specific claim names
    azure_decoder = OIDCDecoder(
        issuer=config.issuer,
        client_id=config.client_id,
        jwks_uri=config.jwks_uri,
        # Azure AD audience is the client_id by default
        audience=config.client_id,
        # 30 seconds clock skew tolerance
        clock_skew_seconds=30,
    )

    logger.info("Azure AD decoder initialized successfully")


async def shutdown_decoder() -> None:
    """Cleanup Azure AD decoder on shutdown."""
    global azure_decoder
    logger.info("Shutting down Azure AD decoder")
    azure_decoder = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    await initialize_decoder()
    yield
    # Shutdown
    await shutdown_decoder()


# =============================================================================
# FastAPI Application
# =============================================================================


app = FastAPI(
    title="Azure AD Simple Example",
    description="Minimal Azure AD authentication example",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Dependencies
# =============================================================================


async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> IdentityContext:
    """Extract and validate identity from Azure AD token.

    This dependency:
    1. Extracts Bearer token from Authorization header
    2. Validates signature against Azure AD JWKS
    3. Validates issuer, audience, and expiration
    4. Returns IdentityContext with user information

    Args:
        credentials: HTTP bearer credentials from request

    Returns:
        IdentityContext with validated user identity

    Raises:
        HTTPException: 401 if token is invalid or expired
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
        logger.info(
            "Token validated successfully",
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


# =============================================================================
# Routes
# =============================================================================


@app.get("/", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Public health check endpoint (no authentication required).

    Returns:
        HealthResponse with service status
    """
    return HealthResponse(
        status="healthy",
        message="Azure AD Simple Example is running",
    )


@app.get("/user/profile", response_model=UserProfileResponse, tags=["User"])
async def get_user_profile(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user's profile (requires valid Azure AD token).

    The user information is extracted from the validated Azure AD token.
    Common claims include email, name, and roles (if configured).

    Args:
        identity: Current user identity from token

    Returns:
        UserProfileResponse with user details
    """
    logger.info(
        "User profile requested",
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
    )

    return UserProfileResponse(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        email=identity.attributes.get("email"),
        name=identity.attributes.get("name"),
        roles=sorted(identity.roles),
    )


@app.post("/token/validate", response_model=TokenValidationResponse, tags=["Token"])
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Validate token and return validation details (for testing/debugging).

    This endpoint is useful for debugging token issues. It validates
    the token and returns information about the token's validity.

    Args:
        credentials: HTTP bearer credentials from request

    Returns:
        TokenValidationResponse with validation details
    """
    if not azure_decoder:
        return TokenValidationResponse(valid=False)

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)
        return TokenValidationResponse(
            valid=True,
            user_id=identity.user_id,
            issuer=identity.issuer,
        )
    except (TokenInvalidError, TokenExpiredError):
        return TokenValidationResponse(valid=False)


# =============================================================================
# Error Handlers
# =============================================================================


@app.exception_handler(TokenInvalidError)
async def handle_invalid_token(request, exc: TokenInvalidError):
    """Handle invalid token errors with consistent JSON response."""
    return JSONResponse(
        status_code=401,
        content={"error": "invalid_token", "message": str(exc)},
    )


@app.exception_handler(TokenExpiredError)
async def handle_expired_token(request, exc: TokenExpiredError):
    """Handle expired token errors with consistent JSON response."""
    return JSONResponse(
        status_code=401,
        content={"error": "token_expired", "message": str(exc)},
    )


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Run the FastAPI service with uvicorn."""
    import uvicorn

    # Load config to validate environment before starting
    try:
        startup_config = AzureADConfig()
    except ValueError as e:
        logger.log_error(error=e, message="Failed to start service")
        raise SystemExit(1)

    logger.info(
        "Starting Azure AD Simple Example service",
        host=startup_config.host,
        port=startup_config.port,
    )

    uvicorn.run(
        "azure_service_simple:app",
        host=startup_config.host,
        port=startup_config.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
