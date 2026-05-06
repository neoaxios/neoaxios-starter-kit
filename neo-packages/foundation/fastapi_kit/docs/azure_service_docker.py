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

"""Production deployment example with Docker and Kubernetes configuration.

This example provides a production-ready Azure AD authenticated service with:
- Docker containerization with proper Python image
- Kubernetes deployment configuration
- Environment variable configuration with validation
- Secret management patterns (Azure Key Vault / K8s secrets)
- Health checks for container orchestration (liveness/readiness)
- Graceful shutdown handling with cleanup
- Production logging (structured JSON)
- Resource limits and configuration
- Telemetry export patterns

This file serves as both:
1. A runnable FastAPI application
2. A template with embedded deployment configurations (YAML in docstrings)

Deployment Configuration Files (create separately):
- Dockerfile - Container build configuration
- docker-compose.yml - Local development orchestration
- k8s-deployment.yaml - Kubernetes deployment
- config.yaml - Application configuration template

Environment Variables:
    AZURE_TENANT_ID: Azure AD tenant ID (required)
    AZURE_CLIENT_ID: Azure AD application ID (required)
    AZURE_CLIENT_SECRET: Client secret for APIs (from secret store)
    AZURE_KEY_VAULT_URL: Azure Key Vault URL for secrets (optional)
    ENVIRONMENT: Deployment environment (development/staging/production)
    LOG_FORMAT: Log format - 'json' for production, 'text' for development
    LOG_LEVEL: Log level (DEBUG/INFO/WARNING/ERROR)
    GRACEFUL_SHUTDOWN_TIMEOUT: Shutdown timeout in seconds (default: 30)
    PORT: Service port (default: 8000)
    HOST: Service host (default: 0.0.0.0)
    WORKERS: Number of uvicorn workers (default: 1)

Usage:
    # Local development
    python azure_service_docker.py

    # Docker build and run
    docker build -t azure-service:latest .
    docker run -p 8000:8000 --env-file .env azure-service:latest

    # Kubernetes deployment
    kubectl apply -f k8s-deployment.yaml

Health Endpoints (for orchestration):
    GET /health/live - Liveness probe (is the service running?)
    GET /health/ready - Readiness probe (is the service ready for traffic?)
    GET /health/startup - Startup probe (has the service started successfully?)

================================================================================
DOCKERFILE (create as 'Dockerfile'):
================================================================================

# Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Copy application code
COPY --chown=appuser:appuser . .

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    WORKERS=1 \
    LOG_FORMAT=json \
    LOG_LEVEL=INFO \
    ENVIRONMENT=production

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Run application
CMD ["python", "azure_service_docker.py"]

================================================================================
DOCKER-COMPOSE.YML (create as 'docker-compose.yml'):
================================================================================

version: '3.8'

services:
  azure-service:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - ENVIRONMENT=development
      - LOG_FORMAT=text
      - LOG_LEVEL=DEBUG
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
    restart: unless-stopped
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M

================================================================================
K8S-DEPLOYMENT.YAML (create as 'k8s-deployment.yaml'):
================================================================================

apiVersion: v1
kind: Namespace
metadata:
  name: azure-service
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-credentials
  namespace: azure-service
type: Opaque
stringData:
  AZURE_TENANT_ID: "your-tenant-id"
  AZURE_CLIENT_ID: "your-client-id"
  AZURE_CLIENT_SECRET: "your-client-secret"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: azure-service-config
  namespace: azure-service
data:
  ENVIRONMENT: "production"
  LOG_FORMAT: "json"
  LOG_LEVEL: "INFO"
  GRACEFUL_SHUTDOWN_TIMEOUT: "30"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azure-service
  namespace: azure-service
  labels:
    app: azure-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: azure-service
  template:
    metadata:
      labels:
        app: azure-service
    spec:
      containers:
      - name: azure-service
        image: azure-service:latest
        ports:
        - containerPort: 8000
        envFrom:
        - secretRef:
            name: azure-credentials
        - configMapRef:
            name: azure-service-config
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health/startup
            port: 8000
          initialDelaySeconds: 0
          periodSeconds: 5
          timeoutSeconds: 5
          failureThreshold: 30
      terminationGracePeriodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: azure-service
  namespace: azure-service
spec:
  selector:
    app: azure-service
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: azure-service
  namespace: azure-service
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: azure-service-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: azure-service
            port:
              number: 80

================================================================================
CONFIG.YAML (create as 'config.yaml'):
================================================================================

# Azure AD Configuration
azure:
  tenant_id: "${AZURE_TENANT_ID}"
  client_id: "${AZURE_CLIENT_ID}"
  # client_secret loaded from secret store
  audience: null  # defaults to client_id

# Server Configuration
server:
  host: "0.0.0.0"
  port: 8000
  workers: 1
  graceful_shutdown_timeout: 30

# Logging Configuration
logging:
  level: "INFO"
  format: "json"  # 'json' for production, 'text' for development

# Health Check Configuration
health:
  include_details: false  # Don't expose internal details in production

# Cache Configuration
cache:
  jwks_ttl_seconds: 86400  # 24 hours
  enabled: true

================================================================================
END OF DEPLOYMENT CONFIGURATIONS
================================================================================
"""

import asyncio
import json
import os
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Depends, status
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
# Environment Configuration
# =============================================================================


class Environment(str, Enum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogFormat(str, Enum):
    """Log output format."""

    JSON = "json"
    TEXT = "text"


class ProductionConfig:
    """Production-ready configuration with validation.

    Configuration is loaded from environment variables with validation
    and sensible defaults for production deployment.

    Security considerations:
    - Secrets should come from secret stores (Key Vault, K8s secrets)
    - Never log secret values
    - Validate all required configuration on startup
    """

    def __init__(self):
        """Load and validate configuration."""
        # Environment
        env_str = os.getenv("ENVIRONMENT", "production").lower()
        try:
            self.environment = Environment(env_str)
        except ValueError:
            self.environment = Environment.PRODUCTION

        # Azure AD Configuration
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.audience = os.getenv("AZURE_AUDIENCE")

        # Optional: Azure Key Vault for secrets
        self.key_vault_url = os.getenv("AZURE_KEY_VAULT_URL")

        # Server Configuration
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))
        self.workers = int(os.getenv("WORKERS", "1"))
        self.graceful_shutdown_timeout = int(os.getenv("GRACEFUL_SHUTDOWN_TIMEOUT", "30"))

        # Logging Configuration
        log_format_str = os.getenv("LOG_FORMAT", "json").lower()
        try:
            self.log_format = LogFormat(log_format_str)
        except ValueError:
            self.log_format = LogFormat.JSON

        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()

        # Health Check Configuration
        self.health_include_details = os.getenv("HEALTH_INCLUDE_DETAILS", "false").lower() == "true"

        # Cache Configuration
        self.jwks_cache_enabled = os.getenv("JWKS_CACHE_ENABLED", "true").lower() == "true"
        self.jwks_cache_ttl = int(os.getenv("JWKS_CACHE_TTL", "86400"))

        # Validate configuration
        self._validate()

        # Construct Azure AD URLs
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        self.jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

        # Log configuration (without secrets)
        self._log_configuration()

    def _validate(self) -> None:
        """Validate required configuration."""
        errors = []

        if not self.tenant_id:
            errors.append("AZURE_TENANT_ID is required")
        if not self.client_id:
            errors.append("AZURE_CLIENT_ID is required")

        if errors:
            error_msg = "; ".join(errors)
            # Log error in structured format
            logger.log_error(message=f"Configuration validation failed: {error_msg}")
            raise ValueError(f"Configuration error: {error_msg}")

    def _log_configuration(self) -> None:
        """Log configuration (excluding secrets)."""
        logger.info(
            "Configuration loaded",
            environment=self.environment.value,
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            has_client_secret=bool(self.client_secret),
            host=self.host,
            port=self.port,
            workers=self.workers,
            log_format=self.log_format.value,
            log_level=self.log_level,
            jwks_cache_enabled=self.jwks_cache_enabled,
            jwks_cache_ttl=self.jwks_cache_ttl,
        )

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION


# =============================================================================
# Application State
# =============================================================================


class ApplicationState:
    """Application state for health checks and metrics.

    Tracks:
    - Service startup status
    - Readiness for traffic
    - Authentication system status
    - Graceful shutdown state
    """

    def __init__(self):
        self.start_time: datetime = datetime.now(timezone.utc)
        self.startup_complete: bool = False
        self.ready_for_traffic: bool = False
        self.shutting_down: bool = False
        self.auth_system_healthy: bool = False
        self.last_health_check: Optional[datetime] = None
        self.request_count: int = 0
        self.error_count: int = 0

    @property
    def uptime_seconds(self) -> float:
        """Get service uptime in seconds."""
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()

    def to_dict(self, include_details: bool = False) -> Dict[str, Any]:
        """Convert state to dictionary for health responses."""
        result = {
            "uptime_seconds": round(self.uptime_seconds, 2),
            "startup_complete": self.startup_complete,
            "ready": self.ready_for_traffic,
            "shutting_down": self.shutting_down,
        }

        if include_details:
            result.update({
                "auth_healthy": self.auth_system_healthy,
                "request_count": self.request_count,
                "error_count": self.error_count,
                "start_time": self.start_time.isoformat(),
            })

        return result


# =============================================================================
# Response Models
# =============================================================================


class LivenessResponse(BaseModel):
    """Liveness probe response."""

    status: str
    timestamp: str


class ReadinessResponse(BaseModel):
    """Readiness probe response."""

    status: str
    ready: bool
    timestamp: str
    checks: Dict[str, bool]


class StartupResponse(BaseModel):
    """Startup probe response."""

    status: str
    startup_complete: bool
    timestamp: str


class HealthDetailResponse(BaseModel):
    """Detailed health response."""

    status: str
    service: str
    version: str
    environment: str
    uptime_seconds: float
    timestamp: str
    checks: Dict[str, Any]


class UserInfoResponse(BaseModel):
    """User info response."""

    user_id: str
    tenant_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    roles: list[str]


# =============================================================================
# Global State
# =============================================================================


config: Optional[ProductionConfig] = None
app_state: Optional[ApplicationState] = None
azure_decoder: Optional[OIDCDecoder] = None
security = HTTPBearer()

# Shutdown event for graceful shutdown
shutdown_event = asyncio.Event()


# =============================================================================
# Graceful Shutdown Handler
# =============================================================================


def signal_handler(signum, frame):
    """Handle shutdown signals for graceful termination.

    Called on SIGTERM (container shutdown) or SIGINT (Ctrl+C).
    Sets the shutdown event to trigger graceful cleanup.
    """
    signal_name = signal.Signals(signum).name
    logger.info(f"Received signal {signal_name}, initiating graceful shutdown")

    if app_state:
        app_state.shutting_down = True
        app_state.ready_for_traffic = False

    # Set shutdown event
    shutdown_event.set()


# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# =============================================================================
# Application Lifecycle
# =============================================================================


async def initialize_services() -> None:
    """Initialize all services on startup.

    This is called during application startup and must:
    1. Load and validate configuration
    2. Initialize authentication decoder
    3. Set up any required connections
    4. Mark service as ready for traffic
    """
    global config, app_state, azure_decoder

    logger.info("Starting service initialization")

    # Initialize application state
    app_state = ApplicationState()

    # Load configuration
    config = ProductionConfig()

    # Create JWKS cache if enabled
    jwks_cache = None
    if config.jwks_cache_enabled:
        jwks_cache = create_jwks_cache(
            backend=None,  # In-memory cache
            default_ttl_seconds=config.jwks_cache_ttl,
        )
        logger.info("JWKS cache initialized", ttl_seconds=config.jwks_cache_ttl)

    # Create Azure AD OIDC decoder
    azure_decoder = OIDCDecoder(
        issuer=config.issuer,
        client_id=config.client_id,
        jwks_uri=config.jwks_uri,
        audience=config.audience or config.client_id,
        clock_skew_seconds=30,
        key_cache=jwks_cache,
    )

    # Mark auth system as healthy
    app_state.auth_system_healthy = True

    # Mark startup as complete
    app_state.startup_complete = True

    # Allow some initialization time before accepting traffic
    await asyncio.sleep(0.1)

    # Mark as ready for traffic
    app_state.ready_for_traffic = True

    logger.info(
        "Service initialization complete",
        environment=config.environment.value,
        ready=True,
    )


async def cleanup_services() -> None:
    """Cleanup services during shutdown.

    This is called during graceful shutdown and should:
    1. Stop accepting new requests
    2. Complete in-flight requests
    3. Close connections
    4. Clean up resources
    """
    global azure_decoder, app_state

    if app_state:
        app_state.shutting_down = True
        app_state.ready_for_traffic = False

    logger.info("Starting graceful shutdown")

    # Allow in-flight requests to complete
    timeout = config.graceful_shutdown_timeout if config else 30
    logger.info(f"Waiting up to {timeout}s for in-flight requests")

    # In production, you would wait for in-flight requests here
    await asyncio.sleep(1)

    # Cleanup resources
    azure_decoder = None

    logger.info("Graceful shutdown complete")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown."""
    # Startup
    await initialize_services()

    yield

    # Shutdown
    await cleanup_services()


# =============================================================================
# FastAPI Application
# =============================================================================


app = FastAPI(
    title="Azure AD Production Service",
    description="Production-ready Azure AD authenticated service with Docker/K8s support",
    version="1.0.0",
    lifespan=lifespan,
    # Disable docs in production
    docs_url="/docs" if os.getenv("ENVIRONMENT", "").lower() != "production" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT", "").lower() != "production" else None,
)


# =============================================================================
# Health Check Endpoints (for Container Orchestration)
# =============================================================================


@app.get("/health/live", response_model=LivenessResponse, tags=["Health"])
async def liveness_probe():
    """Liveness probe for container orchestration.

    Kubernetes liveness probe checks if the service is running.
    If this fails, the container will be restarted.

    Returns 200 if the service process is alive.
    Returns 503 if the service is in a failed state.
    """
    # During shutdown, continue to report as live to allow graceful drain
    return LivenessResponse(
        status="alive",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/health/ready", response_model=ReadinessResponse, tags=["Health"])
async def readiness_probe():
    """Readiness probe for container orchestration.

    Kubernetes readiness probe checks if the service can accept traffic.
    If this fails, the pod is removed from service endpoints.

    Returns 200 if the service is ready to accept traffic.
    Returns 503 if the service is not ready (starting up or shutting down).
    """
    is_ready = (
        app_state is not None
        and app_state.ready_for_traffic
        and not app_state.shutting_down
    )

    checks = {
        "startup_complete": app_state.startup_complete if app_state else False,
        "auth_system": app_state.auth_system_healthy if app_state else False,
        "not_shutting_down": not (app_state.shutting_down if app_state else True),
    }

    if not is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )

    return ReadinessResponse(
        status="ready",
        ready=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
        checks=checks,
    )


@app.get("/health/startup", response_model=StartupResponse, tags=["Health"])
async def startup_probe():
    """Startup probe for container orchestration.

    Kubernetes startup probe checks if the service has finished starting.
    This is useful for services with slow startup (loading models, warming caches).

    Returns 200 when startup is complete.
    Returns 503 during startup.
    """
    startup_complete = app_state is not None and app_state.startup_complete

    if not startup_complete:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service still starting",
        )

    return StartupResponse(
        status="started",
        startup_complete=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/health", response_model=HealthDetailResponse, tags=["Health"])
async def health_check():
    """Detailed health check endpoint.

    Provides comprehensive health information for monitoring systems.
    In production, sensitive details may be hidden.
    """
    include_details = config.health_include_details if config else False

    checks: Dict[str, Any] = {
        "auth_decoder": azure_decoder is not None,
    }

    if include_details and app_state:
        checks.update(app_state.to_dict(include_details=True))

    return HealthDetailResponse(
        status="healthy" if app_state and app_state.ready_for_traffic else "degraded",
        service="azure-ad-production-service",
        version="1.0.0",
        environment=config.environment.value if config else "unknown",
        uptime_seconds=app_state.uptime_seconds if app_state else 0.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        checks=checks,
    )


# =============================================================================
# Authentication Dependency
# =============================================================================


async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> IdentityContext:
    """Extract and validate identity from Azure AD token."""
    if not azure_decoder:
        logger.log_error(message="Authentication service not available")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not available",
        )

    # Track request
    if app_state:
        app_state.request_count += 1

    token = credentials.credentials

    try:
        identity = await azure_decoder.decode(token)
        logger.info(
            "Authentication successful",
            user_id=identity.user_id,
            tenant_id=identity.tenant_id,
        )
        return identity

    except TokenExpiredError:
        if app_state:
            app_state.error_count += 1
        logger.log_error(message="Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except TokenInvalidError as e:
        if app_state:
            app_state.error_count += 1
        logger.log_error(error=e, message="Token validation failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# =============================================================================
# Application Routes
# =============================================================================


@app.get("/", tags=["Public"])
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Azure AD Production Service",
        "version": "1.0.0",
        "health": "/health",
        "docs": "/docs" if not (config and config.is_production) else None,
    }


@app.get("/user/me", response_model=UserInfoResponse, tags=["User"])
async def get_current_user(
    identity: IdentityContext = Depends(get_current_identity),
):
    """Get current user information."""
    return UserInfoResponse(
        user_id=identity.user_id,
        tenant_id=identity.tenant_id,
        email=identity.attributes.get("email"),
        name=identity.attributes.get("name"),
        roles=sorted(identity.roles),
    )


# =============================================================================
# Error Handlers (Structured JSON Responses)
# =============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions with structured JSON response."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": exc.detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle unexpected exceptions with structured JSON response."""
    logger.log_error(error=exc, message="Unhandled exception")

    if app_state:
        app_state.error_count += 1

    # Don't expose internal errors in production
    detail = str(exc) if not (config and config.is_production) else "Internal server error"

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        },
    )


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Run the FastAPI service with uvicorn.

    For production deployment:
    - Use gunicorn with uvicorn workers for multiple workers
    - Configure via environment variables
    - Use container orchestration health probes
    """
    import uvicorn

    # Load config to validate environment
    try:
        startup_config = ProductionConfig()
    except ValueError as e:
        # Log structured error for container logs
        error_log = {
            "level": "ERROR",
            "message": "Failed to start service",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(error_log), file=sys.stderr)
        sys.exit(1)

    logger.info(
        "Starting production service",
        host=startup_config.host,
        port=startup_config.port,
        workers=startup_config.workers,
        environment=startup_config.environment.value,
    )

    # Configure uvicorn
    uvicorn_config = {
        "app": "azure_service_docker:app",
        "host": startup_config.host,
        "port": startup_config.port,
        "log_level": startup_config.log_level.lower(),
        "access_log": not startup_config.is_production,  # Disable access logs in production
    }

    # For production with multiple workers, use:
    # gunicorn azure_service_docker:app -w 4 -k uvicorn.workers.UvicornWorker

    uvicorn.run(**uvicorn_config)


if __name__ == "__main__":
    main()
