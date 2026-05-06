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

"""Full production-ready FastAPI service with all helpers and config integration."""

import os
from datetime import datetime, timezone
from fastapi import FastAPI
from pydantic import BaseModel
from neoaxios_logging import get_telemetry

from neoaxios_fastapi_kit import (
    add_health_endpoint,
    add_metrics_endpoint,
    add_tools_endpoint,
    add_info_endpoint,
    add_cors_config,
    auto_trace_routes,
    add_error_handlers,
    create_graceful_shutdown_lifespan,
)

# Load configuration from environment or ConfigLoader
# This demonstrates the principle: Application owns config, helpers receive values

# Option 1: Simple environment variables (development/testing)
SERVICE_NAME = os.getenv("SERVICE_NAME", "Production Analysis Service")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://app.example.com").split(",")
GIT_COMMIT = os.getenv("GIT_COMMIT", "abc123def456")
BUILD_TIME = os.getenv("BUILD_TIME", datetime.now(timezone.utc).isoformat())
INCLUDE_CORRELATION_ID = os.getenv("INCLUDE_CORRELATION_ID", "true").lower() == "true"
SHUTDOWN_TIMEOUT = int(os.getenv("SHUTDOWN_TIMEOUT", "30"))

# Option 2: ConfigLoader (recommended for production)
# from neoaxios_config import ConfigLoader
# loader = ConfigLoader("analysis-service", env_prefix="ANALYSIS")
# config = loader.load()
# SERVICE_NAME = config.get("service.name", "Production Analysis Service")
# SERVICE_VERSION = config.get("service.version", "1.0.0")
# CORS_ORIGINS = config.get("cors.allowed_origins", ["https://app.example.com"])
# GIT_COMMIT = config.get("build.git_commit", "unknown")
# BUILD_TIME = config.get("build.timestamp", datetime.now(timezone.utc).isoformat())
# INCLUDE_CORRELATION_ID = config.get("telemetry.correlation_id", True)
# SHUTDOWN_TIMEOUT = config.get("server.shutdown_timeout", 30)

# Initialize telemetry
logger = get_telemetry(__name__)

# Setup graceful shutdown lifespan
lifespan = create_graceful_shutdown_lifespan(shutdown_timeout=SHUTDOWN_TIMEOUT)

# Initialize FastAPI with config values and lifespan
app = FastAPI(
    title=SERVICE_NAME,
    version=SERVICE_VERSION,
    description="Production-ready text analysis API",
    lifespan=lifespan
)


# Define models
class AnalysisRequest(BaseModel):
    text: str
    language: str = "en"
    mode: str = "standard"  # standard, deep, quick


class AnalysisResult(BaseModel):
    sentiment: float
    topics: list[str]
    entities: list[str]
    confidence: float


# Business endpoints
@app.post("/v1/analysis", response_model=AnalysisResult)
async def create_analysis(request: AnalysisRequest) -> AnalysisResult:
    """
    Analyze text sentiment, topics, and entities.

    Args:
        request: Analysis request with text and options

    Returns:
        Analysis result with sentiment, topics, entities, and confidence

    Example:
        POST /v1/analysis
        {"text": "I love FastAPI!", "language": "en"}

        Response:
        {
            "sentiment": 0.95,
            "topics": ["technology", "programming"],
            "entities": ["FastAPI"],
            "confidence": 0.92
        }
    """
    # Placeholder implementation
    return AnalysisResult(
        sentiment=0.8,
        topics=["technology", "programming"],
        entities=["FastAPI"],
        confidence=0.85
    )


@app.get("/v1/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: str) -> AnalysisResult:
    """Retrieve existing analysis by ID."""
    # Placeholder implementation
    return AnalysisResult(
        sentiment=0.7,
        topics=["business"],
        entities=[],
        confidence=0.80
    )


@app.get("/v1/analyses", response_model=list[AnalysisResult])
async def list_analyses(limit: int = 10, offset: int = 0) -> list[AnalysisResult]:
    """List recent analyses with pagination."""
    # Placeholder implementation
    return [
        AnalysisResult(
            sentiment=0.8,
            topics=["tech"],
            entities=[],
            confidence=0.85
        )
    ]


# Configure standard endpoints with values from application config
# Principle: Helpers are pure functions, application provides configuration
add_health_endpoint(app, version=SERVICE_VERSION)
add_metrics_endpoint(app)
add_tools_endpoint(app)
add_info_endpoint(
    app,
    git_commit=GIT_COMMIT,
    build_time=BUILD_TIME
)

# Configure middleware with values from application config
add_cors_config(app, allowed_origins=CORS_ORIGINS)
add_error_handlers(app, include_correlation_id=INCLUDE_CORRELATION_ID)

# Apply auto-trace to all routes (AFTER routes are defined)
auto_trace_routes(app, logger)

# Note: Graceful shutdown is configured via lifespan (see app initialization above)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=1  # Use 1 worker per pod in Kubernetes
    )
