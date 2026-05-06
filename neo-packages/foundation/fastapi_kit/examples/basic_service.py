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

"""Basic FastAPI service example using neoaxios-fastapi-kit with config integration."""

import os
from fastapi import FastAPI
from pydantic import BaseModel

# Import helpers
from neoaxios_fastapi_kit import (
    add_health_endpoint,
    add_tools_endpoint,
    add_cors_config,
)

# Load configuration
# Option 1: From environment variables (simple approach)
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://example.com").split(",")

# Option 2: From ConfigLoader (recommended for complex apps)
# from neoaxios_config import ConfigLoader
# loader = ConfigLoader("my-service", env_prefix="MY_SERVICE")
# config = loader.load()
# SERVICE_VERSION = config.get("service.version", "1.0.0")
# CORS_ORIGINS = config.get("cors.allowed_origins", ["https://example.com"])

# Create FastAPI app
app = FastAPI(
    title="Basic Analysis Service",
    version=SERVICE_VERSION,
    description="Simple text analysis service"
)

# Define models
class AnalysisRequest(BaseModel):
    text: str
    language: str = "en"


class AnalysisResult(BaseModel):
    sentiment: float
    topics: list[str]


# Business logic endpoints
@app.post("/v1/analysis", response_model=AnalysisResult)
async def create_analysis(request: AnalysisRequest) -> AnalysisResult:
    """
    Analyze text sentiment and extract topics.

    This function is automatically discoverable via /tools endpoint.
    """
    # Placeholder implementation
    return AnalysisResult(
        sentiment=0.8,
        topics=["technology", "programming"]
    )


@app.get("/v1/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: str) -> AnalysisResult:
    """Retrieve existing analysis by ID."""
    # Placeholder implementation
    return AnalysisResult(
        sentiment=0.7,
        topics=["business"]
    )


# Add helper endpoints (configuration comes from application, not helpers)
add_health_endpoint(app, version=SERVICE_VERSION)
add_tools_endpoint(app)
add_cors_config(app, allowed_origins=CORS_ORIGINS)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
