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

"""Health check endpoint for rate limiter.

Provides a health check endpoint that verifies:
- Backend connectivity (Redis)
- Rate limiter configuration
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from neoaxios_logging import auto_trace, get_telemetry

from .dependencies import get_rate_limiter
from .limiter import RateLimiter

logger = get_telemetry(__name__)

router = APIRouter(prefix="/ratelimit", tags=["ratelimit"])


class RateLimitHealthResponse(BaseModel):
    """Health check response model."""

    status: str
    backend_healthy: bool
    details: dict


@router.get("/health", response_model=RateLimitHealthResponse)
@auto_trace(logger)
async def health_check(
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> RateLimitHealthResponse:
    """Check rate limiter health.

    Returns:
        RateLimitHealthResponse with health status
    """
    try:
        backend_healthy = await limiter.enforcer.backend.health_check()

        return RateLimitHealthResponse(
            status="healthy" if backend_healthy else "degraded",
            backend_healthy=backend_healthy,
            details={
                "algorithm": limiter.enforcer.algorithm.__class__.__name__,
                "behavior": "fail-closed",
            },
        )
    except Exception as e:
        logger.log_error(Exception(f"Health check failed: {e}"))
        return RateLimitHealthResponse(
            status="unhealthy",
            backend_healthy=False,
            details={"error": str(e)},
        )
