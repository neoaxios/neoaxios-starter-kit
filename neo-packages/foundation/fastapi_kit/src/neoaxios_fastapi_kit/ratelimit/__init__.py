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

"""Rate limiting framework for FastAPI services.

Re-export facade that sources framework-agnostic symbols from
neoaxios_resilience_kit.ratelimit and FastAPI-specific symbols from
local submodules. All 20+ existing ``from neoaxios_fastapi_kit.ratelimit import X``
paths are preserved.

Framework-agnostic (from resilience-kit):
    RateLimitConfig, EndpointConfig, RateLimitBackend, RateLimitAlgorithm,
    RateLimitResult, RateLimitEnforcer, create_enforcer, RateLimitIdentity,
    FixedWindowAlgorithm, create_fixed_window_algorithm,
    SlidingWindowAlgorithm, create_sliding_window_algorithm,
    TokenBucketAlgorithm, create_token_bucket_algorithm,
    InMemoryRateLimitBackend, create_memory_ratelimit_backend,
    RedisRateLimitBackend, create_redis_ratelimit_backend,
    parse_rate, is_valid_rate, RateLimitError, RateLimitConfigError

FastAPI-specific (from local submodules):
    RateLimiter, create_rate_limiter, GlobalRateLimitMiddleware,
    require_rate_limit, configure_rate_limiter, disable_rate_limiter,
    is_rate_limiter_disabled, get_rate_limiter, RateLimitDep,
    RateLimitKeyBuilder, create_key_builder, RateLimitExceeded,
    HTTPRateLimitBackendError, RateLimitMetrics, create_metrics,
    health_router

Backward compatibility:
    ``RateLimitBackendError`` in ``__all__`` maps to
    ``HTTPRateLimitBackendError`` so that existing consumers doing
    ``from neoaxios_fastapi_kit.ratelimit import RateLimitBackendError``
    receive the HTTP 503 version (unchanged behavior).
"""

from neoaxios_logging import get_telemetry

# --- Framework-agnostic symbols from resilience-kit ---

from neoaxios_resilience_kit.ratelimit import (
    # Configuration
    RateLimitConfig,
    EndpointConfig,
    # Protocols
    RateLimitBackend,
    RateLimitAlgorithm,
    RateLimitResult,
    # Enforcer
    RateLimitEnforcer,
    create_enforcer,
    # Key building (identity protocol)
    RateLimitIdentity,
    # Algorithms
    FixedWindowAlgorithm,
    create_fixed_window_algorithm,
    SlidingWindowAlgorithm,
    create_sliding_window_algorithm,
    TokenBucketAlgorithm,
    create_token_bucket_algorithm,
    # Backends
    InMemoryRateLimitBackend,
    create_memory_ratelimit_backend,
    RedisRateLimitBackend,
    create_redis_ratelimit_backend,
    # Utilities
    parse_rate,
    is_valid_rate,
    # Exceptions (base types from resilience-kit)
    RateLimitError,
    RateLimitConfigError,
)

# --- FastAPI-specific symbols from local submodules ---

# Exceptions (HTTP subclasses)
from .exceptions import RateLimitExceeded
from .exceptions import HTTPRateLimitBackendError

# Core Components
from .limiter import RateLimiter, create_rate_limiter
from .key_builder import RateLimitKeyBuilder, create_key_builder

# Middleware
from .middleware import GlobalRateLimitMiddleware

# Dependencies
from .dependencies import (
    configure_rate_limiter,
    disable_rate_limiter,
    is_rate_limiter_disabled,
    get_rate_limiter,
    require_rate_limit,
    RateLimitDep,
)

# Metrics
from .metrics import RateLimitMetrics, create_metrics

# Health
from .health import router as health_router

# --- Backward compatibility mapping ---
# Consumers expect ``from neoaxios_fastapi_kit.ratelimit import RateLimitBackendError``
# to give the HTTP 503 version. The resilience-kit base is available as
# ``neoaxios_resilience_kit.ratelimit.RateLimitBackendError``.
RateLimitBackendError = HTTPRateLimitBackendError

logger = get_telemetry(__name__)

__all__ = [
    # Configuration
    "RateLimitConfig",
    "EndpointConfig",
    # Protocols
    "RateLimitBackend",
    "RateLimitAlgorithm",
    "RateLimitResult",
    # Exceptions
    "RateLimitError",
    "RateLimitExceeded",
    "RateLimitBackendError",
    "HTTPRateLimitBackendError",
    "RateLimitConfigError",
    # Core
    "RateLimiter",
    "create_rate_limiter",
    "RateLimitEnforcer",
    "create_enforcer",
    "RateLimitIdentity",
    "RateLimitKeyBuilder",
    "create_key_builder",
    # Backends
    "RedisRateLimitBackend",
    "InMemoryRateLimitBackend",
    "create_redis_ratelimit_backend",
    "create_memory_ratelimit_backend",
    # Algorithms
    "FixedWindowAlgorithm",
    "create_fixed_window_algorithm",
    "SlidingWindowAlgorithm",
    "create_sliding_window_algorithm",
    "TokenBucketAlgorithm",
    "create_token_bucket_algorithm",
    # Middleware
    "GlobalRateLimitMiddleware",
    # Dependencies
    "configure_rate_limiter",
    "disable_rate_limiter",
    "is_rate_limiter_disabled",
    "get_rate_limiter",
    "require_rate_limit",
    "RateLimitDep",
    # Metrics
    "RateLimitMetrics",
    "create_metrics",
    # Health
    "health_router",
    # Utilities
    "parse_rate",
    "is_valid_rate",
]
