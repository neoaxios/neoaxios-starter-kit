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

"""Statistical utilities for scale and performance tests.

Provides latency percentile computation used across multiple package
scale test suites.
"""

from __future__ import annotations

from neoaxios_logging import get_telemetry

logger = get_telemetry(__name__)


def compute_percentiles(latencies: list[float]) -> dict[str, float]:
    """Compute latency distribution statistics.

    Args:
        latencies: List of latency measurements (seconds or milliseconds,
            depending on caller convention).

    Returns:
        Dict with keys: p50, p95, p99, avg, min, max.

    Raises:
        ValueError: If latencies is empty.
    """
    if not latencies:
        raise ValueError("latencies must be non-empty")

    s = sorted(latencies)
    n = len(s)
    return {
        "p50": s[int(n * 0.50)],
        "p95": s[int(n * 0.95)],
        "p99": s[int(n * 0.99)],
        "avg": sum(s) / n,
        "min": s[0],
        "max": s[-1],
    }
