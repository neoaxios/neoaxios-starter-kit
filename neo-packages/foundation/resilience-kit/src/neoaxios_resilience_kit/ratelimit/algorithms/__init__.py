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

"""Rate limiting algorithm implementations.

Provides pluggable algorithm strategies for rate limiting enforcement,
including fixed window, sliding window, and token bucket implementations.

Public API:
    FixedWindowAlgorithm: Fixed window counter algorithm for high-throughput rate limiting.
    create_fixed_window_algorithm: Factory function for FixedWindowAlgorithm.
    SlidingWindowAlgorithm: Sliding window log algorithm for accurate rate limiting.
    create_sliding_window_algorithm: Factory function for SlidingWindowAlgorithm.
    TokenBucketAlgorithm: Token bucket rate limiting algorithm.
    create_token_bucket_algorithm: Factory function for TokenBucketAlgorithm.
"""

from .fixed_window import FixedWindowAlgorithm, create_fixed_window_algorithm
from .sliding_window import SlidingWindowAlgorithm, create_sliding_window_algorithm
from .token_bucket import TokenBucketAlgorithm, create_token_bucket_algorithm

__all__: list[str] = [
    "FixedWindowAlgorithm",
    "create_fixed_window_algorithm",
    "SlidingWindowAlgorithm",
    "create_sliding_window_algorithm",
    "TokenBucketAlgorithm",
    "create_token_bucket_algorithm",
]
