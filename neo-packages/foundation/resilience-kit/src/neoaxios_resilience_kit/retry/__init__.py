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

"""Retry primitives for resilience in distributed systems.

Public API:
    - retry_with_timeout: Async retry with exponential backoff and hard deadline.
    - RetryBudgetExhausted: Raised when attempts or deadline budget is exhausted.
"""

from neoaxios_resilience_kit.retry.exponential_backoff import (
    RetryBudgetExhausted,
    retry_with_timeout,
)

__all__ = [
    "retry_with_timeout",
    "RetryBudgetExhausted",
]
