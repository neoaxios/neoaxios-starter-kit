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

"""Async retry-with-timeout helper using exponential backoff.

Provides :func:`retry_with_timeout`, a single-source-of-truth retry skeleton
for callers that need bounded retries with deadline tracking.

Design notes:
    Multiple retry-loop callers in a typical service share the same shape —
    deadline tracking via ``time.monotonic()``, exponential backoff capped
    to the remaining deadline budget, and a max-attempts guard.  Where
    callers diverge is *what happens when the budget is exhausted* — some
    enqueue to a fallback queue, others fail closed.  That divergence
    belongs in the callers, not in the shared loop.

    :func:`retry_with_timeout` handles only the mechanics:

    - Starting a monotonic deadline.
    - Counting attempts.
    - Sleeping with exponential backoff capped to the remaining budget.
    - Surfacing :class:`RetryBudgetExhausted` when either the deadline is
      crossed or the maximum attempt count is reached, carrying the attempt
      count and last error string so the caller can build its own domain
      exception.

    Callers catch :class:`RetryBudgetExhausted` and apply their own
    post-budget logic.  Non-retryable exceptions (e.g. permanent 4xx) pass
    through the helper unmodified.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, TypeVar

from neoaxios_logging import auto_trace, get_telemetry

if TYPE_CHECKING:
    pass

logger = get_telemetry(__name__)

T = TypeVar("T")

__all__ = [
    "retry_with_timeout",
    "RetryBudgetExhausted",
]


class RetryBudgetExhausted(Exception):
    """Raised by :func:`retry_with_timeout` when the retry budget is exhausted.

    Carries the attempt count and the last error string so the caller can
    build its own domain exception (e.g. ``StripeAccountSyncDeferred`` or
    ``TrustEngineUnavailableError``) without the helper needing to know about
    caller-specific error types.

    Attributes:
        attempts: Number of attempts made before the budget was exhausted.
        last_error: Diagnostic string describing the last retryable failure.
    """

    def __init__(self, *, attempts: int, last_error: str) -> None:
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"retry budget exhausted after {attempts} attempts: {last_error}"
        )


@auto_trace(logger)
async def retry_with_timeout(
    operation: Callable[[], Awaitable[T]],
    *,
    max_attempts: int,
    backoff_base_seconds: float,
    backoff_multiplier: float,
    backoff_max_seconds: float,
    overall_timeout_seconds: float,
    retryable_errors: tuple[type[Exception], ...],
) -> T:
    """Execute ``operation`` with exponential backoff and a hard deadline.

    Attempts ``operation`` up to ``max_attempts`` times within
    ``overall_timeout_seconds`` using exponential backoff between attempts.
    The backoff sleep is capped to the smaller of ``backoff_max_seconds`` and
    the remaining deadline budget, ensuring at least one final attempt is
    possible even when the budget is nearly exhausted.

    Any exception type listed in ``retryable_errors`` triggers a retry.
    All other exceptions (e.g. permanent 4xx errors surfaced by the caller's
    ``operation`` as a domain exception) propagate immediately without retry.

    Args:
        operation: Zero-argument async callable that performs one attempt.
            Should raise a type listed in ``retryable_errors`` for transient
            failures and raise any other exception for permanent failures.
        max_attempts: Maximum number of attempts before raising
            :class:`RetryBudgetExhausted`.
        backoff_base_seconds: Initial sleep duration after the first failure.
        backoff_multiplier: Multiplier applied to the backoff after each
            attempt (e.g. ``2.0`` for doubling).
        backoff_max_seconds: Upper bound on a single sleep interval,
            independent of the deadline cap.  The actual sleep is
            ``min(current_backoff, backoff_max_seconds, remaining_budget)``.
        overall_timeout_seconds: Hard wall-clock deadline across all attempts
            and sleeps combined (measured via ``time.monotonic()``).
        retryable_errors: Tuple of exception types that should be retried.
            Exceptions not in this tuple propagate immediately.

    Returns:
        The return value of ``operation`` on success.

    Raises:
        RetryBudgetExhausted: The deadline was crossed or max attempts were
            reached; contains ``attempts`` and ``last_error``.
        Any non-retryable exception from ``operation``: propagates unchanged.
    """
    deadline = time.monotonic() + overall_timeout_seconds
    attempt = 0
    backoff = backoff_base_seconds
    last_error: str = ""

    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RetryBudgetExhausted(
                attempts=attempt - 1,
                last_error=last_error or "timeout before first attempt",
            )

        try:
            result = await operation()
        except retryable_errors as exc:
            last_error = str(exc)
            logger.info(
                "retry_with_timeout_transient_error",
                context={
                    "attempt": attempt,
                    "error": last_error,
                },
            )
            if attempt >= max_attempts:
                raise RetryBudgetExhausted(
                    attempts=attempt,
                    last_error=last_error,
                )
            # Cap backoff to the lesser of the configured max and the
            # remaining budget so we always make one final attempt rather
            # than sleeping past the deadline.
            sleep_for = min(
                backoff,
                backoff_max_seconds,
                max(0.0, deadline - time.monotonic()),
            )
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            backoff *= backoff_multiplier
            continue

        return result
