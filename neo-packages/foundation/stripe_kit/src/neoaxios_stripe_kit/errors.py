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

"""Structured error taxonomy + translator for the Stripe SDK.

Adapters that wrap the Stripe Python SDK catch ``stripe.error.*`` at
the SDK boundary and translate the exception via
:func:`translate_stripe_error` before surfacing it to the route or
caller layer. The translator preserves the original exception via
``__cause__`` so telemetry traces keep the Stripe request id.

Operational guarantees:
    - Adapters raise :class:`StripeAdapterError` on every failure —
      no manual-approve / env-var / stub-mode fallback.
    - The translator is a pure mapper (no branching beyond the
      isinstance dispatch); callers are traced, the translator is not.
"""

from __future__ import annotations

import stripe

__all__ = [
    "StripeAdapterError",
    "StripeAPIError",
    "StripeAuthError",
    "StripeInvalidRequestError",
    "StripeSignatureVerificationError",
    "translate_stripe_error",
]


class StripeAdapterError(RuntimeError):
    """Base class for every Stripe-translated error.

    Callers catch this type when they need uniform error handling across
    the Stripe surface; the subclasses below let specific callers
    distinguish user-fault (:class:`StripeInvalidRequestError`) from
    infrastructure-fault (:class:`StripeAPIError`) without inspecting
    the underlying ``stripe.error`` type.
    """


class StripeAPIError(StripeAdapterError):
    """Raised for transient API / connection / rate-limit errors.

    Maps to ``stripe.error.APIConnectionError``,
    ``stripe.error.APIError``, and ``stripe.error.RateLimitError``.
    Callers may retry after backoff; this taxonomy itself does NOT
    retry (retry policy lives in the caller / resilience layer).
    """


class StripeAuthError(StripeAdapterError):
    """Raised when Stripe rejects the API key.

    Maps to ``stripe.error.AuthenticationError`` and
    ``stripe.error.PermissionError``. Callers must NOT retry; the key
    itself is bad and must be rotated through the operator's
    credential-rotation procedure.
    """


class StripeInvalidRequestError(StripeAdapterError):
    """Raised for malformed / semantically-invalid requests.

    Maps to ``stripe.error.InvalidRequestError`` and
    ``stripe.error.IdempotencyError``. Represents caller-side bugs and
    maps to a 4xx in the HTTP layer; retries are pointless.
    """


class StripeSignatureVerificationError(StripeAdapterError):
    """Raised when webhook signature verification fails.

    Maps to ``stripe.error.SignatureVerificationError``. The route
    handler translates this to HTTP 401.
    """


# notrace: pure mapper from stripe.error types to adapter errors; no branching logic
def translate_stripe_error(exc: BaseException) -> StripeAdapterError:
    """Translate a raw ``stripe.error.*`` exception into a structured
    :class:`StripeAdapterError` subclass.

    Preserves the original exception via ``__cause__`` so telemetry
    traces keep the Stripe request id (callers should re-raise with
    ``raise translated from exc``).
    """
    if isinstance(exc, stripe.error.SignatureVerificationError):
        return StripeSignatureVerificationError(str(exc))
    if isinstance(
        exc,
        (stripe.error.AuthenticationError, stripe.error.PermissionError),
    ):
        return StripeAuthError(str(exc))
    if isinstance(
        exc,
        (stripe.error.InvalidRequestError, stripe.error.IdempotencyError),
    ):
        return StripeInvalidRequestError(str(exc))
    if isinstance(
        exc,
        (
            stripe.error.APIConnectionError,
            stripe.error.APIError,
            stripe.error.RateLimitError,
        ),
    ):
        return StripeAPIError(str(exc))
    if isinstance(exc, stripe.error.StripeError):
        # Catch-all for anything not specifically partitioned above —
        # treat as API error so callers apply the conservative retry
        # policy.
        return StripeAPIError(str(exc))
    # Non-Stripe exception — preserve the type info in the message so
    # the caller sees the bug rather than a silently-swallowed infra
    # failure.
    return StripeAdapterError(str(exc))
