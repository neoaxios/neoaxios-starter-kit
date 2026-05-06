# neoaxios-stripe-kit

> **Early-stage package (0.0.1).** This is a small starter building block
> in the NeoAxios Starter Kit, not a full Stripe integration library. The
> public surface is intentionally narrow — a typed exception hierarchy and
> a one-function translator — and is expected to grow as additional Stripe
> helpers (idempotency-keyed operations, webhook construction, retryable
> execution) are added in later releases. APIs may evolve before 1.0.0.

Structured error taxonomy and translator for the [Stripe Python SDK]. Wraps
the raw `stripe.error.*` hierarchy in a small set of adapter-friendly
exception classes so callers can do uniform error handling without coupling
to Stripe SDK internals.

[Stripe Python SDK]: https://github.com/stripe/stripe-python

## Why

The Stripe SDK ships nine concrete exception types. Most service code only
needs three categorical distinctions:

- **Retryable infrastructure failure** — connection error, transient API
  error, rate limit
- **Non-retryable caller fault** — invalid request, idempotency violation
- **Auth failure** — bad API key, insufficient permissions

`stripe_kit` collapses the SDK exceptions into that taxonomy and gives
adapters a single base class (`StripeAdapterError`) to catch.

## What's in the box

```
StripeAdapterError                    # base — catch this for "anything Stripe failed"
├── StripeAPIError                    # transient: APIConnectionError, APIError, RateLimitError
├── StripeAuthError                   # AuthenticationError, PermissionError
├── StripeInvalidRequestError         # InvalidRequestError, IdempotencyError
└── StripeSignatureVerificationError  # SignatureVerificationError (webhooks)
```

Plus `translate_stripe_error(exc) → StripeAdapterError` — a pure mapper that
takes a raw Stripe exception and returns the right adapter error subclass,
preserving the original via `__cause__`.

## Design choices

- **No retries here.** The taxonomy distinguishes retryable vs. non-retryable
  but does not retry. Retry policy lives in the caller's resilience layer
  (e.g. `neoaxios-resilience-kit`'s `retry_with_timeout`).
- **No fallback / stub mode.** Adapters raise `StripeAdapterError` on every
  failure. There is no env-var-controlled "manual approve" or stubbed-out
  development mode — fail closed, surface the error.
- **Preserve `__cause__`.** Re-raise as `raise translated from exc` so the
  Stripe request id stays in the traceback for telemetry correlation.
- **Pure mapper.** `translate_stripe_error` has no I/O, no side effects, and
  does not log. Tracing happens at the caller boundary.

## Installation

```bash
pip install neoaxios-stripe-kit
```

Or from the monorepo:

```bash
pip install -e neo-packages/foundation/stripe_kit
```

## Quick start

```python
import stripe
from neoaxios_stripe_kit import (
    StripeAdapterError,
    StripeAuthError,
    StripeAPIError,
    translate_stripe_error,
)

stripe.api_key = "sk_test_..."

def create_customer(email: str) -> stripe.Customer:
    try:
        return stripe.Customer.create(email=email)
    except stripe.error.StripeError as exc:
        raise translate_stripe_error(exc) from exc


# Caller:
try:
    customer = create_customer("user@example.com")
except StripeAuthError:
    # Bad API key — rotate via your credential-rotation procedure.
    raise
except StripeAPIError:
    # Transient — caller may retry through its resilience layer.
    raise
except StripeAdapterError:
    # Anything else (invalid request, signature mismatch, etc.) — caller-fault.
    raise
```

## Webhook signature verification

```python
import stripe
from neoaxios_stripe_kit import StripeSignatureVerificationError, translate_stripe_error

def verify(payload: bytes, sig_header: str, secret: str) -> dict:
    try:
        return stripe.Webhook.construct_event(payload, sig_header, secret)
    except stripe.error.SignatureVerificationError as exc:
        raise translate_stripe_error(exc) from exc

# Route handler:
try:
    event = verify(request.body, request.headers["Stripe-Signature"], secret)
except StripeSignatureVerificationError:
    raise HTTPException(401, "invalid Stripe signature")
```

## License

Apache 2.0. See [LICENSE](LICENSE).
