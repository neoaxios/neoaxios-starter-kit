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

"""HMAC-SHA256 inter-service request signing + verification primitives.

Single source of truth for the canonical form + sign / verify functions
used by every service-to-service call that cannot yet rely on mTLS via
the service mesh.  Callers import from :mod:`neoaxios_fastapi_kit.auth`.

Public surface (stable wire contract):

    canonical_message(*, method, path, body, timestamp, nonce) -> bytes
        Build the exact byte string bound by HMAC-SHA256.  The canonical
        form is intentionally minimal (no header folding, no query
        sorting) because signed inter-service endpoints use stable paths
        + JSON bodies — any divergence between signer and verifier is
        a bug.

    generate_nonce() -> str
        Cryptographically-random 32-character hex token
        (16 random bytes).

    sign_request(*, method, path, body, shared_secret, timestamp=None,
                 nonce=None) -> dict[str, str]
        Returns the header triplet to attach to an outgoing request:
        ``{X-Neo-Signature, X-Neo-Timestamp, X-Neo-Nonce}``.

    verify_request(*, method, path, body, headers, shared_secret,
                   now=None, tolerance_seconds=...) -> None
        Raises :class:`SignatureInvalidError` or
        :class:`SignatureExpiredError` on any failure.  Successful
        verification returns ``None``.

Canonical byte form (MUST stay stable — covered by the cross-module
contract test under ``tests/unit/auth/test_inter_service.py``)::

    {METHOD}\\n{PATH}\\n{TIMESTAMP}\\n{NONCE}\\n{BODY_BYTES}

Signature = ``HMAC-SHA256(shared_secret, canonical_message).hex()``.

Replay protection:
    The verifier enforces ``abs(now - timestamp) <= tolerance_seconds``
    where ``tolerance_seconds`` defaults to
    :data:`secure_cache.defaults.INTER_SERVICE_HMAC_TIMESTAMP_TOLERANCE_SECONDS`
    (centrally managed — no hardcoded literals).  Nonce
    dedup (Redis SETNX or similar) is a caller responsibility if the
    threat model requires it; the current services operate on an
    internal LAN with TLS already terminated between services, so the
    timestamp window is the defence-in-depth layer.

Notes:
    Signatures are never logged verbatim; only the 8-character prefix
    appears in log context so operators can correlate incidents without
    replay risk.

    Signature failures raise; there is no "sign if possible / allow if
    possible" branch.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode

from neoaxios_secure_cache.defaults import (
    INTER_SERVICE_HMAC_TIMESTAMP_TOLERANCE_SECONDS,
)
from neoaxios_secure_config import SecretStr
from neoaxios_logging import auto_trace, get_telemetry

if TYPE_CHECKING:  # pragma: no cover - typing-only
    from fastapi import Request

logger = get_telemetry(__name__)


__all__ = [
    "canonical_message",
    "canonical_path_with_sorted_query",
    "generate_nonce",
    "sign_request",
    "verify_request",
    "verify_signed_request_or_raise",
    "SignatureInvalidError",
    "SignatureExpiredError",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "NONCE_HEADER",
]


# Header names pinned by the wire contract.
SIGNATURE_HEADER = "X-Neo-Signature"
TIMESTAMP_HEADER = "X-Neo-Timestamp"
NONCE_HEADER = "X-Neo-Nonce"


class SignatureInvalidError(ValueError):
    """Raised when a signature does not match the canonical message.

    Route handlers translate this to HTTP 401.  The original signature
    value is NOT included in the exception message so log plumbing
    cannot leak it.
    """


class SignatureExpiredError(ValueError):
    """Raised when a timestamp is outside the tolerance window."""


# notrace: pure canonicalization; stable across caller/verifier for constant-time comparison
def canonical_message(
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    nonce: str,
) -> bytes:
    """Build the canonical byte string for signing.

    Args:
        method: HTTP method, uppercased (``POST``).  Callers that
            pass lowercased input are normalised inside
            :func:`sign_request` / :func:`verify_request`; this helper
            itself does NOT uppercase so tests can exercise canonical
            drift directly.
        path: URL path including path params, excluding query string.
            Must match byte-for-byte between caller and verifier.
        body: Exact request body bytes.  The caller MUST pass the same
            bytes to the HTTP client (``httpx.post(content=body)``) so
            the verifier observes byte-identical input.
        timestamp: Unix seconds (int).  Drives the tolerance window.
        nonce: Hex-encoded random token (32 hex chars = 16 random
            bytes from :func:`generate_nonce`).

    Returns:
        The canonical byte string that goes into HMAC-SHA256.
    """
    header = (
        f"{method}\n"
        f"{path}\n"
        f"{timestamp}\n"
        f"{nonce}\n"
    ).encode("utf-8")
    return header + body


# notrace: pure URL canonicaliser; O(N log N) sort on a tiny query set
def canonical_path_with_sorted_query(
    *,
    path: str,
    query_items: list[tuple[str, str]],
) -> str:
    """Build a canonical ``path?sorted_query`` string for signing.

    The default :func:`canonical_message` excludes the query string
    by design so routes that carry filter parameters in the URL
    (e.g. ``GET /internal/reports?client_id=X``) must cover those
    parameters explicitly.  This helper produces the canonical form
    that both the signer (outbound client) and the verifier (inbound
    route) pass as the ``path`` argument to :func:`sign_request` /
    :func:`verify_request` respectively.

    Sort order:
        ``(name, value)`` — deterministic regardless of the wire
        order the HTTP client put the parameters in, so a caller
        can assemble the URL however it likes and the signature
        still verifies.  Repeated names (multi-value query params)
        are kept in value-sorted order so adding a second value
        does not reorder the first.

    URL encoding:
        :func:`urllib.parse.urlencode` with the default
        ``quote_via=quote_plus`` matches Starlette's inbound
        decoding so round-tripping is lossless for the canonical
        comparison.

    Args:
        path: Request path excluding query (e.g.
            ``"/internal/reports"``).
        query_items: ``(name, value)`` pairs carrying the query
            parameters to include in the signature.  An empty list
            yields just *path* (no trailing ``?``).

    Returns:
        ``"{path}?{sorted&encoded_query}"`` when *query_items* is
        non-empty; just *path* otherwise.
    """
    if not query_items:
        return path
    sorted_pairs = sorted(query_items, key=lambda kv: (kv[0], kv[1]))
    return f"{path}?{urlencode(sorted_pairs)}"


@auto_trace(logger)
def generate_nonce() -> str:
    """Generate a cryptographically-random nonce for inter-service calls.

    Returns:
        32-character hex string derived from 16 random bytes.
    """
    return secrets.token_hex(16)


@auto_trace(logger)
def sign_request(
    *,
    method: str,
    path: str,
    body: bytes,
    shared_secret: SecretStr,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Sign an inter-service HTTP request.

    Args:
        method: HTTP method.  Uppercased before canonicalization so
            callers need not normalise.
        path: Request path; see :func:`canonical_message`.
        body: Request body bytes.
        shared_secret: Shared HMAC secret as :class:`SecretStr`.
        timestamp: Unix seconds override (defaults to
            ``int(time.time())``).  Passed explicitly only in tests or
            for replay of a known request.
        nonce: Hex-encoded nonce override (defaults to a fresh 16-byte
            token from :func:`generate_nonce`).

    Returns:
        Mapping of headers to attach to the outgoing request::

            {"X-Neo-Signature": "<hex>", "X-Neo-Timestamp": "<int>",
             "X-Neo-Nonce": "<hex>"}
    """
    ts = timestamp if timestamp is not None else int(time.time())
    nonce_val = nonce if nonce is not None else generate_nonce()
    canonical = canonical_message(
        method=method.upper(),
        path=path,
        body=body,
        timestamp=ts,
        nonce=nonce_val,
    )
    mac = hmac.new(
        shared_secret.get_secret_value().encode("utf-8"),
        canonical,
        hashlib.sha256,
    )
    signature = mac.hexdigest()
    logger.info(
        "inter_service_request_signed",
        context={
            "method": method.upper(),
            "path": path,
            "signature_prefix": signature[:8],
            "timestamp": ts,
        },
    )
    return {
        SIGNATURE_HEADER: signature,
        TIMESTAMP_HEADER: str(ts),
        NONCE_HEADER: nonce_val,
    }


@auto_trace(logger)
def verify_request(
    *,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str] | Any,
    shared_secret: SecretStr,
    now: int | None = None,
    tolerance_seconds: int = INTER_SERVICE_HMAC_TIMESTAMP_TOLERANCE_SECONDS,
) -> None:
    """Verify an inter-service HTTP request.

    Args:
        method: Received HTTP method (e.g. ``request.method``).
        path: Received path (e.g. ``request.url.path``).
        body: Raw body bytes.  MUST be the pre-parse bytes; parsing
            mutates whitespace.
        headers: Dict-like access to the incoming request headers.
            Case-insensitive lookup is attempted against the exact,
            lowercased, and uppercased variants of each header name so
            the caller can pass FastAPI ``Request.headers``,
            ``httpx.Headers``, plain dicts, or
            ``requests.structures.CaseInsensitiveDict`` unchanged.
        shared_secret: Shared HMAC secret.
        now: Override for the current unix seconds (test-only).
        tolerance_seconds: Max allowed age for the timestamp.  Default
            comes from
            :data:`INTER_SERVICE_HMAC_TIMESTAMP_TOLERANCE_SECONDS` so
            the value is centrally managed.

    Raises:
        SignatureInvalidError: Headers missing / malformed, or the
            computed signature does not match the received signature.
        SignatureExpiredError: Timestamp is older than
            ``tolerance_seconds`` (or too far in the future by the
            same margin).
    """
    sig = _header_lookup(headers, SIGNATURE_HEADER)
    ts_raw = _header_lookup(headers, TIMESTAMP_HEADER)
    nonce = _header_lookup(headers, NONCE_HEADER)

    if sig is None or ts_raw is None or nonce is None:
        logger.log_error(
            SignatureInvalidError("missing signature headers"),
            context={
                "method": method,
                "path": path,
                "has_sig": sig is not None,
                "has_ts": ts_raw is not None,
                "has_nonce": nonce is not None,
            },
        )
        raise SignatureInvalidError("missing signature headers")

    try:
        ts = int(ts_raw)
    except (TypeError, ValueError) as exc:
        logger.log_error(
            SignatureInvalidError("timestamp header is not an integer"),
            context={"method": method, "path": path},
        )
        raise SignatureInvalidError(
            "timestamp header is not an integer"
        ) from exc

    current = now if now is not None else int(time.time())
    age = abs(current - ts)
    if age > tolerance_seconds:
        logger.log_error(
            SignatureExpiredError(
                f"timestamp age {age}s exceeds tolerance {tolerance_seconds}s"
            ),
            context={
                "method": method,
                "path": path,
                "age_seconds": age,
                "tolerance_seconds": tolerance_seconds,
            },
        )
        raise SignatureExpiredError(
            f"timestamp age {age}s exceeds tolerance"
        )

    canonical = canonical_message(
        method=method.upper(),
        path=path,
        body=body,
        timestamp=ts,
        nonce=nonce,
    )
    mac = hmac.new(
        shared_secret.get_secret_value().encode("utf-8"),
        canonical,
        hashlib.sha256,
    )
    expected_sig = mac.hexdigest()

    if not hmac.compare_digest(expected_sig, sig):
        logger.log_error(
            SignatureInvalidError("signature mismatch"),
            context={
                "method": method,
                "path": path,
                "signature_prefix": sig[:8] if sig else "",
                "expected_prefix": expected_sig[:8],
            },
        )
        raise SignatureInvalidError("signature mismatch")

    logger.info(
        "inter_service_request_verified",
        context={
            "method": method.upper(),
            "path": path,
            "signature_prefix": sig[:8],
            "age_seconds": age,
        },
    )


# notrace: pure helper, no I/O, no branching worth tracing
def _header_lookup(
    headers: dict[str, str] | Any, name: str
) -> str | None:
    """Case-insensitive header lookup tolerant of dict / multimap types.

    FastAPI ``Request.headers`` is a multimap; ``httpx.Headers`` is too.
    Plain dicts and ``requests.structures.CaseInsensitiveDict`` also
    work here.
    """
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is not None:
            return value
        value = headers.get(name.lower())
        if value is not None:
            return value
        value = headers.get(name.upper())
        if value is not None:
            return value
    return None


# ---------------------------------------------------------------------------
# HTTP error mapping
# ---------------------------------------------------------------------------
#
# The shared helper below wraps :func:`verify_request` with a consistent
# HTTP 401 mapping of :class:`SignatureExpiredError` /
# :class:`SignatureInvalidError`, so any future change (e.g. adding
# correlation ids, widening the 401 body schema) only needs to land
# here.
#
# Kept as a direct-call helper rather than a FastAPI ``Depends(...)``
# dependency because every caller reads the request body BEFORE
# verification (the HMAC must cover the exact bytes that were received
# — letting FastAPI's body-parsing dependency-injection system consume
# the body first would break the signed-bytes contract).


@auto_trace(logger)
async def verify_signed_request_or_raise(
    request: "Request",
    *,
    body: bytes,
    shared_secret: SecretStr,
    op_label: str,
    canonical_path: str | None = None,
) -> None:
    """Verify HMAC on a FastAPI request or raise structured HTTP 401.

    Shared HTTP error mapping for signed inter-service routes.
    Call from inside a route handler AFTER reading the body and AFTER
    resolving the shared secret from ``app.state``; on signature
    failure this raises :class:`fastapi.HTTPException` with a
    structured body the client can decode.

    Args:
        request: The incoming FastAPI :class:`Request`. The helper
            reads ``request.method``, ``request.url.path`` and
            ``request.headers`` — nothing else — so callers retain full
            control over body handling.
        body: Raw request body bytes. MUST be the pre-parse bytes
            captured via ``await request.body()``; any re-reading
            through pydantic mutates whitespace and breaks the HMAC.
        shared_secret: Shared HMAC secret, resolved by the caller from
            ``app.state``.
        op_label: Short operation tag (e.g. ``"resource_route_sig_verify"``,
            ``"keys_signed_request"``) that appears in the
            log context on verification failure so operators can
            distinguish routes when correlating 401s across services.
        canonical_path: Optional override for the path the caller
            signed over.  GET routes whose filters live in the query
            string MUST pass the sorted-query-encoded path (e.g.
            ``"/internal/reports?client_id=X&limit=50"``) built with
            :func:`canonical_path_with_sorted_query` so the signature
            covers those parameters.  When ``None`` (default), the
            helper verifies against ``request.url.path`` which
            excludes the query string by design — the right choice
            for POST routes whose filters live in the JSON body and
            GET routes that take no query parameters.

    Raises:
        HTTPException: HTTP 401 with one of two structured bodies:

            - ``{"error": {"code": "signature_expired",
                           "message": "..."}}`` — timestamp outside
              tolerance (:class:`SignatureExpiredError`).
            - ``{"error": {"code": "invalid_signature",
                           "message": "..."}}`` — HMAC mismatch or
              missing / malformed headers
              (:class:`SignatureInvalidError`).

    Notes:
        503 mapping for a missing shared secret is intentionally NOT in
        scope — the caller's app-state resolver already maps that to
        ``internal_signing_not_configured`` with a route-specific
        error message. Keeping secret resolution in the caller avoids
        a two-way dependency between this module and every service's
        ``app.state`` shape.
    """
    # HTTPException is imported here rather than at module scope so
    # ``neoaxios_fastapi_kit.auth.inter_service`` remains importable in contexts
    # that do not have FastAPI available (pure signing callers).
    from fastapi import HTTPException, status

    path_to_verify = (
        canonical_path if canonical_path is not None else request.url.path
    )
    try:
        verify_request(
            method=request.method,
            path=path_to_verify,
            body=body,
            headers=dict(request.headers),
            shared_secret=shared_secret,
        )
    except SignatureExpiredError as exc:
        logger.log_error(exc, context={"op": op_label})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "signature_expired",
                    "message": (
                        "Inter-service signature timestamp outside tolerance."
                    ),
                }
            },
        ) from exc
    except SignatureInvalidError as exc:
        logger.log_error(exc, context={"op": op_label})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "invalid_signature",
                    "message": (
                        "Inter-service signature verification failed."
                    ),
                }
            },
        ) from exc
