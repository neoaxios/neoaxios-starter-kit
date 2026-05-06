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

"""Shared startup helpers for FastAPI services.

Two primitives that every service assembles identically during
lifespan setup:

- :func:`sanitize_postgres_url` -- redact userinfo from a Postgres DSN
  before it lands in a log line.  The sanitizer exists so log emission
  can never itself leak credentials.  A malformed DSN must not raise
  from a logging call, so the helper returns the literal string
  ``"<unparseable>"`` on parse failure; the downstream connection
  attempt is where configuration errors surface loudly.

- :func:`generate_consumer_name` -- mint a Redis Streams consumer-group
  member name of the form ``{hostname}-{pid}-{uuid8}`` (or
  ``{hostname}-{pid}-{uuid8}-{suffix}`` when a suffix is supplied).
  Used by every service that consumes from a Redis consumer group; the
  hostname + pid + uuid combination makes the identity unique per
  process instance, while the optional suffix lets a single process
  distinguish multiple consumer groups.

Note:
    The log sanitizer must not raise on a malformed DSN; the downstream
    connection attempt surfaces the parse error loudly while this helper
    stays safe for log emission.
"""

from __future__ import annotations

import os
import socket
import uuid
from urllib.parse import urlparse

from neoaxios_logging import auto_trace, get_telemetry


logger = get_telemetry(__name__)


@auto_trace(logger)
def sanitize_postgres_url(raw: str) -> str:
    """Redact userinfo from a Postgres DSN for safe logging.

    Returns ``{scheme}://{host}:{port}/{db}`` without userinfo.  When
    the URL has no userinfo, returns the same fields without change.
    When parsing fails, returns ``"<unparseable>"`` so the caller can
    emit a safe, non-secret value from a log line.

    Args:
        raw: The Postgres DSN read from config, potentially containing
            ``user:password`` userinfo.

    Returns:
        A string suitable for logging: either the redacted DSN or the
        sentinel ``"<unparseable>"`` on parse failure.
    """
    try:
        p = urlparse(raw)
    except ValueError:
        # The log sanitizer must not raise on a malformed DSN; the
        # downstream connection attempt surfaces the parse error
        # loudly, while this helper stays safe for log emission.
        return "<unparseable>"
    host = p.hostname or ""
    port = f":{p.port}" if p.port is not None else ""
    db = p.path or ""
    return f"{p.scheme}://{host}{port}{db}"


@auto_trace(logger)
def generate_consumer_name(suffix: str | None = None) -> str:
    """Build a Redis Streams consumer-group member identifier.

    Produces a ``{hostname}-{pid}-{uuid8}`` identifier, or
    ``{hostname}-{pid}-{uuid8}-{suffix}`` when ``suffix`` is supplied.
    The hostname + pid + uuid combination makes the identity unique
    per process instance; the optional suffix lets a single process
    run multiple consumer groups with distinguishable member names
    (e.g. one consumer per violation severity tier).

    Pattern source:
    ``neoaxios_fastapi_kit/storage/message_queue.py:73-76``.

    Args:
        suffix: Optional tag appended to the identity (typically the
            consumer-group name).  When ``None`` the bare
            ``{hostname}-{pid}-{uuid8}`` form is returned.

    Returns:
        A string suitable for use as the ``consumer_name`` parameter to
        Redis ``XREADGROUP`` / consumer-group APIs.
    """
    hostname = socket.gethostname()
    pid = os.getpid()
    short_uuid = str(uuid.uuid4())[:8]
    base = f"{hostname}-{pid}-{short_uuid}"
    if suffix is None:
        return base
    return f"{base}-{suffix}"


__all__ = [
    "sanitize_postgres_url",
    "generate_consumer_name",
]
