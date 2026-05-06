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

"""Redis Streams shared utilities for XADD and response decoding.

Extracted from neoaxios_fastapi_kit's ``StreamDispatcher`` (XADD pattern)
and ``RedisMessageQueue`` (bytes-to-str decoding) to provide reusable
stream primitives for any package that interacts with Redis Streams.

Usage:
    from neoaxios_secure_cache.redis.streams import stream_add, decode_fields

    message_id = await stream_add(redis, "my-stream", {"key": "val"})
    decoded = decode_fields({b"key": b"val"})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_secure_cache.defaults import STREAM_MAXLEN

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = get_telemetry(__name__)


@auto_trace(logger)
async def stream_add(
    redis: Redis,
    stream_key: str,
    fields: dict[str, Any],
    *,
    maxlen: int | None = None,
) -> str:
    """Add a message to a Redis Stream via XADD with bytes normalization.

    Wraps ``redis.xadd()`` with approximate MAXLEN trimming and
    normalizes the returned message ID from bytes to str when the
    Redis client returns bytes.

    Args:
        redis: Async Redis client for stream operations.
        stream_key: Fully-qualified stream key (caller is responsible
            for namespace prefixing via ``CacheNamespace.make_key()``
            before calling this function).
        fields: Message field dict to write. Values are passed through
            to XADD as-is (Redis converts to strings internally).
        maxlen: Optional maximum stream length for approximate trimming.
            Defaults to ``STREAM_MAXLEN`` from ``secure_cache.defaults``
            when ``None``.

    Returns:
        Redis Stream message ID as a str (e.g. ``"1234567890-0"``).
    """
    effective_maxlen = maxlen if maxlen is not None else STREAM_MAXLEN

    message_id: str = await redis.xadd(  # type: ignore[assignment]
        stream_key,
        fields,
        maxlen=effective_maxlen,
    )

    # Redis may return bytes in some client configurations; normalize.
    result: str = message_id.decode() if isinstance(message_id, bytes) else message_id
    return result


@auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
def decode_fields(
    fields: dict[bytes | str, bytes | str],
) -> dict[str, str]:
    """Decode Redis bytes keys and values to str.

    Handles mixed bytes/str dicts returned by XREADGROUP, XAUTOCLAIM,
    and XCLAIM responses. Pre-decoded str values pass through unchanged.

    Args:
        fields: Raw field dict from Redis stream response.

    Returns:
        Dict with all keys and values as str.
    """
    decoded: dict[str, str] = {}
    for key, value in fields.items():
        str_key = key.decode() if isinstance(key, bytes) else key
        str_value = value.decode() if isinstance(value, bytes) else value
        decoded[str_key] = str_value
    return decoded
