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

"""Pluggable serialization protocol with JSON and msgpack implementations.

This module defines the ``Serializer`` protocol and provides two concrete
implementations:

- ``JsonSerializer``: Deterministic JSON output using ``sort_keys=True`` and
  compact separators.  Suitable for use with ``SigningCacheWrapper`` where
  identical input must produce identical bytes (signature consistency).
- ``MsgpackSerializer``: Binary serialization via ``msgpack``.  Non-deterministic
  because msgpack does not guarantee dict key ordering across versions.
- ``SmartSerializer``: Auto-detecting deserializer that inspects the first byte
  of incoming data to decide whether to delegate to JSON or msgpack.  This
  enables gradual migration from JSON-encoded cache entries to msgpack without
  a cache flush.

Usage:
    from neoaxios_secure_cache.serialization import JsonSerializer, MsgpackSerializer, SmartSerializer

    # Deterministic JSON serializer (for signing wrappers)
    json_ser = JsonSerializer()
    data = json_ser.dumps({"key": "value"})
    value = json_ser.loads(data)

    # Binary msgpack serializer (for throughput)
    mp_ser = MsgpackSerializer()
    data = mp_ser.dumps({"key": "value"})
    value = mp_ser.loads(data)

    # Auto-detecting deserializer (for migration)
    smart = SmartSerializer()
    value = smart.loads(data)  # works with both JSON and msgpack bytes
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@runtime_checkable
class Serializer(Protocol):
    """Protocol for pluggable cache value serialization.

    All serializer implementations must provide ``dumps``, ``loads``, and the
    ``deterministic`` property.  The ``deterministic`` flag is consumed by
    ``SigningCacheWrapper`` to decide whether re-serialization of a value
    will produce byte-identical output (required for HMAC signature consistency).

    Example:
        class CustomSerializer:
            def dumps(self, value: Any) -> bytes: ...
            def loads(self, data: bytes) -> Any: ...

            @property
            def deterministic(self) -> bool: ...
    """

    def dumps(self, value: Any) -> bytes:
        """Serialize a Python value to bytes.

        Args:
            value: The value to serialize.  Must be compatible with the
                underlying format (JSON-serializable for JsonSerializer,
                msgpack-compatible for MsgpackSerializer).

        Returns:
            Serialized byte representation of *value*.
        """
        ...

    def loads(self, data: bytes) -> Any:
        """Deserialize bytes back to a Python value.

        Args:
            data: Byte string previously produced by ``dumps()`` (or
                compatible encoder).

        Returns:
            Deserialized Python object.
        """
        ...

    @property
    def deterministic(self) -> bool:
        """Whether serialization produces identical output for identical input.

        When ``True``, calling ``dumps(v)`` twice with the same *v* is
        guaranteed to yield byte-identical results.  Required by
        ``SigningCacheWrapper`` for HMAC signature consistency.

        Returns:
            ``True`` if output is deterministic, ``False`` otherwise.
        """
        ...


class JsonSerializer:
    """Deterministic JSON serializer.

    Produces compact, sorted JSON suitable for HMAC signing.  Uses
    ``sort_keys=True`` to guarantee dict key ordering and minimal
    separators ``(",", ":")`` to eliminate whitespace variation.

    Attributes:
        deterministic: Always ``True``.
    """

    @property
    def deterministic(self) -> bool:
        """Return ``True`` -- JSON output is deterministic with sorted keys."""
        return True

    @auto_trace(logger)
    def dumps(self, value: Any) -> bytes:
        """Serialize *value* to deterministic JSON bytes.

        Args:
            value: JSON-serializable Python object.

        Returns:
            UTF-8 encoded JSON bytes with sorted keys and compact separators.

        Raises:
            TypeError: If *value* is not JSON-serializable.
        """
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @auto_trace(logger)
    def loads(self, data: bytes) -> Any:
        """Deserialize JSON bytes to a Python value.

        Args:
            data: UTF-8 encoded JSON bytes.

        Returns:
            Deserialized Python object.

        Raises:
            json.JSONDecodeError: If *data* is not valid JSON.
        """
        return json.loads(data)


class MsgpackSerializer:
    """Binary msgpack serializer.

    Uses ``msgpack`` for compact binary serialization.  Non-deterministic
    because msgpack does not guarantee dict key ordering across library
    versions or platforms.

    Requires the ``msgpack`` package (``pip install msgpack>=1.0``).

    Attributes:
        deterministic: Always ``False``.
    """

    @property
    def deterministic(self) -> bool:
        """Return ``False`` -- msgpack output is not guaranteed deterministic."""
        return False

    @auto_trace(logger)
    def dumps(self, value: Any) -> bytes:
        """Serialize *value* to msgpack bytes.

        Args:
            value: msgpack-compatible Python object.

        Returns:
            Packed msgpack bytes.

        Raises:
            ImportError: If ``msgpack`` is not installed.
            TypeError: If *value* is not msgpack-serializable.
        """
        import msgpack

        return msgpack.packb(value, use_bin_type=True)

    @auto_trace(logger)
    def loads(self, data: bytes) -> Any:
        """Deserialize msgpack bytes to a Python value.

        Args:
            data: Packed msgpack bytes.

        Returns:
            Deserialized Python object.

        Raises:
            ImportError: If ``msgpack`` is not installed.
            msgpack.UnpackValueError: If *data* is not valid msgpack.
        """
        import msgpack

        return msgpack.unpackb(data, raw=False)


class SmartSerializer:
    """Auto-detecting serializer that routes to JSON or msgpack on ``loads()``.

    Inspects the first byte of incoming data to decide the format:

    - ``0x7b`` (``{``) or ``0x5b`` (``[``): delegates to ``JsonSerializer``
    - Any other first byte: delegates to ``MsgpackSerializer``

    For ``dumps()``, always delegates to the *primary* serializer (defaults
    to ``MsgpackSerializer``).  This enables gradual migration: new writes
    use msgpack while old JSON-encoded entries are still readable.

    Args:
        primary: Serializer used for ``dumps()``.  Defaults to
            ``MsgpackSerializer`` if not provided.

    Attributes:
        deterministic: Delegates to the primary serializer's property.
    """

    @auto_trace(logger)
    def __init__(self, primary: Serializer | None = None) -> None:
        """Initialize with a primary serializer for writes.

        Args:
            primary: Serializer used for ``dumps()``.  When ``None``,
                defaults to ``MsgpackSerializer``.
        """
        self._primary: Serializer = primary if primary is not None else MsgpackSerializer()
        self._json = JsonSerializer()
        self._msgpack = MsgpackSerializer()

        logger.info(
            "smart_serializer_initialized",
            primary=type(self._primary).__name__,
        )

    @property
    def deterministic(self) -> bool:
        """Delegate to the primary serializer's deterministic property."""
        return self._primary.deterministic

    @auto_trace(logger)
    def dumps(self, value: Any) -> bytes:
        """Serialize *value* using the primary serializer.

        Args:
            value: Value to serialize.

        Returns:
            Serialized bytes in the primary serializer's format.
        """
        return self._primary.dumps(value)

    @auto_trace(logger)
    def loads(self, data: bytes) -> Any:
        """Deserialize bytes by auto-detecting the format.

        Inspects the first byte:

        - ``0x7b`` (``{``) or ``0x5b`` (``[``): JSON
        - Anything else: msgpack

        Args:
            data: Serialized bytes (JSON or msgpack).

        Returns:
            Deserialized Python object.

        Raises:
            ValueError: If *data* is empty.
        """
        if not data:
            raise ValueError("Cannot deserialize empty data")

        first_byte = data[0]

        if first_byte == 0x7B or first_byte == 0x5B:
            logger.debug("smart_serializer_detected_json")
            return self._json.loads(data)

        logger.debug("smart_serializer_detected_msgpack")
        return self._msgpack.loads(data)
