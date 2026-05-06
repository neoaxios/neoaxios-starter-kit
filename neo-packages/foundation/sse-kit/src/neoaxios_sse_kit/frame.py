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

"""
SSE frame-boundary scanner — raw byte-level event extraction.

Provides :func:`extract_complete_events` for buffered-stream consumers that
need to split a rolling byte buffer into complete SSE events terminated
by a blank-line delimiter. Recognises BOTH ``b"\\n\\n"`` and
``b"\\r\\n\\r\\n"`` delimiters per W3C EventSource §6.

The scanner is READ-ONLY — callers own buffer mutation. The returned
``residual`` is the tail of the input that has not yet terminated on a
blank line (typically an in-progress event awaiting more bytes).

Byte-preservation contract: returned event segments include the
terminating delimiter verbatim — the signer-side window buffer and the
verifier-side receive buffer hash byte-identical sequences when they
read through this helper. No normalisation, no CR/LF rewriting, no
delimiter stripping.

This is the single source of truth for SSE frame detection: byte
preservation, CR/LF honoured, read-only scan.
"""

from __future__ import annotations

__all__ = ["extract_complete_events"]


# notrace: pure byte scan on the per-chunk hot path — enclosing
# stream-processing generators trace at scope (``@auto_trace`` /
# ``include_args=False``); per-chunk tracing would explode log volume on
# multi-kilobyte streams.
def extract_complete_events(
    buffer: bytes | bytearray,
) -> tuple[list[bytes], bytearray]:
    """Split a rolling byte buffer on the SSE event-terminator delimiter.

    Per W3C EventSource §6 an event is terminated by a blank line,
    which may be either ``\\n\\n`` (LF-only) or ``\\r\\n\\r\\n`` (CRLF).
    The scanner recognises both and honours whichever appears first at
    each cursor position (mixed-mode upstreams that switch delimiter
    style mid-stream are split correctly).

    Returned event segments include the matched delimiter verbatim
    (preserving raw SSE wire bytes with delimiters intact):
    ``b"data: foo\\n\\n"`` for LF-only, ``b"data: foo\\r\\n\\r\\n"``
    for CRLF. No normalisation. The scanner NEVER rewrites ``buffer``
    contents.

    Args:
        buffer: Rolling byte buffer; may be ``bytes`` or ``bytearray``.
            Treated as immutable — the scanner reads from a snapshot.

    Returns:
        A tuple ``(complete_events, residual)``:
            * ``complete_events`` — list of byte segments each
              terminated by an SSE delimiter (LF-only or CRLF).
              Delimiters are preserved verbatim.
            * ``residual`` — trailing bytes that did not yet
              terminate on a blank line (partial event). Callers
              typically store this back into the buffer so the next
              chunk appends to the partial event.

    Examples:
        >>> extract_complete_events(b"data: a\\n\\ndata: b\\n\\n")
        ([b'data: a\\n\\n', b'data: b\\n\\n'], bytearray(b''))

        >>> extract_complete_events(b"data: a\\r\\n\\r\\ndata: partial")
        ([b'data: a\\r\\n\\r\\n'], bytearray(b'data: partial'))

        >>> extract_complete_events(b"data: a\\n\\ndata: b\\r\\n\\r\\n")
        ([b'data: a\\n\\n', b'data: b\\r\\n\\r\\n'], bytearray(b''))
    """
    events: list[bytes] = []
    cursor = 0
    data = bytes(buffer)
    length = len(data)
    while cursor < length:
        lf_idx = data.find(b"\n\n", cursor)
        crlf_idx = data.find(b"\r\n\r\n", cursor)
        # Pick the earliest valid delimiter position; match the
        # matching delimiter's length so the returned segment
        # includes the exact terminator bytes.
        if lf_idx == -1 and crlf_idx == -1:
            break
        if crlf_idx != -1 and (lf_idx == -1 or crlf_idx < lf_idx):
            end = crlf_idx + 4
        else:
            end = lf_idx + 2
        events.append(data[cursor:end])
        cursor = end
    residual = bytearray(data[cursor:])
    return events, residual
