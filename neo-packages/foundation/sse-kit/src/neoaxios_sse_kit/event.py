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
SSE event dataclass and parser.

Parses raw Server-Sent Events text (per the W3C EventSource specification)
into typed SSEEvent objects. Handles event:, data:, id:, retry:, and
comment lines (: prefix).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@dataclass
class SSEEvent:
    """Parsed Server-Sent Event.

    Attributes:
        event_type: Event type (e.g., "phase_completed", "message").
        data: Parsed JSON data payload.
        event_id: Optional event ID for resumption.
        retry: Optional retry interval in milliseconds.
    """

    event_type: str
    data: dict[str, Any]
    event_id: str | None = None
    retry: int | None = None


@auto_trace(logger)
def parse_sse_event(raw_event: str) -> SSEEvent | None:
    """Parse raw SSE event string into SSEEvent.

    Processes each line of the raw event text according to the SSE
    specification:
    - ``event:`` sets the event type (default: "message")
    - ``id:`` sets the event ID
    - ``retry:`` sets the retry interval (integer milliseconds)
    - ``data:`` appends to the data payload (multiple lines joined by newline)
    - ``:`` prefix indicates a comment line (ignored)

    Data lines are joined and parsed as JSON. If JSON parsing fails,
    the raw text is stored under a ``"raw"`` key.

    Args:
        raw_event: Raw SSE event text (may contain multiple lines).

    Returns:
        Parsed SSEEvent or None if no data lines are present.
    """
    event_type = "message"  # Default SSE event type
    event_id = None
    retry = None
    data_lines: list[str] = []

    for line in raw_event.strip().split("\n"):
        if line.startswith("event:"):
            event_type = line[6:].strip()
        elif line.startswith("id:"):
            event_id = line[3:].strip()
        elif line.startswith("retry:"):
            try:
                retry = int(line[6:].strip())
            except ValueError:
                logger.warning(
                    "Invalid retry value in SSE event",
                    retry_raw=line[6:].strip(),
                )
        elif line.startswith("data:"):
            data_lines.append(line[5:].strip())
        elif line.startswith(":"):
            # Comment line, ignore
            pass

    if not data_lines:
        return None

    # Join data lines and parse as JSON
    data_str = "\n".join(data_lines)
    try:
        parsed = json.loads(data_str)
        if not isinstance(parsed, dict):
            data = {"raw": data_str}
        else:
            data = parsed
    except json.JSONDecodeError:
        data = {"raw": data_str}

    return SSEEvent(
        event_type=event_type,
        data=data,
        event_id=event_id,
        retry=retry,
    )
