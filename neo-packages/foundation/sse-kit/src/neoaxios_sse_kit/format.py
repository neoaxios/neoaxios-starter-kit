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
SSE event formatter.

Formats Python dicts as W3C Server-Sent Events text. This is the inverse
of ``parse_sse_event`` — it serializes structured data into the
``text/event-stream`` wire format.
"""

from __future__ import annotations

import json

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@auto_trace(logger)
def format_sse_event(
    data: dict,
    *,
    event: str | None = None,
    event_id: str | None = None,
    retry: int | None = None,
) -> str:
    """Format data as an SSE string.

    Builds a W3C-compliant Server-Sent Events frame from the provided
    parameters.  The ``data`` dict is JSON-encoded into a single
    ``data:`` line.  Optional ``event:``, ``id:``, and ``retry:`` lines
    are prepended when the corresponding arguments are not None.

    Args:
        data: Event data payload (must be JSON-serializable dict).
        event: Optional SSE event type (``event:`` line).
        event_id: Optional event ID for resumption (``id:`` line).
        retry: Optional reconnection interval in milliseconds (``retry:`` line).

    Returns:
        SSE formatted string terminated by a double newline.
    """
    lines: list[str] = []

    if event is not None:
        lines.append(f"event: {event}")

    if event_id is not None:
        lines.append(f"id: {event_id}")

    if retry is not None:
        lines.append(f"retry: {retry}")

    json_data = json.dumps(data)
    lines.append(f"data: {json_data}")

    return "\n".join(lines) + "\n\n"
