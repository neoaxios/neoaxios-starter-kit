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
NeoAxios SSE Kit - Server-Sent Events parsing and formatting.

Provides SSEEvent dataclass, parse_sse_event for parsing text/event-stream
data into typed event objects, and format_sse_event for serializing dicts
into SSE wire format. Shared foundation package consumed by cli-kit,
and neoaxios_fastapi_kit.
"""

from neoaxios_sse_kit.event import SSEEvent, parse_sse_event
from neoaxios_sse_kit.format import format_sse_event
from neoaxios_sse_kit.frame import extract_complete_events

__all__ = [
    "SSEEvent",
    "extract_complete_events",
    "format_sse_event",
    "parse_sse_event",
]
