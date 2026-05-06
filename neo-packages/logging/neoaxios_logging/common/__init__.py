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
Common utilities and types shared by all telemetry implementations.

This package contains:
- types.py: LogLevel, EventType enums and constants
- utils.py: Shared utility functions
"""

from .types import (
    LogLevel,
    EventType,
    TraceDisabledReason,
    DEFAULT_TELEMETRY_DIR,
    DEFAULT_TELEMETRY_LEVEL,
    DEFAULT_TELEMETRY_FORMAT,
    DEFAULT_FLIGHT_RECORDER_DIR,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_PERFORMANCE_HISTORY_SIZE,
    VALID_LOG_FORMATS,
    VALID_LOG_LEVELS,
)

from .utils import get_telemetry_dir

__all__ = [
    # Types and enums
    'LogLevel',
    'EventType',
    'TraceDisabledReason',

    # Constants
    'DEFAULT_TELEMETRY_DIR',
    'DEFAULT_TELEMETRY_LEVEL',
    'DEFAULT_TELEMETRY_FORMAT',
    'DEFAULT_FLIGHT_RECORDER_DIR',
    'DEFAULT_RETENTION_DAYS',
    'DEFAULT_PERFORMANCE_HISTORY_SIZE',
    'VALID_LOG_FORMATS',
    'VALID_LOG_LEVELS',

    # Utilities
    'get_telemetry_dir',
]
