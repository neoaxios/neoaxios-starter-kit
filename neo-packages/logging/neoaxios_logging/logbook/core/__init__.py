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
Core components for Logbook.

This module exports the core logging functionality including LogLevel enum,
Logbook class, and decorators.
"""

from neoaxios_logging.common.types import LogLevel
from neoaxios_logging.logbook.core.logbook import (
    Logbook,
    get_logger,
    get_telemetry,
    with_telemetry,
)
from neoaxios_logging.logbook.core.decorators import auto_trace

__all__ = [
    'LogLevel',
    'Logbook',
    'get_logger',
    'get_telemetry',
    'with_telemetry',
    'auto_trace',
]
