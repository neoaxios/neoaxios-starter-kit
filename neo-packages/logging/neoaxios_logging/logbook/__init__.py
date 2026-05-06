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
Logbook - Production application logging.

This package provides:
- logbook.py: Main Logbook implementation (structlog-based)
- export.py: TelemetryExporter for log analysis and export

Features:
- Structured JSON logging
- Function entry/exit tracking
- Context tracking via contextvars
- Metrics and events
- Timer context manager
- Export and analysis tools

Usage:
    from neoaxios_logging.logbook import get_telemetry

    logbook = get_telemetry("my_component")
    logbook.log_entry(user_id=123)
    # ... do work ...
    logbook.log_exit(return_code=0)
"""

from .core.logbook import (
    Logbook,
    get_telemetry,
    get_logger,
    get_telemetry_log_path,
    with_telemetry,
)
from .core.decorators import auto_trace

from .export import (
    TelemetryExporter,
    setup_telemetry_hooks,
)


def get_enhanced_logger(component: str):
    """
    Get an enhanced logger with correlation tracking and performance monitoring.

    Note: This now returns a Logbook which provides the same enhanced
    features via structlog's contextvars support.

    Args:
        component: Component name for the logger

    Returns:
        Logbook instance with enhanced features
    """
    return get_telemetry(component)


def is_enhanced_logging_enabled() -> bool:
    """
    Check if enhanced logging features are enabled.

    Note: Enhanced logging is now always available via structlog.
    This function always returns True.

    Returns:
        True (enhanced logging via structlog is always available)
    """
    return True


__all__ = [
    # Core classes
    'Logbook',

    # Factory functions
    'get_telemetry',
    'get_logger',
    'get_enhanced_logger',

    # Decorators
    'with_telemetry',
    'auto_trace',

    # Export and analysis
    'TelemetryExporter',
    'setup_telemetry_hooks',

    # Utility functions
    'is_enhanced_logging_enabled',
    'get_telemetry_log_path',
]
