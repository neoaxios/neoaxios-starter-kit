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
NeoAxios Telemetry Package

Three-tier architecture for telemetry, logging, and debugging:
1. Logbook - Production application logging (off by default)
2. FlightRecorder - Test/debug timeline recording (on by default)
3. Diagnostics - Environment validation and health checks

This package provides comprehensive logging, metrics, and debugging capabilities
using a unified structlog-based architecture.

Components:
- logbook: Production structured logging
- flight_recorder: Timeline-based event recording with integrated process tracking
- diagnostics: Environment validation and health checks
- performance: Performance analysis and regression detection (FlightRecorder tooling)
- config: Centralized configuration management
- common: Shared types and utilities

Environment Variables:
- TELEMETRY_ENABLED: Enable/disable Logbook (default: false)
- TELEMETRY_LEVEL: Log level (DEBUG, INFO, WARNING, ERROR) (default: WARNING)
- TELEMETRY_CONSOLE: Enable console output (default: false)
- TELEMETRY_DIR: Directory for telemetry files (default: .telemetry)
- TELEMETRY_FORMAT: Log format (json or text) (default: json)
- FLIGHT_RECORDER_ENABLED: Enable FlightRecorder (default: true)
- PERFORMANCE_TRACKING: Enable performance tracking (default: true)
- DIAGNOSTICS_ENABLED: Enable diagnostics (default: true)

Configuration:
    Create telemetry.yaml in your project root:

    version: "1.0"
    logbook:
      enabled: true
      level: INFO
    flight_recorder:
      enabled: true
      buffering: true
    performance:
      enabled: true
    diagnostics:
      enabled: true

Basic Usage - Logbook (Modern @auto_trace pattern):
    from neoaxios_logging import get_telemetry, auto_trace

    logger = get_telemetry("my_component")

    @auto_trace(logger)
    def process_data(user_id: int):
        logger.info("Processing started", user_id=user_id)
        # ... work ...
        return result

FlightRecorder Usage:
    from neoaxios_logging.flight_recorder import FlightRecorder

    with FlightRecorder("test_name") as fr:
        fr.emit("checkpoint", level=LogLevel.INFO)
        fr.emit_process_start(1234, ["pytest", "test.py"])
        fr.emit_process_end(1234, exit_code=0)

Configuration Usage:
    from neoaxios_logging.config import get_config_manager

    config = get_config_manager().load()
    print(f"Logbook enabled: {config.logbook.enabled}")
    print(f"Performance tracking: {config.performance.enabled}")
"""

__version__ = "0.2.1"

# Core Logbook exports
from .logbook import (
    Logbook,
    get_telemetry,
    get_logger,
    get_telemetry_log_path,
    with_telemetry,
    auto_trace,
    get_enhanced_logger,
    is_enhanced_logging_enabled,
    TelemetryExporter,
    setup_telemetry_hooks,
)

# Common types
from .common import (
    LogLevel,
    EventType,
    TraceDisabledReason,
)

# FlightRecorder (explicit import recommended)
# from telemetry.flight_recorder import FlightRecorder, flight_recorded

# Config (explicit import recommended)
# from telemetry.config import get_config_manager, load_config

# Performance (explicit import recommended)
# from telemetry.flight_recorder import PerformanceAnalyzer

# Diagnostics (explicit import recommended)
# from telemetry.diagnostics import DiagnosticCheck


__all__ = [
    # Core Logbook
    'Logbook',
    'get_telemetry',
    'get_logger',
    'get_telemetry_log_path',
    'with_telemetry',
    'auto_trace',
    'get_enhanced_logger',
    'is_enhanced_logging_enabled',

    # Export and analysis
    'TelemetryExporter',
    'setup_telemetry_hooks',

    # Common types
    'LogLevel',
    'EventType',
    'TraceDisabledReason',

    # Sub-packages (import explicitly when needed):
    # - Configuration: from telemetry.config import get_config_manager, load_config
    # - FlightRecorder: from telemetry.flight_recorder import FlightRecorder, flight_recorded
    # - Performance: from telemetry.flight_recorder import PerformanceAnalyzer
    # - Diagnostics: from telemetry.diagnostics import DiagnosticCheck
]
