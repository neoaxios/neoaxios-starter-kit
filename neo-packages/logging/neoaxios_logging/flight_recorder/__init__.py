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
FlightRecorder - Test Execution Timeline Recording System

Records test execution timeline using structlog,
capturing events for post-mortem analysis of test failures.

Features:
- Buffered writes by default (buffer_size=100, flush every 1s) for performance
- Automatic flush on critical events (errors, exceptions, test boundaries)
- Thread-safe operation with proper locking
- Configurable buffer size and flush intervals
- Runtime enable/disable of buffering
- Optional immediate writes mode (buffer_size=0) for maximum crash safety
- Integrated process tracking with optional resource monitoring (psutil)

Usage:
    from neoaxios_logging.flight_recorder import FlightRecorder, flight_recorded

    # As decorator (buffered by default)
    @flight_recorded("test_execution")
    def my_test():
        # ... test code ...
        pass

    # As context manager (buffered by default)
    with FlightRecorder("my_operation") as fr:
        fr.emit("step_1", data="value")
        # ... work ...
        fr.emit("step_2", result="success")

    # Immediate writes mode (for crash safety)
    with FlightRecorder("test", buffer_size=0) as fr:
        fr.emit("critical_operation")  # Written immediately

Process Tracking:
    from neoaxios_logging.flight_recorder import FlightRecorder

    with FlightRecorder("test_execution") as fr:
        # Track subprocess execution
        fr.emit_process_start(1234, ["pytest", "test.py"], test_file="test.py")
        # Optional: enable resource monitoring with track_resources=True (requires psutil)
        fr.emit_process_start(1235, ["python", "script.py"], track_resources=True)

        # Track process completion
        fr.emit_process_end(1234, exit_code=0)

        # Track signals and timeouts
        fr.emit_signal_sent(1234, signal.SIGTERM)
        fr.emit_timeout(1234, timeout=30.0)
        fr.emit_cleanup_attempt("SIGTERM", [1234, 1235], success=True)

Query Utilities:
    from neoaxios_logging.flight_recorder.query import query_events, get_test_timeline, find_failures

    # Or use the main CLI:
    python -m telemetry.flight_recorder.query --test-name my_test --level ERROR
"""

from .flight_recorder import (
    FlightRecorder,
    flight_recorded,
    configure_flight_recorder,
    FlightRecorderProcessor
)

# Import LogLevel and EventType from common module
from ..common import LogLevel, EventType

# Query utilities (optional - import explicitly when needed)
# from .query import query_events, get_test_timeline, find_failures

__all__ = [
    # Core flight recorder
    'FlightRecorder',
    'flight_recorded',
    'configure_flight_recorder',
    'FlightRecorderProcessor',

    # Common types (re-exported for convenience)
    'LogLevel',
    'EventType',

    # Query utilities available at:
    # from telemetry.flight_recorder.query import query_events, get_test_timeline, find_failures
]
