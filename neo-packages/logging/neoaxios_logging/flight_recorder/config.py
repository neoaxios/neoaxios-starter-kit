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
FlightRecorder Configuration

Configuration for FlightRecorder and its performance analysis tooling.
"""

from dataclasses import dataclass

# Default configuration
DEFAULT_TELEMETRY_DIR = ".telemetry"
DEFAULT_PERFORMANCE_HISTORY_SIZE = 100


@dataclass
class FlightRecorderConfig:
    """FlightRecorder timeline recording configuration."""

    enabled: bool = True  # Enable FlightRecorder persistence
    directory: str = f"{DEFAULT_TELEMETRY_DIR}/flight_recorder"  # FlightRecorder output directory
    buffering: bool = True  # Enable buffering for performance
    buffer_size: int = 100  # Number of events to buffer before writing
    auto_flush_on_critical: bool = True  # Automatically flush buffer on ERROR/CRITICAL events
    cleanup_old_recordings: bool = True  # Clean up old recordings
    recording_retention_days: int = 7  # How long to keep recordings



@dataclass
class PerformanceConfig:
    """Performance tracking and analysis configuration (uses FlightRecorder)."""

    enabled: bool = True  # Enable performance tracking
    max_history_size: int = DEFAULT_PERFORMANCE_HISTORY_SIZE  # Number of historical runs to keep per test
    history_file: str = f"{DEFAULT_TELEMETRY_DIR}/performance_history.json"  # Path to performance history file
    track_individual_tests: bool = True  # Track individual test durations
    batch_recording: bool = True  # Use batch recording for better performance
    cleanup_old_reports: bool = True  # Clean up old JSON report files
    report_retention_days: int = 30  # How long to keep JSON reports


__all__ = [
    'FlightRecorderConfig',
    'PerformanceConfig',
    'DEFAULT_TELEMETRY_DIR',
    'DEFAULT_PERFORMANCE_HISTORY_SIZE',
]
