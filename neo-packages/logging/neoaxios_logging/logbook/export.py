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

"""Telemetry export functionality for debugging"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from .core.logbook import get_telemetry


class TelemetryExporter:
    """Export telemetry data for analysis"""

    def __init__(self, output_dir: Path = None):
        if output_dir:
            self.output_dir = output_dir
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            from ..common import get_telemetry_dir

            self.output_dir = get_telemetry_dir() / "exports"
            self.output_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry = get_telemetry("exporter")

    def export_session(self, session_id: Optional[str] = None) -> Path:
        """Export current telemetry session"""
        if not session_id:
            session_id = f"session_{int(time.time())}"

        output_file = self.output_dir / f"{session_id}.json"

        # Get telemetry instance and export data
        data = self.telemetry.export_telemetry()

        # Add metadata
        export_data = {
            "session_id": session_id,
            "export_time": datetime.now().isoformat(),
            "telemetry_data": data,
        }

        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        self.telemetry.info("Telemetry exported", file=str(output_file))
        return output_file

    def analyze_hanging(self, session_file: Path) -> Dict[str, Any]:
        """Analyze telemetry for hanging issues"""
        with open(session_file, "r") as f:
            data = json.load(f)

        telemetry_data = data.get("telemetry_data", {})
        events = telemetry_data.get("events", [])
        metrics = telemetry_data.get("metrics", {})

        # Find long-running operations
        operation_durations = {}
        operation_starts = {}

        for event in events:
            if event["type"] == "timer_start":
                operation_starts[event["operation"]] = event["timestamp"]
            elif event["type"] == "timer_end" and event["operation"] in operation_starts:
                duration = event["timestamp"] - operation_starts[event["operation"]]
                operation_durations[event["operation"]] = duration

        # Find incomplete operations (started but not ended)
        incomplete_operations = []
        for op, start_time in operation_starts.items():
            if op not in operation_durations:
                incomplete_operations.append(
                    {
                        "operation": op,
                        "started_at": start_time,
                        "duration_so_far": time.time() - start_time,
                    }
                )

        # Analyze subprocess calls
        subprocess_events = [
            e for e in events if "subprocess" in str(e).lower() or "process" in str(e).lower()
        ]

        return {
            "operation_durations": operation_durations,
            "incomplete_operations": incomplete_operations,
            "subprocess_events": subprocess_events,
            "total_events": len(events),
            "metrics": metrics,
        }


def setup_telemetry_hooks():
    """Setup hooks to export telemetry on exit/timeout"""
    import atexit
    import signal

    exporter = TelemetryExporter()

    def export_on_exit():
        try:
            session_file = exporter.export_session("exit_dump")
            # Analyze immediately
            analysis = exporter.analyze_hanging(session_file)

            # Write analysis
            analysis_file = session_file.with_suffix(".analysis.json")
            with open(analysis_file, "w") as f:
                json.dump(analysis, f, indent=2, default=str)
        except Exception as e:
            # Failsafe - write to stderr (avoid logging during shutdown)
            import sys
            sys.stderr.write(f"Telemetry export failed: {e}\n")

    # Register exit handler
    atexit.register(export_on_exit)

    # Also handle signals
    def signal_handler(signum, frame):
        export_on_exit()
        # Re-raise to allow normal signal handling
        signal.signal(signum, signal.SIG_DFL)
        signal.raise_signal(signum)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
