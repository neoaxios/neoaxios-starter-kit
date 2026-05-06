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
Performance Analyzer for test test execution.

This module provides analysis capabilities for test execution performance,
including time sink identification, regression detection, and optimization recommendations.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, TypedDict
from dataclasses import dataclass, field
import statistics

from ..logbook import get_logger
from .test_results_cache import TestResultsCache

# Import FlightRecorder for better error tracking
try:
    from .flight_recorder import FlightRecorder
    from ..common import LogLevel
    HAS_FLIGHT_RECORDER = True
except ImportError:
    HAS_FLIGHT_RECORDER = False


class TestRecord(TypedDict):
    """Type definition for test record used in batch recording."""
    test_id: str
    file_path: str
    test_name: str
    duration: float
    timestamp: Optional[str]


@dataclass
class TestPerformanceData:
    """Performance data for a single test."""

    test_id: str
    file_path: str
    test_name: str
    durations: List[float] = field(default_factory=list)
    timestamps: List[str] = field(default_factory=list)

    @property
    def average_duration(self) -> float:
        """Calculate average duration."""
        return statistics.mean(self.durations) if self.durations else 0.0

    @property
    def min_duration(self) -> float:
        """Get minimum duration."""
        return min(self.durations) if self.durations else 0.0

    @property
    def max_duration(self) -> float:
        """Get maximum duration."""
        return max(self.durations) if self.durations else 0.0

    @property
    def variance(self) -> float:
        """Calculate variance in durations."""
        return statistics.variance(self.durations) if len(self.durations) > 1 else 0.0

    @property
    def std_dev(self) -> float:
        """Calculate standard deviation."""
        return statistics.stdev(self.durations) if len(self.durations) > 1 else 0.0


@dataclass
class PerformanceAnalysis:
    """Results of performance analysis."""

    total_tests: int
    total_duration: float
    time_sinks: List[Tuple[str, float, float]]  # (test_id, duration, percentage)
    regressions: List[Dict[str, Any]]
    recommendations: List[str]
    variance_analysis: List[Dict[str, Any]]
    optimization_opportunities: List[Dict[str, Any]]


class TestPerformanceAnalyzer:
    """Analyze test execution performance and provide insights."""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        max_history_size: Optional[int] = None,
        enabled: Optional[bool] = None,
        use_config: bool = True
    ):
        """Initialize the performance analyzer.

        Args:
            project_root: Project root directory
            max_history_size: Maximum number of historical runs to keep per test
                            (overrides config if provided, otherwise uses config or default: 100)
            enabled: Enable performance tracking
                    (overrides config if provided, otherwise uses config or default: True)
            use_config: Load settings from config manager (default: True)
                       Set to False to skip config loading and use only provided parameters
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.logger = get_logger(__name__)
        self.cache = TestResultsCache(self.project_root)

        # Load configuration from config manager if enabled
        if use_config:
            try:
                from ..config import get_config_manager
                config_manager = get_config_manager(self.project_root)
                config = config_manager.load()
                perf_config = config.performance

                # Use config values, but allow parameter overrides
                self.max_history_size = max_history_size if max_history_size is not None else perf_config.max_history_size
                self.enabled = enabled if enabled is not None else perf_config.enabled
                self.batch_recording = perf_config.batch_recording

                # Get history file path from config
                history_file_path = perf_config.history_file
            except Exception as e:
                # If config loading fails, fall back to parameters or defaults
                self.logger.warning(f"Failed to load config, using defaults: {e}")
                self.max_history_size = max_history_size if max_history_size is not None else 100
                self.enabled = enabled if enabled is not None else True
                self.batch_recording = True
                history_file_path = None
        else:
            # Config loading disabled, use parameters or defaults
            self.max_history_size = max_history_size if max_history_size is not None else 100
            self.enabled = enabled if enabled is not None else True
            self.batch_recording = True
            history_file_path = None

        # Set up history file path
        if history_file_path:
            self._performance_history_file = self.project_root / history_file_path
        else:
            # Use default path
            telemetry_dir = self.project_root / ".telemetry"
            telemetry_dir.mkdir(parents=True, exist_ok=True)
            self._performance_history_file = telemetry_dir / "performance_history.json"

        self._performance_data: Dict[str, TestPerformanceData] = {}

        # Only load history if performance tracking is enabled
        if self.enabled:
            self._load_performance_history()

    
    def _load_performance_history(self) -> None:
        """Load performance history from disk."""
        if self._performance_history_file.exists():
            try:
                with open(self._performance_history_file, "r") as f:
                    data = json.load(f)
                    for test_id, test_data in data.items():
                        self._performance_data[test_id] = TestPerformanceData(
                            test_id=test_data["test_id"],
                            file_path=test_data["file_path"],
                            test_name=test_data["test_name"],
                            durations=test_data["durations"],
                            timestamps=test_data["timestamps"],
                        )
            except Exception as e:
                self.logger.error(f"Failed to load performance history: {e}")

    def _save_performance_history(self) -> None:
        """
        Save performance history to disk using atomic writes.

        Uses temporary file + atomic rename for crash safety without file locking.
        Note: In multi-process scenarios, use proper multiprocessing primitives
        (e.g., multiprocessing.Lock) for coordination instead of file locks.
        """
        try:
            self._performance_history_file.parent.mkdir(parents=True, exist_ok=True)

            # First, reload the current data to get latest updates
            current_data = {}
            if self._performance_history_file.exists():
                try:
                    with open(self._performance_history_file, "r") as f:
                        current_data = json.load(f)
                except Exception:
                    # File might not exist yet or be corrupted, start fresh
                    pass

            # Merge our data with the current data (our data takes precedence)
            for test_id, perf_data in self._performance_data.items():
                current_data[test_id] = {
                    "test_id": perf_data.test_id,
                    "file_path": perf_data.file_path,
                    "test_name": perf_data.test_name,
                    "durations": perf_data.durations,
                    "timestamps": perf_data.timestamps,
                }

            # Use a unique temporary file and atomic rename for crash safety
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=self._performance_history_file.parent,
                suffix='.tmp',
                delete=False
            ) as temp_file:
                temp_path = Path(temp_file.name)
                json.dump(current_data, temp_file, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())  # Ensure data is written to disk

            # Atomic rename (on POSIX systems) - provides crash safety
            temp_path.replace(self._performance_history_file)

        except Exception as e:
            self.logger.error(f"Failed to save performance history: {e}")
            if HAS_FLIGHT_RECORDER:
                try:
                    fr = FlightRecorder("performance_analyzer_save_error")
                    fr.emit("save_failed", LogLevel.ERROR,
                           file_path=str(self._performance_history_file),
                           error=str(e),
                           operation="save_performance_history")
                except:
                    pass
            # Try to clean up temp file if it exists
            try:
                if 'temp_path' in locals() and temp_path.exists():
                    temp_path.unlink()
            except:
                pass

    def record_duration(
        self,
        test_id: str,
        file_path: str,
        test_name: str,
        duration: float,
        timestamp: Optional[str] = None,
    ) -> None:
        """Record a test execution duration.
        
        Note: This method saves to disk immediately for backward compatibility.
        For batch operations, use record_duration_batch() for better performance.
        """
        # Skip if performance tracking is disabled
        if not self.enabled:
            return
            
        if test_id not in self._performance_data:
            self._performance_data[test_id] = TestPerformanceData(
                test_id=test_id, file_path=file_path, test_name=test_name
            )

        perf_data = self._performance_data[test_id]
        perf_data.durations.append(duration)
        perf_data.timestamps.append(timestamp or datetime.now().isoformat())

        # Keep only last N runs to avoid unbounded growth
        if len(perf_data.durations) > self.max_history_size:
            perf_data.durations.pop(0)
            perf_data.timestamps.pop(0)

        self._save_performance_history()
    
    def record_duration_batch(
        self,
        test_records: List[TestRecord]
    ) -> None:
        """Record multiple test execution durations at once.
        
        This is much more efficient than calling record_duration() multiple times
        as it only saves to disk once after processing all records.
        
        Args:
            test_records: List of TestRecord dictionaries with required keys
            
        Raises:
            ValueError: If required keys are missing from any record
        """
        # Skip if performance tracking is disabled
        if not self.enabled:
            return
            
        # Early return for empty list
        if not test_records:
            return
            
        # Validate required keys
        required_keys = {'test_id', 'file_path', 'test_name', 'duration'}
        for idx, record in enumerate(test_records):
            if not required_keys.issubset(record.keys()):
                missing = required_keys - set(record.keys())
                raise ValueError(
                    f"Record {idx} missing required keys: {missing}. "
                    f"Got: {list(record.keys())}"
                )
        
        for record in test_records:
            test_id = record['test_id']
            
            if test_id not in self._performance_data:
                self._performance_data[test_id] = TestPerformanceData(
                    test_id=test_id,
                    file_path=record['file_path'],
                    test_name=record['test_name']
                )
            
            perf_data = self._performance_data[test_id]
            perf_data.durations.append(record['duration'])
            perf_data.timestamps.append(
                record.get('timestamp') or datetime.now().isoformat()
            )
            
            # Keep only last N runs to avoid unbounded growth
            if len(perf_data.durations) > self.max_history_size:
                perf_data.durations.pop(0)
                perf_data.timestamps.pop(0)
        
        # Save ONCE after processing all records
        if test_records:  # Only save if we actually processed something
            self._save_performance_history()

    def identify_time_sinks(self, threshold_percentile: int = 80) -> List[Tuple[str, float, float]]:
        """Identify tests consuming most execution time."""
        if not self._performance_data:
            return []

        # Calculate total duration across all tests
        test_durations = []
        for test_id, perf_data in self._performance_data.items():
            if perf_data.durations:
                avg_duration = perf_data.average_duration
                test_durations.append((test_id, avg_duration))

        if not test_durations:
            return []

        # Sort by duration
        test_durations.sort(key=lambda x: x[1], reverse=True)
        total_duration = sum(d[1] for d in test_durations)

        # Find threshold
        if threshold_percentile == 100:
            threshold_index = len(test_durations)
        else:
            cumulative_duration = 0
            threshold_index = 0
            target_duration = total_duration * (threshold_percentile / 100)

            for i, (_, duration) in enumerate(test_durations):
                cumulative_duration += duration
                if cumulative_duration >= target_duration:
                    threshold_index = i + 1
                    break

        # Return time sinks with percentage
        time_sinks = []
        for i in range(min(threshold_index, len(test_durations))):
            test_id, duration = test_durations[i]
            percentage = (duration / total_duration * 100) if total_duration > 0 else 0
            time_sinks.append((test_id, duration, percentage))

        return time_sinks

    def detect_regressions(self, sensitivity: float = 1.5) -> List[Dict[str, Any]]:
        """Detect tests that have gotten slower over time."""
        regressions = []

        for test_id, perf_data in self._performance_data.items():
            if len(perf_data.durations) < 5:
                continue  # Need at least 5 runs to detect trend

            # Compare recent runs to historical baseline
            recent_runs = perf_data.durations[-5:]
            older_runs = perf_data.durations[:-5]

            if not older_runs:
                continue

            recent_avg = statistics.mean(recent_runs)
            baseline_avg = statistics.mean(older_runs)

            # Check if recent average is significantly higher
            if recent_avg > baseline_avg * sensitivity:
                regression_factor = recent_avg / baseline_avg
                regressions.append(
                    {
                        "test_id": test_id,
                        "file_path": perf_data.file_path,
                        "test_name": perf_data.test_name,
                        "baseline_duration": baseline_avg,
                        "current_duration": recent_avg,
                        "regression_factor": regression_factor,
                        "increase_seconds": recent_avg - baseline_avg,
                    }
                )

        # Sort by regression factor
        regressions.sort(key=lambda x: x["regression_factor"], reverse=True)
        return regressions

    def analyze_variance(self) -> List[Dict[str, Any]]:
        """Analyze tests with high variance in execution time."""
        high_variance_tests = []

        for test_id, perf_data in self._performance_data.items():
            if len(perf_data.durations) < 3:
                continue

            avg_duration = perf_data.average_duration
            std_dev = perf_data.std_dev

            if avg_duration > 0:
                cv = std_dev / avg_duration  # Coefficient of variation

                # Flag tests with high variance
                if cv > 0.5 or (perf_data.max_duration / perf_data.min_duration > 5):
                    high_variance_tests.append(
                        {
                            "test_id": test_id,
                            "file_path": perf_data.file_path,
                            "test_name": perf_data.test_name,
                            "min_duration": perf_data.min_duration,
                            "max_duration": perf_data.max_duration,
                            "average_duration": avg_duration,
                            "std_dev": std_dev,
                            "coefficient_of_variation": cv,
                            "variance_ratio": (
                                perf_data.max_duration / perf_data.min_duration
                                if perf_data.min_duration > 0
                                else float("inf")
                            ),
                        }
                    )

        # Sort by variance ratio
        high_variance_tests.sort(key=lambda x: x["variance_ratio"], reverse=True)
        return high_variance_tests

    def calculate_optimization_roi(self) -> List[Dict[str, Any]]:
        """Calculate return on investment for optimizing slow tests."""
        time_sinks = self.identify_time_sinks(threshold_percentile=100)
        optimization_opportunities = []

        for test_id, duration, percentage in time_sinks[:20]:  # Top 20 slowest
            perf_data = self._performance_data[test_id]

            # Estimate potential improvement
            # Assume we can improve slow tests by 30-50%
            if duration > 10:
                improvement_factor = 0.5  # 50% improvement for very slow tests
            elif duration > 5:
                improvement_factor = 0.4  # 40% improvement for slow tests
            else:
                improvement_factor = 0.3  # 30% improvement for moderate tests

            potential_savings = duration * improvement_factor

            optimization_opportunities.append(
                {
                    "test_id": test_id,
                    "file_path": perf_data.file_path,
                    "test_name": perf_data.test_name,
                    "current_duration": duration,
                    "potential_duration": duration * (1 - improvement_factor),
                    "potential_savings": potential_savings,
                    "percentage_of_total": percentage,
                    "priority": "high" if duration > 10 else "medium" if duration > 5 else "low",
                }
            )

        return optimization_opportunities

    def get_recommendations(self, analysis: PerformanceAnalysis) -> List[str]:
        """Generate specific recommendations based on analysis."""
        recommendations = []

        # Recommendations for time sinks
        if analysis.time_sinks:
            top_sinks = analysis.time_sinks[:3]
            total_top_duration = sum(d[1] for d in top_sinks)
            recommendations.append(
                f"Focus on optimizing top {len(top_sinks)} slowest tests - "
                f"they consume {total_top_duration:.1f}s ({sum(d[2] for d in top_sinks):.1f}% of total time)"
            )

            for test_id, duration, _ in top_sinks:
                if duration > 30:
                    recommendations.append(
                        f"Consider splitting {test_id} into smaller, focused tests"
                    )
                elif duration > 10:
                    recommendations.append(
                        f"Review {test_id} for unnecessary I/O or sleep statements"
                    )

        # Recommendations for regressions
        if analysis.regressions:
            for regression in analysis.regressions[:3]:
                recommendations.append(
                    f"Investigate {regression['test_name']} - "
                    f"{regression['regression_factor']:.1f}x slower than baseline"
                )

        # Recommendations for high variance
        if analysis.variance_analysis:
            for variance in analysis.variance_analysis[:3]:
                if variance["variance_ratio"] > 10:
                    recommendations.append(
                        f"Fix flaky test {variance['test_name']} - "
                        f"execution time varies by {variance['variance_ratio']:.0f}x"
                    )

        # General recommendations
        if analysis.total_duration > 300:  # 5 minutes
            recommendations.append("Consider parallel execution strategies to reduce total runtime")

        return recommendations

    def analyze(self, days: int = 30) -> PerformanceAnalysis:
        """Perform comprehensive performance analysis."""
        # Calculate time sinks
        time_sinks = self.identify_time_sinks(threshold_percentile=80)

        # Detect regressions
        regressions = self.detect_regressions()

        # Analyze variance
        variance_analysis = self.analyze_variance()

        # Calculate optimization opportunities
        optimization_opportunities = self.calculate_optimization_roi()

        # Calculate totals
        total_tests = len(self._performance_data)
        total_duration = sum(
            perf_data.average_duration
            for perf_data in self._performance_data.values()
            if perf_data.durations
        )

        # Create analysis result
        analysis = PerformanceAnalysis(
            total_tests=total_tests,
            total_duration=total_duration,
            time_sinks=time_sinks,
            regressions=regressions,
            recommendations=[],
            variance_analysis=variance_analysis,
            optimization_opportunities=optimization_opportunities,
        )

        # Generate recommendations
        analysis.recommendations = self.get_recommendations(analysis)

        return analysis

    def compare_runs(self, run1_id: str, run2_id: str) -> Dict[str, Any]:
        """Compare performance between two test runs."""
        # This would need integration with run tracking
        # For now, return a placeholder
        return {
            "run1": run1_id,
            "run2": run2_id,
            "comparison": "Not yet implemented",
            "message": "This feature requires integration with test run tracking",
        }

    def get_test_history(self, test_id: str, days: int = 30) -> Optional[Dict[str, Any]]:
        """Get performance history for a specific test."""
        if test_id not in self._performance_data:
            return None

        perf_data = self._performance_data[test_id]

        # Filter by days if needed
        cutoff_date = datetime.now() - timedelta(days=days)
        filtered_data = []

        for duration, timestamp in zip(perf_data.durations, perf_data.timestamps):
            try:
                ts_date = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if ts_date >= cutoff_date:
                    filtered_data.append((duration, timestamp))
            except:
                # Include if we can't parse timestamp
                filtered_data.append((duration, timestamp))

        if not filtered_data:
            return None

        durations = [d[0] for d in filtered_data]

        return {
            "test_id": test_id,
            "file_path": perf_data.file_path,
            "test_name": perf_data.test_name,
            "history": filtered_data,
            "statistics": {
                "min": min(durations),
                "max": max(durations),
                "average": statistics.mean(durations),
                "std_dev": statistics.stdev(durations) if len(durations) > 1 else 0,
                "sample_count": len(durations),
            },
        }
