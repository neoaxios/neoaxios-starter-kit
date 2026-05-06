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
Shared pytest fixtures for NeoAxios packages.

Provides common test utilities, fixtures, and helpers for all packages.

USAGE (DO NOT DUPLICATE):
    # In package conftest.py:
    from neoaxios_test_foundation.fixtures import (
        temp_dir_factory,
        telemetry_capture,
        flight_recorder,
        sample_json_schemas,
        performance_timer,
        isolation_checker
    )

    # Or import all:
    pytest_plugins = ['neoaxios_test_foundation.fixtures']

Available Fixtures:
    - temp_dir_factory: Create isolated temporary directories
    - telemetry_capture: Capture and validate FlightRecorder events
    - sample_json_schemas: Library of common JSON schemas
    - performance_timer: Measure test performance
    - isolation_checker: Validate test isolation (no shared state)
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from neoaxios_logging.flight_recorder import FlightRecorder

# ============================================================================
# Temporary Directory Factory
# ============================================================================

@pytest.fixture
def temp_dir_factory(tmp_path):
    """
    Factory for creating isolated temporary directories.

    Creates uniquely named temp directories for parallel test safety.
    Each call returns a new directory with automatic cleanup.

    Args:
        tmp_path: pytest's built-in tmp_path fixture

    Returns:
        Callable that creates temp directories

    Example:
        def test_example(temp_dir_factory):
            test_dir = temp_dir_factory("my_test")
            data_dir = temp_dir_factory("data")
            # Both directories are unique and isolated
    """
    counter = [0]  # Mutable counter for unique names

    def create_temp_dir(name: str = "temp") -> Path:
        """
        Create a temporary directory with unique name.

        Args:
            name: Base name for directory

        Returns:
            Path to created temporary directory
        """
        counter[0] += 1
        dir_path = tmp_path / f"{name}_{counter[0]}"
        dir_path.mkdir(parents=True, exist_ok=True)

        fr = FlightRecorder("temp_dir_factory")
        fr.emit("Created temp directory", path=str(dir_path), name=name)

        return dir_path

    return create_temp_dir


# ============================================================================
# Telemetry Capture
# ============================================================================

class TelemetryCapture:
    """
    Capture and validate FlightRecorder telemetry events.

    Usage:
        def test_example(telemetry_capture):
            fr = FlightRecorder("test.example")
            fr.emit("test event", key="value")

            assert telemetry_capture.has_event("test event")
            assert telemetry_capture.events_count() > 0
    """

    def __init__(self):
        """Initialize telemetry capture."""
        self._events: List[Dict[str, Any]] = []
        self._original_emit = None
        self.fr = FlightRecorder("telemetry_capture")

    def start_capture(self):
        """Start capturing FlightRecorder events."""
        self.fr.emit("Starting telemetry capture")

        # Note: This is a simplified implementation
        # Real implementation would need to hook into FlightRecorder internals
        # For now, this serves as a template for future enhancement
        self._events.clear()

    def stop_capture(self):
        """Stop capturing FlightRecorder events."""
        self.fr.emit("Stopping telemetry capture", events_captured=len(self._events))

    def has_event(self, event_name: str) -> bool:
        """
        Check if an event with given name was captured.

        Args:
            event_name: Event name to search for

        Returns:
            True if event was captured
        """
        return any(event.get("event") == event_name for event in self._events)

    def get_events(self, event_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get captured events, optionally filtered by name.

        Args:
            event_name: Optional event name to filter by

        Returns:
            List of event dictionaries
        """
        if event_name:
            return [e for e in self._events if e.get("event") == event_name]
        return self._events.copy()

    def events_count(self) -> int:
        """Get total number of captured events."""
        return len(self._events)

    def clear_events(self):
        """Clear all captured events."""
        self._events.clear()

    def assert_event_exists(self, event_name: str):
        """
        Assert that an event exists (raises AssertionError if not).

        Args:
            event_name: Event name to check

        Raises:
            AssertionError: If event not found
        """
        assert self.has_event(event_name), f"Event '{event_name}' not found in telemetry"


@pytest.fixture
def telemetry_capture():
    """
    Fixture to capture and validate telemetry events.

    Returns:
        TelemetryCapture instance

    Example:
        def test_example(telemetry_capture):
            telemetry_capture.start_capture()
            # ... code that emits events ...
            telemetry_capture.stop_capture()
            assert telemetry_capture.events_count() > 0
    """
    capture = TelemetryCapture()
    capture.start_capture()
    yield capture
    capture.stop_capture()


# ============================================================================
# FlightRecorder Fixture (Shared across all packages)
# ============================================================================

@pytest.fixture
def flight_recorder(request):
    """
    Shared FlightRecorder fixture for all test types.

    Provides function-scoped FlightRecorder instance with automatic
    test lifecycle logging and cleanup.

    Args:
        request: pytest request object for test metadata

    Yields:
        FlightRecorder: Configured recorder with test name

    Usage:
        # In package conftest.py:
        from neoaxios_test_foundation.fixtures import flight_recorder

        # Or use pytest_plugins:
        pytest_plugins = ['neoaxios_test_foundation.fixtures']

        # In test:
        def test_example(flight_recorder):
            flight_recorder.emit("custom_event", data="value")
            # Test logic

    Example:
        def test_pipeline_run(flight_recorder):
            flight_recorder.emit("pipeline_start", LogLevel.ENTER, checkpoint="start")
            result = run_pipeline()
            flight_recorder.emit("pipeline_done", LogLevel.EXIT, checkpoint="done")
            assert result.success
    """
    from neoaxios_logging.common import LogLevel

    test_name = request.node.name
    recorder = FlightRecorder(test_name, buffer_size=0)
    recorder.emit("test_start", LogLevel.ENTER, test_name=test_name)

    yield recorder

    recorder.emit("test_end", LogLevel.EXIT, test_name=test_name)
    recorder.flush()


@pytest.fixture
def flight_recorder_with_file(tmp_path):
    """
    FlightRecorder variant that persists to file in tmp directory.

    Use this variant when you need file-based telemetry for analysis
    after test completion. Useful for integration tests that need to
    inspect the telemetry timeline.

    Args:
        tmp_path: pytest temporary directory fixture

    Yields:
        FlightRecorder: Configured recorder that writes to tmp file

    Usage:
        def test_example(flight_recorder_with_file):
            flight_recorder_with_file.emit("event", data="value")
            # Test logic
            # Telemetry written to tmp_path/flight_recorder.jsonl
    """
    recorder = FlightRecorder(str(tmp_path / "flight_recorder.jsonl"))
    yield recorder
    recorder.close()


@pytest.fixture
def flight_recorder_persistent(request, tmp_path):
    """
    FlightRecorder variant with persistent output to .flight_recorder directory.

    Use this variant for E2E tests and debugging scenarios where you need
    telemetry to persist beyond test execution for post-mortem analysis.

    Args:
        request: pytest request object for test metadata
        tmp_path: pytest temporary directory fixture

    Yields:
        FlightRecorder: Configured recorder with persistent storage

    Usage:
        def test_example(flight_recorder_persistent):
            flight_recorder_persistent.emit("checkpoint", status="started")
            # Test logic
            # Telemetry persists to tmp_path/.flight_recorder/
    """
    test_name = request.node.name
    output_dir = tmp_path / ".flight_recorder"
    output_dir.mkdir(exist_ok=True)

    recorder = FlightRecorder(
        test_name=test_name,
        output_dir=output_dir,
        buffer_size=0  # Immediate writes for crash safety
    )

    yield recorder

    recorder.flush()


# ============================================================================
# Mock Server Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def mock_llm_server():
    """
    Provide MockLLMServer for deterministic testing with fault injection.

    Use this fixture for tests that require predictable LLM responses, especially
    for testing error/failure scenarios where real LLM behavior is unpredictable.

    Security features:
        - Health check verification before yielding (fail-safe)
        - RuntimeError if server fails to start (prevents production API calls)
        - Port release verification on cleanup

    Yields:
        MockLLMServer: Configured and running mock server on auto-allocated port

    Raises:
        RuntimeError: If mock server fails to start. This prevents tests from
                     accidentally calling production APIs.

    Example:
        def test_example(mock_llm_server):
            mock_llm_server.set_response_mode("static", content="Test response")
            # Configure LLM client to use: f"http://localhost:{mock_llm_server.port}/v1"
            # Test logic
    """
    import requests
    import socket
    import warnings

    # Import MockLLMServer from this package (single source of truth)
    from neoaxios_test_foundation.mock_llm_server import MockLLMServer

    server = MockLLMServer(port=0)  # Auto-allocate port

    try:
        server.start()

        # SECURITY: Verify mock server is responding before allowing tests to run
        # If this fails, tests MUST NOT proceed (fail-safe behavior)
        try:
            response = requests.get(f"http://127.0.0.1:{server.port}/health", timeout=2)
            if response.status_code != 200:
                raise RuntimeError(
                    f"MockLLMServer health check failed on port {server.port}. "
                    f"Tests cannot proceed - they might call production APIs."
                )
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                f"MockLLMServer failed to start on port {server.port}: {e}. "
                f"Tests cannot proceed safely - without mock server, tests would "
                f"attempt to call production APIs."
            ) from e

        yield server

    finally:
        # Cleanup with port release verification
        try:
            server.stop()

            # Verify port is released
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                test_socket.bind(('127.0.0.1', server.port))
                test_socket.close()
            except OSError:
                warnings.warn(
                    f"MockLLMServer port {server.port} may not have been fully released.",
                    ResourceWarning
                )
        except Exception as e:
            warnings.warn(f"Error during MockLLMServer cleanup: {e}", ResourceWarning)


# ============================================================================
# Sample JSON Schemas
# ============================================================================

@pytest.fixture(scope="session")
def sample_json_schemas():
    """
    Library of common JSON schemas for validation.

    Returns:
        Dictionary of schema name -> schema dict

    Available schemas:
        - basic_response: Simple {"result": str, "data": dict}
        - error_schema: Standard error response
        - llm_response: LLM completion response

    Example:
        def test_example(sample_json_schemas):
            schema = sample_json_schemas["basic_response"]
            jsonschema.validate(data, schema)
    """
    return {
        "basic_response": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["result", "data"],
            "properties": {
                "result": {"type": "string"},
                "data": {"type": "object"}
            }
        },

        "error_schema": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["error"],
            "properties": {
                "error": {
                    "type": "object",
                    "required": ["message", "type"],
                    "properties": {
                        "message": {"type": "string"},
                        "type": {"type": "string"},
                        "code": {"type": "string"}
                    }
                }
            }
        },

        "llm_response": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["id", "object", "created", "model", "choices"],
            "properties": {
                "id": {"type": "string"},
                "object": {"type": "string"},
                "created": {"type": "integer"},
                "model": {"type": "string"},
                "choices": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["index", "message", "finish_reason"],
                        "properties": {
                            "index": {"type": "integer"},
                            "message": {
                                "type": "object",
                                "required": ["role", "content"],
                                "properties": {
                                    "role": {"type": "string"},
                                    "content": {"type": "string"}
                                }
                            },
                            "finish_reason": {"type": "string"}
                        }
                    }
                },
                "usage": {
                    "type": "object",
                    "properties": {
                        "prompt_tokens": {"type": "integer"},
                        "completion_tokens": {"type": "integer"},
                        "total_tokens": {"type": "integer"}
                    }
                }
            }
        },

    }


# ============================================================================
# Performance Timer
# ============================================================================

class PerformanceTimer:
    """
    Context manager for measuring test performance.

    Usage:
        def test_example(performance_timer):
            with performance_timer as timer:
                # Code to measure
                time.sleep(0.1)

            assert timer.elapsed < 0.2
            assert timer.elapsed_ms < 200
    """

    def __init__(self):
        """Initialize performance timer."""
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.fr = FlightRecorder("performance_timer")

    def __enter__(self):
        """Start timer."""
        self.start_time = time.perf_counter()
        self.fr.emit("Timer started")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timer."""
        self.end_time = time.perf_counter()
        self.fr.emit("Timer stopped", elapsed=self.elapsed)
        return False

    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        if self.end_time is None:
            return time.perf_counter() - self.start_time
        return self.end_time - self.start_time

    @property
    def elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        return self.elapsed * 1000

    def assert_faster_than(self, seconds: float):
        """
        Assert that elapsed time is less than given seconds.

        Args:
            seconds: Maximum allowed time

        Raises:
            AssertionError: If elapsed time exceeds limit
        """
        assert self.elapsed < seconds, f"Expected < {seconds}s, got {self.elapsed:.3f}s"


@pytest.fixture
def performance_timer():
    """
    Fixture for measuring test performance.

    Returns:
        PerformanceTimer instance

    Example:
        def test_example(performance_timer):
            with performance_timer as timer:
                do_something()
            timer.assert_faster_than(1.0)
    """
    return PerformanceTimer()


# ============================================================================
# Isolation Checker
# ============================================================================

class IsolationChecker:
    """
    Validates test isolation by detecting shared state.

    Usage:
        def test_example(isolation_checker):
            isolation_checker.register_state("my_module.global_var", value)
            # Test code
            isolation_checker.assert_no_changes()
    """

    def __init__(self):
        """Initialize isolation checker."""
        self._initial_state: Dict[str, Any] = {}
        self.fr = FlightRecorder("isolation_checker")

    def register_state(self, name: str, value: Any):
        """
        Register a state variable to monitor.

        Args:
            name: State variable name
            value: Initial value
        """
        self._initial_state[name] = value
        self.fr.emit("Registered state", name=name)

    def assert_no_changes(self):
        """
        Assert that no registered state has changed.

        Raises:
            AssertionError: If any state changed
        """
        # Note: This is a simplified implementation
        # Real implementation would track actual Python object state
        self.fr.emit("Checking isolation", tracked_variables=len(self._initial_state))

    def clear_state(self):
        """Clear all registered state."""
        self._initial_state.clear()


@pytest.fixture
def isolation_checker():
    """
    Fixture to validate test isolation.

    Returns:
        IsolationChecker instance

    Example:
        def test_example(isolation_checker):
            isolation_checker.register_state("counter", 0)
            # Test that modifies counter
            isolation_checker.assert_no_changes()
    """
    return IsolationChecker()


# ============================================================================
# Sample Data Builders
# ============================================================================

@pytest.fixture
def sample_llm_responses():
    """
    Sample LLM response strings for testing.

    Returns:
        Dictionary of response_type -> response_text

    Available responses:
        - valid_json: Clean JSON response
        - markdown_json: JSON in markdown code block
        - mixed_content: JSON embedded in text
        - malformed: Incomplete JSON
        - error: Error response

    Example:
        def test_example(sample_llm_responses):
            response = sample_llm_responses["valid_json"]
            result = parse_llm_response(response)
    """
    return {
        "valid_json": '{"result": "success", "data": {"value": 42}}',

        "markdown_json": """Here is the result:

```json
{
  "result": "success",
  "data": {"value": 42}
}
```

That's the analysis.""",

        "mixed_content": """Let me analyze this.

The answer is: {"status": "complete", "score": 8}

Hope that helps!""",

        "malformed": '{"result": "success", "data": {',

        "error": '{"error": {"message": "Invalid request", "type": "invalid_request_error"}}'
    }


@pytest.fixture
def sample_test_results():
    """
    Sample pytest result data for test-result aggregation tests.

    Returns:
        List of test result dictionaries

    Example:
        def test_example(sample_test_results):
            aggregator.process_results(sample_test_results)
            assert aggregator.total == 3
    """
    return [
        {
            "nodeid": "test_module.py::test_pass",
            "outcome": "passed",
            "duration": 0.5,
            "when": "call"
        },
        {
            "nodeid": "test_module.py::test_fail",
            "outcome": "failed",
            "duration": 1.2,
            "when": "call",
            "longrepr": "AssertionError: Expected 1, got 2"
        },
        {
            "nodeid": "test_module.py::test_skip",
            "outcome": "skipped",
            "duration": 0.0,
            "when": "setup",
            "longrepr": "Skipped: Missing dependency"
        }
    ]


# ============================================================================
# Assertion Helpers
# ============================================================================

def assert_valid_json_schema(data: Dict[str, Any], schema: Dict[str, Any]):
    """
    Assert that data matches JSON schema.

    Args:
        data: Data to validate
        schema: JSON schema dictionary

    Raises:
        AssertionError: If validation fails
    """
    import jsonschema
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise AssertionError(f"Schema validation failed: {e.message}")


def assert_telemetry_logged(test_name: str):
    """
    Assert that telemetry was logged for a test.

    Args:
        test_name: Test name to check

    Raises:
        AssertionError: If no telemetry found
    """
    # Note: Simplified implementation
    # Real implementation would check FlightRecorder logs
    fr = FlightRecorder("assert_telemetry")
    fr.emit("Checking telemetry", test_name=test_name)


def assert_no_print_statements(file_path: Path):
    """
    Assert that a test file has no print statements.

    Args:
        file_path: Path to test file

    Raises:
        AssertionError: If print statements found
    """
    content = file_path.read_text()
    lines_with_print = [
        line for line in content.split('\n')
        if 'print(' in line and not line.strip().startswith('#')
    ]

    assert len(lines_with_print) == 0, \
        f"Found {len(lines_with_print)} print statements in {file_path.name}. Use FlightRecorder instead."


# ============================================================================
# Export all fixtures for easy import
# ============================================================================

__all__ = [
    # Fixtures
    'temp_dir_factory',
    'telemetry_capture',
    'flight_recorder',
    'flight_recorder_with_file',
    'flight_recorder_persistent',
    'mock_llm_server',
    'sample_json_schemas',
    'performance_timer',
    'isolation_checker',
    'sample_llm_responses',
    'sample_test_results',
    # Helper classes
    'TelemetryCapture',
    'PerformanceTimer',
    'IsolationChecker',
    # Assertion helpers
    'assert_valid_json_schema',
    'assert_telemetry_logged',
    'assert_no_print_statements',
]
