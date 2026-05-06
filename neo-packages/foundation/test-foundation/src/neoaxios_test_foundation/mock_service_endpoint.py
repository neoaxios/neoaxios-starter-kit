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
Mock Service Endpoint - Generic HTTP server for testing service-call stages.

Provides a Flask-based mock server that implements a configurable JSON POST
endpoint for testing code paths that issue outbound HTTP calls without
requiring an external service to be running.

USAGE:
    from neoaxios_test_foundation.mock_service_endpoint import MockServiceEndpoint

    @pytest.fixture(scope="module")
    def echo_service():
        server = MockServiceEndpoint(
            path="/v1/process",
            operation_id="processItem",
        )
        server.set_response({"status": "ok", "items_processed": 1})
        server.start()
        yield server
        server.stop()

    def test_example(echo_service):
        response = requests.post(
            f"{echo_service.url}/v1/process",
            json={"name": "test"},
        )
        assert response.status_code == 200

Thread-safe: safe for concurrent test execution.
"""

import threading
import time
from typing import Any, Callable, Dict, List, Optional

import yaml
from flask import Flask, jsonify, request as flask_request
from neoaxios_logging.flight_recorder import FlightRecorder
from werkzeug.serving import make_server


class MockServiceEndpoint:
    """
    Generic mock HTTP service for testing outbound service-call code paths.

    Serves a single POST endpoint at a configurable path, returning
    configurable JSON responses. Useful as a substitute for an external
    HTTP dependency in unit and integration tests.

    Features:
        - Configurable endpoint path and operation ID
        - Static, echo, dynamic, or error response modes
        - Request logging for test assertions
        - OpenAPI spec generation for API spec integration
        - Thread-safe operation with dynamic port allocation
        - Health check endpoint

    Example:
        >>> server = MockServiceEndpoint(path="/v1/process", operation_id="processItem")
        >>> server.set_response({"status": "ok"})
        >>> server.start()
        >>> # Run code paths that issue HTTP calls against server.url
        >>> server.stop()
        >>> assert server.get_request_count() == 1
    """

    def __init__(
        self,
        path: str = "/v1/process",
        operation_id: str = "processItem",
        port: int = 0,
        host: str = "127.0.0.1",
    ):
        """
        Initialize mock service endpoint.

        Args:
            path: URL path for the POST endpoint (e.g., "/v1/process").
            operation_id: OpenAPI operationId for spec generation.
            port: Port to listen on. Use 0 for automatic allocation.
            host: Host to bind to.
        """
        self._path = path
        self._operation_id = operation_id
        self._requested_port = port
        self.port: Optional[int] = None
        self.host = host
        self.app = Flask(__name__)
        self.server = None
        self.server_thread = None
        self._is_running = False
        self.fr = FlightRecorder("mock_service_endpoint.auto")

        # Response configuration
        self._response_mode = "static"
        self._static_response: Dict[str, Any] = {}
        self._custom_handler: Optional[Callable] = None
        self._error_status: Optional[int] = None
        self._error_body: Optional[str] = None
        self._response_delay: float = 0.0

        # Request logging
        self._request_log: List[Dict[str, Any]] = []
        self._request_count = 0
        self._lock = threading.Lock()

        self._setup_routes()
        self.fr.emit("MockServiceEndpoint initialized", path=path, operation_id=operation_id)

    def _setup_routes(self):
        """Setup Flask routes for the configurable endpoint."""

        @self.app.route(self._path, methods=["POST"])
        def handle_post():
            """Handle POST requests to the configured endpoint."""
            self.fr.emit("request_received", path=self._path)

            request_data = flask_request.get_json(silent=True) or {}

            with self._lock:
                self._request_count += 1
                self._request_log.append({
                    "timestamp": time.time(),
                    "method": "POST",
                    "path": self._path,
                    "data": request_data,
                    "request_id": self._request_count,
                })

            if self._response_delay > 0:
                time.sleep(self._response_delay)

            # Error injection
            if self._error_status is not None:
                body = self._error_body or f"Error {self._error_status}"
                self.fr.emit("error_response", status=self._error_status)
                return body, self._error_status

            # Response modes
            if self._response_mode == "custom" and self._custom_handler:
                response_data = self._custom_handler(request_data)
                return jsonify(response_data), 200

            if self._response_mode == "echo":
                response_data = {
                    "_echo": request_data,
                    "_request_id": self._request_count,
                }
                return jsonify(response_data), 200

            # Static mode (default)
            return jsonify(self._static_response), 200

        @self.app.route("/health", methods=["GET"])
        def health():
            """Health check endpoint."""
            return jsonify({
                "status": "ok",
                "requests_served": self._request_count,
                "endpoint": self._path,
                "operation_id": self._operation_id,
            }), 200

    def set_response(self, response: Dict[str, Any]) -> None:
        """Set a static JSON response for all requests.

        Args:
            response: Dict to return as JSON for every POST.
        """
        self._response_mode = "static"
        self._static_response = response
        self._error_status = None

    def set_custom_handler(self, handler: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        """Set a custom handler function for dynamic responses.

        Args:
            handler: Function that receives request body dict and returns response dict.
        """
        self._response_mode = "custom"
        self._custom_handler = handler
        self._error_status = None

    def set_echo_mode(self) -> None:
        """Set echo mode — returns the request body back with metadata."""
        self._response_mode = "echo"
        self._error_status = None

    def set_error(self, status: int, body: str = "") -> None:
        """Configure the server to return an HTTP error.

        Args:
            status: HTTP status code to return.
            body: Response body text.
        """
        self._error_status = status
        self._error_body = body

    def clear_error(self) -> None:
        """Clear error injection, restoring normal response mode."""
        self._error_status = None
        self._error_body = None

    def set_response_delay(self, seconds: float) -> None:
        """Add a delay before responding (for timeout testing).

        Args:
            seconds: Delay in seconds.
        """
        self._response_delay = seconds

    def start(self) -> None:
        """Start the mock server in a background thread."""
        if self._is_running:
            return

        self.fr.emit("starting", host=self.host, port=self._requested_port)
        self.server = make_server(self.host, self._requested_port, self.app, threaded=True)
        self.port = self.server.server_address[1]
        self._is_running = True

        self.server_thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
            name=f"MockServiceEndpoint-{self.port}",
        )
        self.server_thread.start()

        # Wait for readiness
        import requests
        for attempt in range(20):
            try:
                resp = requests.get(f"http://{self.host}:{self.port}/health", timeout=1)
                if resp.status_code == 200:
                    self.fr.emit("started", port=self.port, attempts=attempt + 1)
                    return
            except Exception:
                time.sleep(0.1)

        self.stop()
        raise RuntimeError(
            f"MockServiceEndpoint on port {self.port} failed to become ready"
        )

    def stop(self) -> None:
        """Stop the mock server."""
        if not self._is_running:
            return

        self.fr.emit("stopping", port=self.port, requests_served=self._request_count)
        if self.server:
            self.server.shutdown()
            self.server.server_close()

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2.0)

        self._is_running = False
        self.server = None
        self.server_thread = None
        self.fr.emit("stopped", port=self.port)

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._is_running and self.server is not None

    @property
    def url(self) -> str:
        """Base URL of the mock server."""
        return f"http://{self.host}:{self.port}"

    def get_request_log(self) -> List[Dict[str, Any]]:
        """Get log of all requests received."""
        with self._lock:
            return self._request_log.copy()

    def get_request_count(self) -> int:
        """Get total number of requests received."""
        with self._lock:
            return self._request_count

    def get_last_request(self) -> Optional[Dict[str, Any]]:
        """Get the most recent request received."""
        with self._lock:
            return self._request_log[-1] if self._request_log else None

    def clear_request_log(self) -> None:
        """Clear the request log and reset count."""
        with self._lock:
            self._request_log.clear()
            self._request_count = 0

    def write_openapi_spec(self, dest_dir: str) -> str:
        """Write an OpenAPI spec YAML matching this endpoint's configuration.

        Generates a minimal OpenAPI 3.0.3 spec with the configured path and
        operationId, suitable for external contract validators.

        Args:
            dest_dir: Directory to write the openapi.yaml file into.

        Returns:
            Path to the written spec file.
        """
        import os
        os.makedirs(dest_dir, exist_ok=True)

        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": f"Mock {self._operation_id}",
                "version": "1.0.0",
            },
            "paths": {
                self._path: {
                    "post": {
                        "operationId": self._operation_id,
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "additionalProperties": True,
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "additionalProperties": True,
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            },
        }

        spec_path = os.path.join(dest_dir, "openapi.yaml")
        with open(spec_path, "w") as f:
            yaml.dump(spec, f, default_flow_style=False)

        self.fr.emit("openapi_spec_written", path=spec_path)
        return spec_path

    def __repr__(self) -> str:
        return (
            f"MockServiceEndpoint(path={self._path!r}, "
            f"port={self.port}, requests={self._request_count})"
        )


def create_mock_service_endpoint(
    path: str = "/v1/process",
    operation_id: str = "processItem",
    port: int = 0,
    **kwargs: Any,
) -> MockServiceEndpoint:
    """Factory function to create a MockServiceEndpoint.

    Args:
        path: URL path for the POST endpoint.
        operation_id: OpenAPI operationId.
        port: Port number (0 for auto).
        **kwargs: Additional configuration passed to MockServiceEndpoint.

    Returns:
        Configured MockServiceEndpoint instance (not started).
    """
    return MockServiceEndpoint(path=path, operation_id=operation_id, port=port, **kwargs)
