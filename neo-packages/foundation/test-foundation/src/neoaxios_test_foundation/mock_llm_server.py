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
Mock LLM Server - OpenAI-compatible HTTP server for testing.

Provides a Flask-based mock server that implements the OpenAI Chat Completions API
for testing neoaxios_fastapi_kit and sse-kit without requiring external LLM services.

USAGE (DO NOT DUPLICATE THIS CODE):
    from neoaxios_test_foundation.mock_llm_server import MockLLMServer

    @pytest.fixture(scope="module")
    def llm_server():
        server = MockLLMServer(port=8899)
        server.start()
        yield server
        server.stop()

    def test_example(llm_server):
        response = requests.post(
            f"http://localhost:{llm_server.port}/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "Hello"}]}
        )
        assert response.status_code == 200

Telemetry: uses FlightRecorder for operational logging (not Logbook).
Thread-safe: safe for concurrent test execution.
"""

import threading
import time
from typing import Any, Callable, Dict, List, Optional

from flask import Flask, jsonify, request
from neoaxios_logging.flight_recorder import FlightRecorder
from werkzeug.serving import make_server


class MockLLMServer:
    """
    OpenAI-compatible mock LLM server for integration tests.

    Features:
        - /v1/chat/completions endpoint (OpenAI compatible)
        - Configurable responses (static, dynamic, or custom)
        - Rate limiting simulation
        - Error injection (auth, timeout, invalid response)
        - Request logging for test validation
        - Thread-safe operation
        - Easy pytest fixture integration

    Example:
        >>> server = MockLLMServer(port=8899)
        >>> server.set_response_mode("static", content="Test response")
        >>> server.start()
        >>> # Run tests
        >>> server.stop()
        >>> requests = server.get_request_log()
    """

    def __init__(self, port: int = 0, host: str = "127.0.0.1"):
        """
        Initialize mock LLM server.

        Args:
            port: Port to listen on. Use 0 for automatic port allocation (default: 0)
            host: Host to bind to (default: 127.0.0.1)
        """
        self._requested_port = port
        self.port = None  # Will be set after binding
        self.host = host
        self.app = Flask(__name__)
        self.server = None
        self.server_thread = None
        self._is_running = False
        self.fr = FlightRecorder("mock_llm_server.auto")

        # Response configuration
        self._response_mode = "static"  # static, dynamic, custom, error
        self._static_content = "Mock LLM response"
        self._custom_handler: Optional[Callable] = None
        self._error_mode: Optional[str] = None  # auth_error, timeout, invalid_json

        # Request logging
        self._request_log: List[Dict[str, Any]] = []
        self._request_count = 0
        self._lock = threading.Lock()

        # Rate limiting
        self._rate_limit_enabled = False
        self._rate_limit_delay = 0.0

        # Setup routes
        self._setup_routes()

        self.fr.emit("MockLLMServer initialized", port=port, host=host)

    def _setup_routes(self):
        """
        Setup Flask routes for OpenAI-compatible endpoints.

        Supports both /v1/chat/completions and /chat/completions to handle:
        - OpenAI SDK: Uses /v1/chat/completions (official OpenAI API spec)
        - LiteLLM with custom api_base: Uses /chat/completions (strips /v1)
        """

        @self.app.route('/v1/chat/completions', methods=['POST'])
        @self.app.route('/chat/completions', methods=['POST'])
        def chat_completions():
            """OpenAI Chat Completions endpoint."""
            self.fr.emit("Received chat completion request")

            try:
                # Log request
                request_data = request.get_json()
                with self._lock:
                    self._request_count += 1
                    self._request_log.append({
                        "timestamp": time.time(),
                        "method": "POST",
                        "path": "/v1/chat/completions",
                        "data": request_data,
                        "request_id": self._request_count
                    })

                self.fr.emit("Request logged", request_id=self._request_count)

                # Rate limiting simulation
                if self._rate_limit_enabled:
                    self.fr.emit("Simulating rate limit", delay=self._rate_limit_delay)
                    time.sleep(self._rate_limit_delay)

                # Error injection
                if self._error_mode == "auth_error":
                    self.fr.emit("Injecting auth error")
                    return jsonify({"error": {"message": "Invalid API key", "type": "invalid_request_error"}}), 401

                elif self._error_mode == "timeout":
                    self.fr.emit("Injecting timeout")
                    time.sleep(1)  # Simulate timeout - optimized for faster tests
                    return jsonify({"error": {"message": "Request timeout"}}), 408

                elif self._error_mode == "invalid_json":
                    self.fr.emit("Injecting invalid JSON")
                    return "Not JSON at all!", 200

                elif self._error_mode == "rate_limit":
                    self.fr.emit("Injecting rate limit error")
                    return jsonify({
                        "error": {
                            "message": "Rate limit exceeded",
                            "type": "rate_limit_error"
                        }
                    }), 429

                # Generate response based on mode
                if self._response_mode == "custom" and self._custom_handler:
                    self.fr.emit("Using custom handler")
                    response_data = self._custom_handler(request_data)
                    return jsonify(response_data), 200

                elif self._response_mode == "dynamic":
                    # Echo user message with prefix
                    messages = request_data.get("messages", [])
                    user_message = messages[-1].get("content", "") if messages else ""
                    content = f"Mock response to: {user_message}"
                    self.fr.emit("Dynamic response generated", content_length=len(content))

                else:  # static mode (default)
                    content = self._static_content
                    self.fr.emit("Static response", content_length=len(content))

                # Build OpenAI-compatible response
                response = {
                    "id": f"chatcmpl-mock-{self._request_count}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": request_data.get("model", "gpt-3.5-turbo"),
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 20,
                        "total_tokens": 30
                    }
                }

                self.fr.emit("Response sent", request_id=self._request_count)
                return jsonify(response), 200

            except Exception as e:
                self.fr.emit("Error handling request", error=str(e))
                return jsonify({"error": {"message": f"Internal error: {str(e)}"}}), 500

        @self.app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint."""
            return jsonify({"status": "ok", "requests_served": self._request_count}), 200

    def start(self):
        """
        Start the mock server in a background thread.

        Uses automatic port allocation if port=0 was specified.
        Blocks briefly to ensure server is ready before returning.
        """
        if self._is_running:
            self.fr.emit("Server already running", port=self.port)
            return

        self.fr.emit("Starting server", host=self.host, requested_port=self._requested_port)

        try:
            self.server = make_server(self.host, self._requested_port, self.app, threaded=True)
            self.port = self.server.server_address[1]  # Get actual assigned port
            self._is_running = True

            self.fr.emit("Server bound to port", actual_port=self.port)

            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True,
                name=f"MockLLMServer-{self.port}"
            )
            self.server_thread.start()

            # Wait for server to be ready
            max_attempts = 10
            for attempt in range(max_attempts):
                try:
                    import requests
                    response = requests.get(f"http://{self.host}:{self.port}/health", timeout=1)
                    if response.status_code == 200:
                        self.fr.emit("Server started successfully", port=self.port, attempts=attempt + 1)
                        return
                except:
                    time.sleep(0.1)

            # Server didn't respond - force cleanup
            self.fr.emit("Server failed to become ready", port=self.port)
            self.stop()
            raise RuntimeError(f"MockLLMServer on port {self.port} failed to become ready after 10 attempts")

        except Exception as e:
            self._is_running = False
            self.fr.emit("Server start failed", error=str(e))
            raise

    def stop(self):
        """Stop the mock server with enhanced cleanup."""
        if not self._is_running:
            self.fr.emit("Server already stopped")
            return

        self.fr.emit("Stopping server", port=self.port, requests_served=self._request_count)

        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()  # Explicitly close socket

            # Wait for thread to finish (with timeout)
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=2.0)
                if self.server_thread.is_alive():
                    self.fr.emit("Warning: server thread did not terminate", port=self.port)

            self._is_running = False
            self.fr.emit("Server stopped cleanly", port=self.port)

        except Exception as e:
            self.fr.emit("Error during server stop", error=str(e), port=self.port)
            self._is_running = False
        finally:
            self.server = None
            self.server_thread = None

    def is_running(self) -> bool:
        """Check if server is currently running."""
        return self._is_running and self.server is not None

    def set_response_mode(self, mode: str, **kwargs):
        """
        Configure response behavior.

        Args:
            mode: Response mode - "static", "dynamic", "custom", or "error"
            **kwargs: Mode-specific parameters
                - For "static": content=str (response text)
                - For "custom": handler=callable (function(request_data) -> response_dict)
                - For "error": error_type=str (auth_error, timeout, invalid_json, rate_limit)

        Example:
            >>> server.set_response_mode("static", content="Test response")
            >>> server.set_response_mode("custom", handler=lambda req: {"choices": [...]})
            >>> server.set_response_mode("error", error_type="auth_error")
        """
        self.fr.emit("Setting response mode", mode=mode, kwargs=kwargs)

        self._response_mode = mode

        if mode == "static":
            self._static_content = kwargs.get("content", "Mock LLM response")
            self._error_mode = None  # Clear error state to prevent pollution

        elif mode == "dynamic":
            self._error_mode = None  # Clear error state to prevent pollution

        elif mode == "custom":
            self._custom_handler = kwargs.get("handler")
            if not callable(self._custom_handler):
                raise ValueError("Custom mode requires 'handler' callable")
            self._error_mode = None  # Clear error state to prevent pollution

        elif mode == "error":
            self._error_mode = kwargs.get("error_type", "auth_error")
            if self._error_mode not in ["auth_error", "timeout", "invalid_json", "rate_limit"]:
                raise ValueError(f"Invalid error_type: {self._error_mode}")

    def enable_rate_limiting(self, delay: float = 1.0):
        """
        Enable rate limiting simulation.

        Args:
            delay: Delay in seconds to add to each request
        """
        self.fr.emit("Enabling rate limiting", delay=delay)
        self._rate_limit_enabled = True
        self._rate_limit_delay = delay

    def disable_rate_limiting(self):
        """Disable rate limiting simulation."""
        self.fr.emit("Disabling rate limiting")
        self._rate_limit_enabled = False

    def get_request_log(self) -> List[Dict[str, Any]]:
        """
        Get log of all requests received by the server.

        Returns:
            List of request dictionaries with timestamp, method, path, data

        Example:
            >>> server.get_request_log()
            [{"timestamp": 123.45, "method": "POST", "path": "/v1/chat/completions", ...}]
        """
        with self._lock:
            return self._request_log.copy()

    def get_request_count(self) -> int:
        """Get total number of requests received."""
        with self._lock:
            return self._request_count

    def clear_request_log(self):
        """Clear the request log."""
        self.fr.emit("Clearing request log")
        with self._lock:
            self._request_log.clear()
            self._request_count = 0

    def get_last_request(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent request received.

        Returns:
            Last request dict or None if no requests
        """
        with self._lock:
            return self._request_log[-1] if self._request_log else None

    @property
    def url(self) -> str:
        """Get the base URL of the mock server."""
        return f"http://{self.host}:{self.port}"

    def __repr__(self):
        return f"MockLLMServer(host={self.host}, port={self.port}, requests={self._request_count})"


# Convenience function for pytest fixtures
def create_mock_llm_server(port: int = 8899, **kwargs) -> MockLLMServer:
    """
    Factory function to create and configure a MockLLMServer.

    Args:
        port: Port number for the server
        **kwargs: Additional configuration passed to MockLLMServer

    Returns:
        Configured MockLLMServer instance (not started)

    Example:
        @pytest.fixture(scope="module")
        def llm_server():
            server = create_mock_llm_server(port=8899)
            server.start()
            yield server
            server.stop()
    """
    return MockLLMServer(port=port, **kwargs)
