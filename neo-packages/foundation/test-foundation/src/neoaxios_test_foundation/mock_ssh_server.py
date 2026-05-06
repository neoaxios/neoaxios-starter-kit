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
Mock SSH Server - Paramiko-based SSH server for testing.

Provides a mock SSH server for testing distributed test-execution code paths
without requiring actual remote workers.

USAGE (DO NOT DUPLICATE THIS CODE):
    from neoaxios_test_foundation.mock_ssh_server import MockSSHServer

    @pytest.fixture(scope="module")
    def ssh_server():
        server = MockSSHServer(port=2222)
        server.start()
        yield server
        server.stop()

    def test_example(ssh_server):
        import paramiko
        client = paramiko.SSHClient()
        client.connect("localhost", port=ssh_server.port, username="test", password="test")
        stdin, stdout, stderr = client.exec_command("echo hello")
        assert stdout.read() == b"hello\\n"

Telemetry: uses FlightRecorder for operational logging.
Thread-safe: safe for concurrent test execution.
"""

import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import paramiko
from paramiko import RSAKey, ServerInterface, Transport
from paramiko.channel import Channel
from neoaxios_logging.flight_recorder import FlightRecorder


class MockSSHServerHandler(ServerInterface):
    """
    Paramiko ServerInterface implementation for mock SSH server.

    Handles authentication and channel requests.
    """

    def __init__(self, command_handler: Callable[[str], tuple]):
        """
        Initialize SSH server handler.

        Args:
            command_handler: Function to handle SSH commands (cmd) -> (stdout, stderr, exit_code)
        """
        self.command_handler = command_handler
        self.fr = FlightRecorder("mock_ssh_handler")

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Check password authentication.

        Args:
            username: Username
            password: Password

        Returns:
            AUTH_SUCCESSFUL or AUTH_FAILED
        """
        self.fr.emit("Password auth attempt", username=username)

        # Accept any username/password for testing
        if username == "test" and password == "test":
            self.fr.emit("Auth successful", username=username)
            return paramiko.AUTH_SUCCESSFUL

        # Also accept testuser/testpass (commonly used in tests)
        if username == "testuser" and password == "testpass":
            self.fr.emit("Auth successful", username=username)
            return paramiko.AUTH_SUCCESSFUL

        self.fr.emit("Auth failed", username=username)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """
        Check public key authentication.

        Args:
            username: Username
            key: Public key

        Returns:
            AUTH_SUCCESSFUL (accepts any key for testing)
        """
        self.fr.emit("Pubkey auth attempt", username=username)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        """
        Get allowed authentication methods.

        Args:
            username: Username

        Returns:
            Comma-separated list of allowed auth methods
        """
        return "password,publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """
        Check if a channel request is allowed.

        Args:
            kind: Channel type (e.g., "session")
            chanid: Channel ID

        Returns:
            OPEN_SUCCEEDED
        """
        self.fr.emit("Channel request", kind=kind, chanid=chanid)

        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        """
        Handle exec request (command execution).

        Args:
            channel: Channel for communication
            command: Command to execute

        Returns:
            True if request accepted
        """
        cmd = command.decode("utf-8")
        self.fr.emit("Exec request", command=cmd)

        # Execute command via handler
        try:
            stdout, stderr, exit_code = self.command_handler(cmd)
            self.fr.emit("Command executed", exit_code=exit_code)

            # Send output
            if stdout:
                channel.sendall(stdout.encode("utf-8") if isinstance(stdout, str) else stdout)
            if stderr:
                channel.sendall_stderr(stderr.encode("utf-8") if isinstance(stderr, str) else stderr)

            # Send exit status
            channel.send_exit_status(exit_code)

        except Exception as e:
            self.fr.emit("Command execution error", error=str(e))
            channel.sendall_stderr(f"Error: {str(e)}\n".encode("utf-8"))
            channel.send_exit_status(1)

        finally:
            channel.close()

        return True

    def check_channel_pty_request(self, channel: Channel, term: bytes, width: int, height: int,
                                    pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        """
        Handle PTY request.

        Returns:
            True (accept all PTY requests for testing)
        """
        self.fr.emit("PTY request", term=term.decode("utf-8"))
        return True

    def check_channel_shell_request(self, channel: Channel) -> bool:
        """
        Handle shell request.

        Returns:
            False (we only support exec, not interactive shell)
        """
        self.fr.emit("Shell request (rejected)")
        return False


class MockSSHServer:
    """
    Mock SSH server for distributed test-execution integration tests.

    Features:
        - Command execution simulation
        - File transfer simulation (rsync/scp)
        - Configurable command handlers
        - Connection tracking
        - Error injection capabilities
        - Thread-safe operation
        - Easy pytest fixture integration

    Example:
        >>> server = MockSSHServer(port=2222)
        >>> server.add_command_handler("echo hello", stdout="hello\\n", exit_code=0)
        >>> server.start()
        >>> # Run tests
        >>> server.stop()
        >>> connections = server.get_connection_log()
    """

    def __init__(self, port: int = 2222, host: str = "127.0.0.1"):
        """
        Initialize mock SSH server.

        Args:
            port: Port to listen on (default: 2222)
            host: Host to bind to (default: 127.0.0.1)
        """
        self.port = port
        self.host = host
        self.fr = FlightRecorder(f"mock_ssh_server.{port}")

        # Server state
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

        # Command handlers
        self._command_handlers: Dict[str, tuple] = {}
        self._default_handler: Optional[Callable] = None
        self._command_log: List[Dict[str, Any]] = []
        self._connection_count = 0

        # Error injection
        self._error_mode: Optional[str] = None  # connection_refused, auth_failure, command_timeout

        # Generate host key
        self._host_key = RSAKey.generate(2048)

        self.fr.emit("MockSSHServer initialized", port=port, host=host)

    def _handle_client(self, client_socket: socket.socket, addr: tuple):
        """
        Handle an incoming SSH client connection.

        Args:
            client_socket: Client socket
            addr: Client address (host, port)
        """
        self.fr.emit("Client connected", addr=addr)

        with self._lock:
            self._connection_count += 1
            connection_id = self._connection_count

        try:
            # Create SSH transport
            transport = Transport(client_socket)
            transport.add_server_key(self._host_key)

            # Create server handler
            server_handler = MockSSHServerHandler(self._execute_command)

            # Start SSH server
            transport.start_server(server=server_handler)

            # Wait for channel
            channel = transport.accept(timeout=10)
            if channel is None:
                self.fr.emit("No channel opened", connection_id=connection_id)
                return

            # Keep transport alive while channel is active
            while not channel.closed:
                time.sleep(0.1)

            self.fr.emit("Client disconnected", connection_id=connection_id)

        except Exception as e:
            self.fr.emit("Error handling client", error=str(e), connection_id=connection_id)

        finally:
            try:
                client_socket.close()
            except:
                pass

    def _execute_command(self, command: str) -> tuple:
        """
        Execute a command via registered handlers.

        Args:
            command: Command string

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        self.fr.emit("Executing command", command=command)

        # Log command
        with self._lock:
            self._command_log.append({
                "timestamp": time.time(),
                "command": command
            })

        # Error injection
        if self._error_mode == "command_timeout":
            self.fr.emit("Injecting command timeout")
            time.sleep(10)
            return "", "Command timeout", 124

        # Check for exact match handler
        if command in self._command_handlers:
            handler = self._command_handlers[command]
            stdout = handler[0] if len(handler) > 0 else ""
            stderr = handler[1] if len(handler) > 1 else ""
            exit_code = handler[2] if len(handler) > 2 else 0
            self.fr.emit("Command handled (exact match)", exit_code=exit_code)
            return stdout, stderr, exit_code

        # Check for pattern match handler (startswith)
        for pattern, handler in self._command_handlers.items():
            if command.startswith(pattern):
                stdout = handler[0] if len(handler) > 0 else ""
                stderr = handler[1] if len(handler) > 1 else ""
                exit_code = handler[2] if len(handler) > 2 else 0
                self.fr.emit("Command handled (pattern match)", pattern=pattern, exit_code=exit_code)
                return stdout, stderr, exit_code

        # Default handler
        if self._default_handler:
            self.fr.emit("Using default handler")
            return self._default_handler(command)

        # Built-in handlers for common commands
        if command.startswith("echo "):
            msg = command[5:].strip()
            return f"{msg}\n", "", 0

        elif command.startswith("pytest "):
            # Simulate successful test run
            return "collected 10 items\ntest_sample.py::test_1 PASSED\n", "", 0

        elif command.startswith("rsync "):
            # Simulate successful rsync
            return "", "", 0

        elif command == "pwd":
            return "/tmp/work\n", "", 0

        elif command.startswith("mkdir "):
            return "", "", 0

        # Unknown command
        self.fr.emit("Unknown command (returning error)", command=command)
        return "", f"bash: {command.split()[0]}: command not found\n", 127

    def _accept_connections(self):
        """Accept incoming SSH connections (runs in background thread)."""
        self.fr.emit("Accept loop started")

        while self._running:
            try:
                # Check for shutdown with timeout
                self._server_socket.settimeout(1.0)
                client_socket, addr = self._server_socket.accept()

                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()

            except socket.timeout:
                continue  # Check _running flag

            except Exception as e:
                if self._running:  # Only log if not shutting down
                    self.fr.emit("Accept error", error=str(e))
                break

        self.fr.emit("Accept loop stopped")

    def start(self):
        """
        Start the mock SSH server in a background thread.

        Blocks briefly to ensure server is ready before returning.
        """
        self.fr.emit("Starting server", host=self.host, port=self.port)

        # Error injection
        if self._error_mode == "connection_refused":
            self.fr.emit("Error injection: connection refused (not starting)")
            return  # Don't start server

        # Create server socket
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)

        # Start accept thread
        self._running = True
        self._server_thread = threading.Thread(target=self._accept_connections, daemon=True)
        self._server_thread.start()

        # Wait for server to be ready
        time.sleep(0.2)
        self.fr.emit("Server started successfully")

    def stop(self):
        """Stop the mock SSH server."""
        self.fr.emit("Stopping server")

        self._running = False

        if self._server_socket:
            try:
                self._server_socket.close()
            except:
                pass

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)

        self.fr.emit("Server stopped", total_connections=self._connection_count)

    def add_command_handler(self, command: str, stdout: str = "", stderr: str = "", exit_code: int = 0):
        """
        Register a command handler.

        Args:
            command: Command string (exact match or prefix)
            stdout: Standard output to return
            stderr: Standard error to return
            exit_code: Exit code to return

        Example:
            >>> server.add_command_handler("echo hello", stdout="hello\\n", exit_code=0)
            >>> server.add_command_handler("pytest ", stdout="PASSED", exit_code=0)  # Prefix match
        """
        self.fr.emit("Adding command handler", command=command, exit_code=exit_code)
        self._command_handlers[command] = (stdout, stderr, exit_code)

    def set_default_handler(self, handler: Callable[[str], tuple]):
        """
        Set a default handler for unmatched commands.

        Args:
            handler: Function that takes command string and returns (stdout, stderr, exit_code)

        Example:
            >>> server.set_default_handler(lambda cmd: (f"Ran: {cmd}", "", 0))
        """
        self.fr.emit("Setting default handler")
        self._default_handler = handler

    def set_error_mode(self, error_mode: Optional[str]):
        """
        Enable error injection.

        Args:
            error_mode: Error type - "connection_refused", "auth_failure", "command_timeout", or None

        Example:
            >>> server.set_error_mode("connection_refused")
            >>> server.set_error_mode(None)  # Disable
        """
        self.fr.emit("Setting error mode", error_mode=error_mode)
        self._error_mode = error_mode

    def get_command_log(self) -> List[Dict[str, Any]]:
        """
        Get log of all commands executed.

        Returns:
            List of command dictionaries with timestamp and command

        Example:
            >>> server.get_command_log()
            [{"timestamp": 123.45, "command": "echo hello"}, ...]
        """
        with self._lock:
            return self._command_log.copy()

    def get_connection_count(self) -> int:
        """Get total number of connections received."""
        with self._lock:
            return self._connection_count

    def clear_command_log(self):
        """Clear the command log."""
        self.fr.emit("Clearing command log")
        with self._lock:
            self._command_log.clear()

    def get_last_command(self) -> Optional[str]:
        """
        Get the most recent command executed.

        Returns:
            Last command string or None if no commands
        """
        with self._lock:
            if self._command_log:
                return self._command_log[-1]["command"]
            return None

    @property
    def connection_string(self) -> str:
        """Get SSH connection string (host:port)."""
        return f"{self.host}:{self.port}"

    def __repr__(self):
        return f"MockSSHServer(host={self.host}, port={self.port}, connections={self._connection_count})"


# Convenience function for pytest fixtures
def create_mock_ssh_server(port: int = 2222, **kwargs) -> MockSSHServer:
    """
    Factory function to create and configure a MockSSHServer.

    Args:
        port: Port number for the server
        **kwargs: Additional configuration passed to MockSSHServer

    Returns:
        Configured MockSSHServer instance (not started)

    Example:
        @pytest.fixture(scope="module")
        def ssh_server():
            server = create_mock_ssh_server(port=2222)
            server.add_command_handler("pytest ", stdout="PASSED", exit_code=0)
            server.start()
            yield server
            server.stop()
    """
    return MockSSHServer(port=port, **kwargs)
