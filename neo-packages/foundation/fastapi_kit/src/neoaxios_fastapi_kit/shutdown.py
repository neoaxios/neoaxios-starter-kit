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

"""Graceful shutdown handling for FastAPI services."""

import signal
import asyncio
import threading
import warnings
from types import FrameType
from typing import Optional, Callable, List, AsyncContextManager
from contextlib import asynccontextmanager
from fastapi import FastAPI
from neoaxios_secure_cache.defaults import GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS
from neoaxios_logging import get_telemetry, auto_trace


logger = get_telemetry(__name__)


# =============================================================================
# Global Shutdown Registry (Multi-App Support)
# =============================================================================

# Global registry of shutdown events from all FastAPI apps in the process
# This enables a single signal handler to trigger shutdown for all apps
_shutdown_registry: List[asyncio.Event] = []
_registry_lock = threading.Lock()
_signal_handlers_installed = False


@auto_trace(logger)  # OS signal callback
def _global_signal_handler(signum: int, frame: Optional[FrameType]) -> None:
    """Global signal handler that triggers shutdown for ALL registered apps.

    This handler is installed ONCE at process level and notifies all
    registered FastAPI applications via their shutdown events.

    Thread-safe: Uses lock to access global registry.

    Args:
        signum: Signal number (SIGTERM or SIGINT)
        frame: Current stack frame (unused)
    """
    sig_name = signal.Signals(signum).name
    logger.info(f"Received {sig_name}, initiating graceful shutdown for all apps...")

    with _registry_lock:
        app_count = len(_shutdown_registry)
        logger.info(f"Triggering shutdown for {app_count} registered app(s)")

        for idx, event in enumerate(_shutdown_registry):
            try:
                event.set()
                logger.debug(f"Shutdown event {idx + 1}/{app_count} triggered")
            except Exception as e:
                logger.error(f"Failed to trigger shutdown event {idx + 1}: {e}")


@auto_trace(logger)  # Factory function for signal handler
def _create_signal_handler(
    shutdown_event: asyncio.Event
) -> Callable[[int, Optional[FrameType]], None]:
    """Create signal handler for shutdown events (DEPRECATED - single app only).

    DEPRECATED: This creates per-app signal handlers which overwrite each other
    in multi-app scenarios. Use register_app_shutdown() instead.
    """
    def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, initiating graceful shutdown...")
        shutdown_event.set()
    return signal_handler


@auto_trace(logger)
def register_app_shutdown(shutdown_event: asyncio.Event) -> None:
    """Register app's shutdown event in global registry (multi-app safe).

    This function is idempotent and thread-safe. It registers the app's
    shutdown event in a global registry and installs process-level signal
    handlers ONCE for all apps.

    In multi-app scenarios, calling this from each app ensures:
    - All apps receive SIGTERM/SIGINT signals
    - No handler overwrites (single global handler)
    - All app shutdown sequences execute

    Thread-safe: Uses lock for registry mutations and handler installation.

    Args:
        shutdown_event: asyncio.Event from app.state.shutdown_event

    Example:
        app = FastAPI()
        shutdown_event = asyncio.Event()
        app.state.shutdown_event = shutdown_event
        register_app_shutdown(shutdown_event)  # Safe for multiple apps
    """
    global _signal_handlers_installed

    with _registry_lock:
        # Install global signal handlers ONCE (first app registration)
        if not _signal_handlers_installed:
            try:
                signal.signal(signal.SIGTERM, _global_signal_handler)
                signal.signal(signal.SIGINT, _global_signal_handler)
                _signal_handlers_installed = True
                logger.info("Installed global signal handlers (SIGTERM, SIGINT)")
            except ValueError as e:
                # Signal handlers only work in main thread (e.g., pytest)
                logger.warning(f"Could not install signal handlers (not main thread): {e}")
                return

        # Register this app's shutdown event (avoid duplicates)
        if shutdown_event not in _shutdown_registry:
            _shutdown_registry.append(shutdown_event)
            logger.info(f"Registered app shutdown event (total apps: {len(_shutdown_registry)})")
        else:
            logger.debug("Shutdown event already registered (duplicate call ignored)")


@auto_trace(logger)  # Deprecated signal handler registration
def _register_signal_handlers(shutdown_event: asyncio.Event) -> None:
    """Register SIGTERM and SIGINT handlers safely (DEPRECATED - single app only).

    DEPRECATED: This creates per-app signal handlers which overwrite each other
    in multi-app scenarios. Use register_app_shutdown() instead.

    Handles ValueError when not running in main thread (e.g., pytest).
    """
    handler = _create_signal_handler(shutdown_event)
    try:
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)
    except ValueError as e:
        # Signal handlers only work in main thread
        logger.warning(f"Could not register signal handlers (not main thread): {e}")


@auto_trace(logger)  # Executes cleanup during shutdown
async def _run_cleanup_callbacks(cleanup_callbacks: List[Callable]) -> None:
    """Execute cleanup callbacks (async and sync)."""
    logger.info("Running cleanup callbacks...")
    for callback in cleanup_callbacks:
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback()
            else:
                callback()
        except Exception as e:
            logger.error(f"Cleanup callback failed: {e}")
    logger.info("Cleanup completed")


@auto_trace(logger)
def create_graceful_shutdown_lifespan(
    shutdown_timeout: int = GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS,
    cleanup_callbacks: Optional[List[Callable]] = None,
) -> Callable[[FastAPI], AsyncContextManager]:
    """
    Create a lifespan context manager for graceful shutdown handling.

    This is the recommended approach for FastAPI applications, replacing
    the deprecated @app.on_event("shutdown") pattern.

    Ensures:
    - In-flight requests complete
    - Resources are cleaned up via callbacks
    - FastAPI lifespan shutdown runs
    - Process exits cleanly

    Args:
        shutdown_timeout: Max seconds to wait for cleanup
            (default: GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS)
        cleanup_callbacks: Optional list of async/sync cleanup functions

    Returns:
        Async context manager function for use with FastAPI(lifespan=...)

    Usage:
        from fastapi import FastAPI
        from neoaxios_fastapi_kit import create_graceful_shutdown_lifespan

        # Basic usage
        app = FastAPI(lifespan=create_graceful_shutdown_lifespan())

        # With custom cleanup
        async def close_db():
            await db.close()

        def close_cache():
            cache.cleanup()

        lifespan = create_graceful_shutdown_lifespan(
            cleanup_callbacks=[close_db, close_cache]
        )
        app = FastAPI(lifespan=lifespan)

    Features:
    - Signal handlers for SIGTERM and SIGINT
    - Shutdown event stored on app.state
    - Custom cleanup callbacks (async and sync)

    Note:
        In Kubernetes, set terminationGracePeriodSeconds >= shutdown_timeout.

    Example Kubernetes config:
        spec:
          terminationGracePeriodSeconds: 30
          containers:
          - lifecycle:
              preStop:
                exec:
                  command: ["/bin/sh", "-c", "sleep 5"]
    """
    # NOTE: No @auto_trace - Returns a factory function, not executed directly.
    # The returned lifespan context manager will be traced by FastAPI's internal machinery.
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan context manager for FastAPI application."""
        # Startup phase
        shutdown_event = asyncio.Event()

        # Use global registry (multi-app safe) + legacy handler for compatibility
        register_app_shutdown(shutdown_event)
        _register_signal_handlers(shutdown_event)

        app.state.shutdown_event = shutdown_event

        logger.info("Application startup complete")

        # Yield control to the application
        yield

        # Shutdown phase - runs when application is shutting down
        logger.info("Application shutdown initiated")

        # Run cleanup callbacks with timeout
        if cleanup_callbacks:
            try:
                await asyncio.wait_for(
                    _run_cleanup_callbacks(cleanup_callbacks),
                    timeout=shutdown_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"Cleanup timed out after {shutdown_timeout}s, "
                    "forcing shutdown"
                )

    return lifespan


@auto_trace(logger)
def add_graceful_shutdown(
    app: FastAPI,
    shutdown_timeout: int = GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS,
    cleanup_callbacks: Optional[List[Callable]] = None,
) -> None:
    """
    Add graceful shutdown handling for SIGTERM/SIGINT.

    .. deprecated:: 1.1.0
        Use :func:`create_graceful_shutdown_lifespan` instead.
        This function uses the deprecated @app.on_event("shutdown") pattern.

    Ensures:
    - In-flight requests complete
    - Resources are cleaned up
    - FastAPI lifespan shutdown runs
    - Process exits cleanly

    Args:
        app: FastAPI application instance
        shutdown_timeout: Max seconds to wait for cleanup
            (default: GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS)
        cleanup_callbacks: Optional list of async cleanup functions

    Usage (deprecated):
        app = FastAPI()
        add_graceful_shutdown(app)

        # With custom cleanup
        async def close_db():
            await db.close()

        add_graceful_shutdown(app, cleanup_callbacks=[close_db])

    Recommended alternative:
        from neoaxios_fastapi_kit import create_graceful_shutdown_lifespan

        lifespan = create_graceful_shutdown_lifespan(
            cleanup_callbacks=[close_db]
        )
        app = FastAPI(lifespan=lifespan)

    Note:
        This registers signal handlers for SIGTERM and SIGINT.
        In Kubernetes, set terminationGracePeriodSeconds >= shutdown_timeout.

    Example Kubernetes config:
        spec:
          terminationGracePeriodSeconds: 30
          containers:
          - lifecycle:
              preStop:
                exec:
                  command: ["/bin/sh", "-c", "sleep 5"]
    """
    warnings.warn(
        "add_graceful_shutdown() is deprecated and uses the deprecated "
        "@app.on_event('shutdown') pattern. Use create_graceful_shutdown_lifespan() "
        "instead with FastAPI(lifespan=...) for the modern lifespan approach.",
        DeprecationWarning,
        stacklevel=2
    )
    shutdown_event = asyncio.Event()

    # Use global registry (multi-app safe) + legacy handler for compatibility
    register_app_shutdown(shutdown_event)
    _register_signal_handlers(shutdown_event)

    app.state.shutdown_event = shutdown_event

    # Run cleanup callbacks on shutdown with timeout
    if cleanup_callbacks:
        # NOTE: No @auto_trace - FastAPI lifecycle event handler, not a route handler.
        # Uses logger.info()/logger.error() directly for shutdown visibility.
        @app.on_event("shutdown")
        async def run_cleanup():
            """Run custom cleanup callbacks with timeout."""
            try:
                await asyncio.wait_for(
                    _run_cleanup_callbacks(cleanup_callbacks),
                    timeout=shutdown_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"Cleanup timed out after {shutdown_timeout}s, "
                    "forcing shutdown"
                )
