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
Centralized test configuration for LLM-backed test suites.

Provides a single source of truth for the LLM backend host/port and
model name used during tests. Resolution always defers to environment
variables; the constants here are last-resort defaults.

Usage:
    # In a package's conftest.py:
    from neoaxios_test_foundation.test_config import (
        get_llm_model_name,
        get_llm_backend_url,
        DEFAULT_LLM_MODEL,
    )

    TEST_MODEL = get_llm_model_name()
"""

# Tell pytest this is a utility module, not a test module
__test__ = False

import json
import os
import urllib.request

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LLM Backend Defaults
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# These values are last-resort defaults.  Environment variables
# (NEO_LLM_BASE_URL, NEO_LLM_BACKEND_HOST, NEO_LLM_BACKEND_PORT,
# NEO_LLM_MODEL, TEST_MODEL) override them.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# LLM backend served on the loopback interface during tests.
DEFAULT_LLM_BACKEND_HOST = "127.0.0.1"
DEFAULT_LLM_BACKEND_PORT = 12345


# Default model for tests
# IMPORTANT: Model MUST be configured via environment variable or config file
# This sentinel value ensures tests fail clearly if model is not configured
DEFAULT_LLM_MODEL = "UNSET--configure-NEO_LLM_MODEL"

# Module-level cache for auto-discovered model (None = not yet attempted)
_autodiscovered_model: str | None = None
_autodiscovery_attempted: bool = False


@auto_trace(logger)
def _autodiscover_model_from_backend() -> str | None:
    """Query the LLM backend's /v1/models endpoint to discover available models.

    Uses the backend URL from ``get_llm_backend_url()`` (which itself respects
    NEO_LLM_BASE_URL and host/port env vars).  The result is cached for the
    lifetime of the process so at most one HTTP call is made.

    Returns:
        Model ID string if exactly one model is available, or the first model
        if several are listed.  ``None`` on any network/parse error.
    """
    global _autodiscovered_model, _autodiscovery_attempted
    if _autodiscovery_attempted:
        return _autodiscovered_model
    _autodiscovery_attempted = True

    try:
        backend_url = get_llm_backend_url()
        models_url = f"{backend_url}/models"
        req = urllib.request.Request(models_url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1) as resp:
            body = json.loads(resp.read())
        models = body.get("data", [])
        if models:
            _autodiscovered_model = models[0]["id"]
            os.environ.setdefault("NEO_LLM_MODEL", _autodiscovered_model)
            logger.info(
                "auto_discovered_llm_model",
                model=_autodiscovered_model,
                source=models_url,
                model_count=len(models),
            )
    except Exception as exc:  # graceful degradation to sentinel when backend unreachable
        logger.debug("llm_model_autodiscovery_failed", error=str(exc))

    return _autodiscovered_model


@auto_trace(logger)
def get_llm_model_name() -> str:
    """
    Get default LLM model name for tests.

    Checks environment variables, then attempts auto-discovery from the LLM
    backend's ``/v1/models`` endpoint, with final fallback to sentinel.
    This is the ONLY function that should determine the model name.

    Resolution order:
        1. TEST_MODEL env var — explicit test override
        2. NEO_LLM_MODEL env var — canonical NeoAxios model name
        3. NEO_LLM_BACKEND_MODEL env var — component-specific override
        4. Auto-discovery via /v1/models on the LLM backend
        5. DEFAULT_LLM_MODEL sentinel — causes clear failure if backend unreachable

    Returns:
        Model name string (e.g., "vendor/model-name" or "/path/to/model.gguf")
    """
    model = (
        os.environ.get("TEST_MODEL")
        or os.environ.get("NEO_LLM_MODEL")
        or os.environ.get("NEO_LLM_BACKEND_MODEL")
        or _autodiscover_model_from_backend()
        or DEFAULT_LLM_MODEL
    )

    logger.info("Using LLM model", model=model)
    return model


@auto_trace(logger)
def get_llm_backend_url() -> str:
    """
    Get LLM backend URL from environment.

    Checks environment variables with fallback to centralized defaults.
    Returns URL with /v1 suffix for OpenAI API compatibility.

    Environment variable precedence:
        1. NEO_LLM_BASE_URL - full URL override (canonical)
        2. NEO_LLM_BACKEND_HOST + NEO_LLM_BACKEND_PORT - host/port components
        3. DEFAULT_LLM_BACKEND_HOST + DEFAULT_LLM_BACKEND_PORT - hardcoded defaults

    Returns:
        Backend URL string with /v1 suffix (e.g., "http://127.0.0.1:12345/v1")
    """
    # Check for full URL override first
    if backend_url := os.environ.get("NEO_LLM_BASE_URL"):
        if not backend_url.endswith("/v1"):
            backend_url = f"{backend_url.rstrip('/')}/v1"
        logger.info("Using LLM backend URL from env", url=backend_url)
        return backend_url

    # Build from host/port components
    host = os.environ.get("NEO_LLM_BACKEND_HOST") or DEFAULT_LLM_BACKEND_HOST
    port = int(os.environ.get("NEO_LLM_BACKEND_PORT") or DEFAULT_LLM_BACKEND_PORT)
    backend_url = f"http://{host}:{port}/v1"

    logger.info("Using LLM backend URL from defaults", url=backend_url, host=host, port=port)
    return backend_url


@auto_trace(logger)
def get_llm_backend_host() -> str:
    """
    Get LLM backend host (hostname or IP only).

    Returns:
        Host string (e.g., "127.0.0.1")
    """
    return os.environ.get("NEO_LLM_BACKEND_HOST") or DEFAULT_LLM_BACKEND_HOST


@auto_trace(logger)
def get_llm_backend_port() -> int:
    """
    Get LLM backend port (port number only).

    Returns:
        Port integer (e.g., 12345)
    """
    return int(os.environ.get("NEO_LLM_BACKEND_PORT") or DEFAULT_LLM_BACKEND_PORT)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Export all configuration functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

__all__ = [
    # Configuration defaults
    'DEFAULT_LLM_MODEL',
    'DEFAULT_LLM_BACKEND_HOST',
    'DEFAULT_LLM_BACKEND_PORT',
    # Configuration getters
    'get_llm_model_name',
    'get_llm_backend_url',
    'get_llm_backend_host',
    'get_llm_backend_port',
]
