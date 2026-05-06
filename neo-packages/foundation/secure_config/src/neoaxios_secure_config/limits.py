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

"""File size limits and configuration for secure_config.

Provides centralized constants and helper functions for file size validation.
This eliminates code duplication across loader and resolver modules.
"""

import os

from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)

# File size limits
MAX_CONFIG_FILE_SIZE = 10 * 1024 * 1024  # 10 MB for config files
MAX_SECRET_FILE_SIZE = 1 * 1024 * 1024   # 1 MB for secret files

# Environment variable extraction limits (defense in depth)
MAX_ENV_VAR_VALUE_SIZE = 64 * 1024  # 64 KB max per env var value
MAX_EXTRACT_ENV_VAR_COUNT = 100     # Max env vars that can be extracted per component


@auto_trace(logger)
def get_max_config_size() -> int:
    """Get maximum config file size from environment or default.

    Environment variable: SECURE_CONFIG_MAX_CONFIG_SIZE

    Returns:
        Maximum size in bytes
    """
    env_value = os.environ.get("SECURE_CONFIG_MAX_CONFIG_SIZE")
    if env_value is not None:
        try:
            return int(env_value)
        except ValueError:
            logger.warning(
                "Invalid SECURE_CONFIG_MAX_CONFIG_SIZE value, using default",
                extra={"env_value": env_value, "default": MAX_CONFIG_FILE_SIZE},
            )
    return MAX_CONFIG_FILE_SIZE


@auto_trace(logger)
def get_max_secret_size() -> int:
    """Get maximum secret file size from environment or default.

    Environment variable: SECURE_CONFIG_MAX_SECRET_SIZE

    Returns:
        Maximum size in bytes
    """
    env_value = os.environ.get("SECURE_CONFIG_MAX_SECRET_SIZE")
    if env_value is not None:
        try:
            return int(env_value)
        except ValueError:
            logger.warning(
                "Invalid SECURE_CONFIG_MAX_SECRET_SIZE value, using default",
                extra={"env_value": env_value, "default": MAX_SECRET_FILE_SIZE},
            )
    return MAX_SECRET_FILE_SIZE


@auto_trace(logger)
def get_max_env_var_value_size() -> int:
    """Get maximum env var value size from environment or default.

    Environment variable: SECURE_CONFIG_MAX_ENV_VAR_SIZE

    Returns:
        Maximum size in bytes
    """
    env_value = os.environ.get("SECURE_CONFIG_MAX_ENV_VAR_SIZE")
    if env_value is not None:
        try:
            return int(env_value)
        except ValueError:
            logger.warning(
                "Invalid SECURE_CONFIG_MAX_ENV_VAR_SIZE value, using default",
                extra={"env_value": env_value, "default": MAX_ENV_VAR_VALUE_SIZE},
            )
    return MAX_ENV_VAR_VALUE_SIZE


@auto_trace(logger)
def get_max_extract_env_var_count() -> int:
    """Get maximum number of env vars that can be extracted.

    Environment variable: SECURE_CONFIG_MAX_ENV_VAR_COUNT

    Returns:
        Maximum count
    """
    env_value = os.environ.get("SECURE_CONFIG_MAX_ENV_VAR_COUNT")
    if env_value is not None:
        try:
            return int(env_value)
        except ValueError:
            logger.warning(
                "Invalid SECURE_CONFIG_MAX_ENV_VAR_COUNT value, using default",
                extra={"env_value": env_value, "default": MAX_EXTRACT_ENV_VAR_COUNT},
            )
    return MAX_EXTRACT_ENV_VAR_COUNT
