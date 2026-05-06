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
Environment file loading utility.

This module provides standalone functions for loading .env files
with proper precedence handling.
"""

import os
from pathlib import Path
from typing import Dict, Optional

# Check if python-dotenv is available
try:
    from dotenv import load_dotenv

    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


def load_env_files(project_root: Optional[Path] = None) -> Dict[str, str]:
    """
    Load .env files with proper precedence.

    Precedence (from lowest to highest):
    1. .env file
    2. .env.test file (overrides .env)
    3. .env.local file (overrides both)

    Environment variables already set have highest precedence and are never overridden.

    Args:
        project_root: Project root directory. Defaults to current working directory.

    Returns:
        Dictionary of TELEMETRY environment variables that were loaded from files.
    """
    if not DOTENV_AVAILABLE:
        return {}

    if project_root is None:
        project_root = Path.cwd()

    # Save existing TELEMETRY variables - these have highest precedence
    original_vars = {key: value for key, value in os.environ.items()
                    if key.startswith("TELEMETRY_") or
                       key in ("ENHANCED_LOGGING", "PROCESS_DEBUG", "PERFORMANCE_TRACKING",
                              "FLIGHT_RECORDER_ENABLED", "DIAGNOSTICS_ENABLED")}

    # Load .env files in order of precedence (lowest to highest)
    env_files = [
        (project_root / ".env", False),  # Base config, no override
        (project_root / ".env.test", True),  # Test config, override
        (project_root / ".env.local", True),  # Local config, override
    ]

    loaded_vars = {}

    for env_file, override in env_files:
        if env_file.exists():
            # Track what's in environment before loading this file
            before_load = {k: v for k, v in os.environ.items()
                          if k.startswith("TELEMETRY_") or k in original_vars}

            try:
                if override:
                    load_dotenv(str(env_file), override=True)
                else:
                    load_dotenv(str(env_file))
            except Exception:
                # Silently ignore errors loading .env files
                # This handles permission errors, malformed files, etc.
                pass

            # Track what was loaded from this specific file
            after_load = {k: v for k, v in os.environ.items()
                         if k.startswith("TELEMETRY_") or k in original_vars}
            file_vars = {
                k: v
                for k, v in after_load.items()
                if k not in original_vars and (k not in before_load or before_load[k] != v)
            }
            loaded_vars.update(file_vars)

    # Restore original environment variables (highest precedence)
    # These should never be overridden by .env files
    for key, value in original_vars.items():
        os.environ[key] = value

    return loaded_vars
