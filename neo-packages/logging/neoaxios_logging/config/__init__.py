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
Telemetry Configuration System - Infrastructure Layer

Provides centralized configuration management infrastructure for all telemetry implementations.
Configuration sources with precedence (highest to lowest):

1. CLI arguments
2. Environment variables
3. .env.local file
4. .env.test file
5. .env file
6. telemetry.yaml configuration file
7. Default values

Config classes are defined in their respective implementation folders:
- LogbookConfig: logbook/config.py
- FlightRecorderConfig + PerformanceConfig: flight_recorder/config.py
- DiagnosticsConfig: diagnostics/config.py

Usage:
    from neoaxios_logging.config import get_config_manager

    config = get_config_manager().load()
    print(f"Structured logger enabled: {config.logbook.enabled}")
    print(f"Performance max history: {config.performance.max_history_size}")
"""

# Infrastructure (manager, discovery, loading)
from .manager import (
    ConfigManager,
    ProjectConfig,
    get_config_manager,
    load_config,
    DEFAULT_CONFIG_NAME,
)

from .config_discovery import ConfigDiscovery
from .env_loader import load_env_files

# Config classes (re-exported for convenience)
from ..logbook.config import LogbookConfig
from ..flight_recorder.config import FlightRecorderConfig, PerformanceConfig
from ..diagnostics.config import DiagnosticsConfig


__all__ = [
    # Infrastructure
    'ConfigManager',
    'ProjectConfig',
    'get_config_manager',
    'load_config',
    'DEFAULT_CONFIG_NAME',

    # Config classes
    'LogbookConfig',
    'FlightRecorderConfig',
    'PerformanceConfig',
    'DiagnosticsConfig',

    # Discovery and utilities
    'ConfigDiscovery',
    'load_env_files',
]
