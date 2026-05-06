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

"""Logbook configuration module."""

from neoaxios_logging.common.types import LogLevel
from .failure_only_config import FailureOnlyConfig
from .schema import (
    LogbookConfig,
    OutputConfig,
    CallsiteConfig,
    ExceptionConfig,
    UnicodeConfig,
    RotationConfig,
    FlushPolicyConfig,
    FilterRule,
    FieldMapping,
    BufferMode,
    RotationType,
)
from .loader import load_config, load_from_file, load_from_env, find_config_file

__all__ = [
    "LogLevel",
    "FailureOnlyConfig",
    "LogbookConfig",
    "OutputConfig",
    "CallsiteConfig",
    "ExceptionConfig",
    "UnicodeConfig",
    "RotationConfig",
    "FlushPolicyConfig",
    "FilterRule",
    "FieldMapping",
    "BufferMode",
    "RotationType",
    "load_config",
    "load_from_file",
    "load_from_env",
    "find_config_file",
]
