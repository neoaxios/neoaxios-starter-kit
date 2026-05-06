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

"""Shared configuration infrastructure for NeoAxios packages.

Provides hierarchical YAML configuration loading with a documented
override precedence (bundled defaults → system → user → project →
environment-specific → local overrides → explicit override → environment
variables), deep-merge semantics, and environment-variable substitution.
"""

from .loader import ConfigLoader
from .env_overrides import (
    apply_env_overrides_recursive,
    expand_env_vars,
    yaml_path_to_env_var,
    convert_value,
)
from .merger import deep_merge, merge_multiple
from .paths import ConfigPathResolver
from .hierarchical import HierarchicalSettings

__version__ = "0.2.1"

__all__ = [
    # Main loader
    "ConfigLoader",
    # Hierarchical settings
    "HierarchicalSettings",
    # Environment variable overrides
    "apply_env_overrides_recursive",
    "expand_env_vars",
    "yaml_path_to_env_var",
    "convert_value",
    # YAML merging
    "deep_merge",
    "merge_multiple",
    # Path resolution
    "ConfigPathResolver",
]
