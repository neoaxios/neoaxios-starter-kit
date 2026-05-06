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
Diagnostics Configuration

Configuration for the diagnostics system.
"""

from dataclasses import dataclass


@dataclass
class DiagnosticsConfig:
    """Diagnostics system configuration."""

    enabled: bool = True  # Enable diagnostics checks
    auto_run: bool = False  # Automatically run diagnostics on startup
    check_python: bool = True  # Check Python environment
    check_javascript: bool = True  # Check JavaScript/Node.js environment
    check_cache: bool = True  # Check cache integrity
    check_config: bool = True  # Check configuration files
    check_runtime: bool = True  # Check runtime dependencies
    fail_on_error: bool = False  # Fail if diagnostics find errors



__all__ = [
    'DiagnosticsConfig',
]
