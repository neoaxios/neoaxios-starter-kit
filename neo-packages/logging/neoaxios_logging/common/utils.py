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
Utility functions for telemetry package.

Provides helper functions for directory management and common operations.
"""

import os
from pathlib import Path


def get_telemetry_dir() -> Path:
    """
    Get telemetry directory for storing logs and exports.

    Uses environment variable NEO_TELEMETRY_DIR if set, otherwise creates
    .telemetry in the current working directory.

    Returns:
        Path object for telemetry directory
    """
    telemetry_dir = os.environ.get("NEO_TELEMETRY_DIR", ".telemetry")
    path = Path(telemetry_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path
