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
Output handlers for Logbook.

This module provides file output management with:
- Multiple output destinations
- Configurable buffering strategies
- Size and time-based rotation
- Flexible flush policies
- Compression support
"""

from .file_output import FileOutput
from .manager import OutputManager, OutputProcessor

__all__ = [
    'FileOutput',
    'OutputManager',
    'OutputProcessor',
]
