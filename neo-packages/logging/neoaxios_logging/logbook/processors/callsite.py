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
Automatic source location tracking processor.

This module provides a configured CallsiteParameterAdder from structlog
that automatically captures filename, function name, line number, and module
for all log calls.
"""

from typing import List
from structlog.processors import CallsiteParameter, CallsiteParameterAdder


def create_callsite_processor(
    additional_ignores: List[str] = None
) -> CallsiteParameterAdder:
    """
    Create a configured CallsiteParameterAdder processor.

    This processor automatically captures source code location information
    for all log calls, eliminating the need for manual function_name parameters.

    Args:
        additional_ignores: Additional module paths to ignore when walking the stack.
                          Defaults to ["telemetry.logbook"] to skip logger
                          wrapper frames.

    Returns:
        Configured CallsiteParameterAdder instance

    Example:
        >>> processor = create_callsite_processor()
        >>> # All logs will include: filename, func_name, lineno, module
    """
    if additional_ignores is None:
        additional_ignores = [
            "telemetry.logbook.core.logger",
            "telemetry.logbook",
        ]

    return CallsiteParameterAdder(
        parameters=[
            CallsiteParameter.FILENAME,
            CallsiteParameter.FUNC_NAME,
            CallsiteParameter.LINENO,
            CallsiteParameter.MODULE,
        ],
        additional_ignores=additional_ignores,
    )


# Default processor instance
callsite_processor = create_callsite_processor()
