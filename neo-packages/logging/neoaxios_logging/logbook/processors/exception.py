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
Structured exception rendering processor.

This module provides processors for converting exceptions to structured
dictionaries suitable for querying in log aggregation platforms.
"""

from typing import Optional
from structlog.processors import ExceptionRenderer, dict_tracebacks


def create_exception_processors(
    include_locals: bool = False,
    include_chain: bool = True,
    max_frames: Optional[int] = None
) -> tuple:
    """
    Create configured exception processing processors.

    Returns two processors that work together to render exceptions as
    structured dictionaries rather than strings:
    1. dict_tracebacks: Converts exception to dictionary format
    2. ExceptionRenderer: Renders the dictionary for output

    Args:
        include_locals: If True, include local variables in frames (security risk)
        include_chain: If True, include exception chain (default: True)
        max_frames: Maximum number of frames to include (None = unlimited)

    Returns:
        Tuple of (dict_tracebacks_processor, exception_renderer)

    Example:
        >>> dict_tb, exc_render = create_exception_processors()
        >>> # Add both to structlog processor pipeline
        >>> # dict_tracebacks first, then ExceptionRenderer
    """
    # Configure dict_tracebacks processor
    # This converts exception objects to structured dictionaries
    dict_tb_processor = dict_tracebacks

    # Configure ExceptionRenderer
    # This renders the exception dictionary for output
    exc_renderer = ExceptionRenderer(exception_formatter=dict_tracebacks)

    return (dict_tb_processor, exc_renderer)


# Default processor instances
default_dict_tracebacks, default_exception_renderer = create_exception_processors()
