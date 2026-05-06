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
Structlog processors for Logbook.

This module exports custom processors for the structlog pipeline including
per-component log level filtering, automatic source location tracking,
structured exception rendering, and unicode safety.
"""

from neoaxios_logging.logbook.processors.level_filter import LogLevelFilterProcessor
from neoaxios_logging.logbook.processors.callsite import (
    create_callsite_processor,
    callsite_processor
)
from neoaxios_logging.logbook.processors.exception import (
    create_exception_processors,
    default_dict_tracebacks,
    default_exception_renderer
)
from neoaxios_logging.logbook.processors.unicode_safety import (
    create_unicode_processors,
    default_unicode_decoder,
    default_unicode_encoder
)

__all__ = [
    'LogLevelFilterProcessor',
    'create_callsite_processor',
    'callsite_processor',
    'create_exception_processors',
    'default_dict_tracebacks',
    'default_exception_renderer',
    'create_unicode_processors',
    'default_unicode_decoder',
    'default_unicode_encoder'
]
