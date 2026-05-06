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
FlightRecorder CLI scripts for log management and querying.

This package provides command-line tools for working with FlightRecorder logs:

- cleanup: Clean up old FlightRecorder log files
- query: Query and analyze FlightRecorder logs

These scripts are available as console commands after installing neoaxios-logging:

    pip install neoaxios-logging

Available commands:

    neoaxios-fr-cleanup --older-than 30 --dry-run
    neoaxios-fr-query --level ERROR --stats

See individual module documentation for details.
"""

from neoaxios_logging.scripts.cleanup import cleanup_old_logs, main as cleanup_main
from neoaxios_logging.scripts.query import (
    FlightRecorderLogReader,
    query_events,
    get_test_timeline,
    find_failures,
    main as query_main
)

__all__ = [
    # Cleanup
    'cleanup_old_logs',
    'cleanup_main',

    # Query
    'FlightRecorderLogReader',
    'query_events',
    'get_test_timeline',
    'find_failures',
    'query_main',
]
