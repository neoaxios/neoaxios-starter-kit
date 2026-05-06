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
Logbook configuration defaults.

All default values are defined here in one place. Changing a default
requires editing ONLY this file.
"""

# Default value for failure-only logging mode
# When True: Only log function calls that fail (ENTRY + EXIT with rc=1)
# When False: Log all function calls (ENTRY + EXIT regardless of outcome)
#
# Impact: Setting to True reduces production log verbosity by 99%+
# Trade-off: Less visibility into successful execution paths
FAILURE_ONLY_DEFAULT = True

# Maximum buffer depth for LogBuffer
# Prevents memory exhaustion from deep recursion or long-running call chains
# When exceeded, oldest entries are discarded (FIFO)
#
# Rationale: 1000 is sufficient for typical call stacks (most < 100)
# Deep recursion beyond this indicates a potential infinite recursion bug
MAX_BUFFER_DEPTH = 1000
