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

# logbook: log_on_failure_only=true
"""
File-Level Configuration Example
=================================

This file demonstrates file-level failure-only configuration.

The special comment above (# logbook: log_on_failure_only=true) enables
failure-only logging for ALL functions in this file that use @auto_trace
without an explicit log_on_failure_only parameter.

This directive MUST appear in the first 10 lines of the file.
"""

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger)
def file_level_enabled_function_1(x: int):
    """
    This function inherits file-level config: log_on_failure_only=true
    - Success: No logs
    - Failure: ENTRY + EXIT (rc=1) logs
    """
    if x < 0:
        raise ValueError("x must be positive")
    return x * 2


@auto_trace(logger)
def file_level_enabled_function_2(y: int):
    """
    This function also inherits file-level config: log_on_failure_only=true
    - Success: No logs
    - Failure: ENTRY + EXIT (rc=1) logs
    """
    if y == 0:
        raise ZeroDivisionError("y cannot be zero")
    return 100 / y


@auto_trace(logger, log_on_failure_only=False)
def decorator_override_function(z: int):
    """
    This function OVERRIDES file-level config at decorator level.
    Even though file says log_on_failure_only=true, this function
    has log_on_failure_only=False.

    - Success: ENTRY + EXIT (rc=0) logs
    - Failure: ENTRY + EXIT (rc=1) logs
    """
    return z + 10


if __name__ == "__main__":
    print("\n" + "="*70)
    print("FILE-LEVEL CONFIGURATION EXAMPLE")
    print("="*70)
    print("\nThis file has: # logbook: log_on_failure_only=true")
    print("Expected behavior:\n")

    # Test 1: File-level config (success - no logs)
    print("1. file_level_enabled_function_1(5) - SUCCESS")
    print("   Expected: No logs")
    result = file_level_enabled_function_1(5)
    print(f"   Result: {result}\n")

    # Test 2: File-level config (failure - logs)
    print("2. file_level_enabled_function_1(-3) - FAILURE")
    print("   Expected: ENTRY + EXIT (rc=1) logs")
    try:
        result = file_level_enabled_function_1(-3)
    except ValueError as e:
        print(f"   Error: {e}\n")

    # Test 3: File-level config (success - no logs)
    print("3. file_level_enabled_function_2(10) - SUCCESS")
    print("   Expected: No logs")
    result = file_level_enabled_function_2(10)
    print(f"   Result: {result}\n")

    # Test 4: Decorator override (success - logs)
    print("4. decorator_override_function(7) - SUCCESS")
    print("   Expected: ENTRY + EXIT (rc=0) logs (decorator overrides file)")
    result = decorator_override_function(7)
    print(f"   Result: {result}\n")

    print("="*70)
    print("Check telemetry logs to verify behavior")
    print("="*70 + "\n")
