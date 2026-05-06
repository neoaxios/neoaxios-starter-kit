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
Failure-Only Logging Examples
==============================

This file demonstrates the three ways to configure failure-only logging:
1. Decorator level (highest precedence)
2. File level
3. Project level (via .logbook.conf or environment variable)

Run these examples to see how different configurations affect logging behavior.
"""

# Example 1: Decorator-level configuration (highest precedence)
# ===============================================================
# Override file/project settings with explicit decorator parameter

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger, log_on_failure_only=True)
def example_decorator_enabled(order_id: int):
    """
    This function has failure-only mode ENABLED at decorator level.
    - Successful calls: No ENTRY/EXIT logs written
    - Failed calls: ENTRY + EXIT (rc=1) written
    """
    if order_id < 0:
        raise ValueError("Order ID must be positive")
    return {"order_id": order_id, "status": "processed"}


@auto_trace(logger, log_on_failure_only=False)
def example_decorator_disabled(order_id: int):
    """
    This function has failure-only mode DISABLED at decorator level.
    - All calls: ENTRY + EXIT logs written regardless of outcome
    """
    if order_id < 0:
        raise ValueError("Order ID must be positive")
    return {"order_id": order_id, "status": "processed"}


@auto_trace(logger)
def example_decorator_default(order_id: int):
    """
    This function uses DEFAULT configuration (no decorator override).
    - Falls through to file-level → project-level → default (False)
    """
    if order_id < 0:
        raise ValueError("Order ID must be positive")
    return {"order_id": order_id, "status": "processed"}


# Example 2: File-level configuration
# ====================================
# To enable failure-only mode for ALL functions in this file,
# add this special comment in the first 10 lines:
#
#   # logbook: log_on_failure_only=true
#
# All @auto_trace decorators without explicit log_on_failure_only parameter
# will inherit the file-level setting.


# Example 3: Project-level configuration
# =======================================
# Create .logbook.conf in package root (e.g., <project-root>/.logbook.conf):
#
#   failure_only = true
#
# Or set environment variable:
#
#   export LOGBOOK_FAILURE_ONLY=true
#
# This applies to all functions in the entire package unless overridden
# by file-level or decorator-level configuration.


# Example 4: Testing the configuration hierarchy
# ===============================================

def test_failure_only_hierarchy():
    """
    Test the configuration hierarchy by running functions with different outcomes.

    Expected behavior (when project/file config is False):
    - example_decorator_enabled: Only logs on failure
    - example_decorator_disabled: Always logs
    - example_decorator_default: Always logs (inherits False from project)
    """

    print("\n" + "="*70)
    print("TESTING FAILURE-ONLY LOGGING HIERARCHY")
    print("="*70)

    # Test 1: Decorator-level enabled (success - no logs)
    print("\n1. Decorator enabled + SUCCESS:")
    print("   Expected: No ENTRY/EXIT logs")
    try:
        result = example_decorator_enabled(123)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 2: Decorator-level enabled (failure - logs)
    print("\n2. Decorator enabled + FAILURE:")
    print("   Expected: ENTRY + EXIT (rc=1) logs")
    try:
        result = example_decorator_enabled(-1)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 3: Decorator-level disabled (success - logs)
    print("\n3. Decorator disabled + SUCCESS:")
    print("   Expected: ENTRY + EXIT (rc=0) logs")
    try:
        result = example_decorator_disabled(456)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 4: Decorator-level disabled (failure - logs)
    print("\n4. Decorator disabled + FAILURE:")
    print("   Expected: ENTRY + EXIT (rc=1) logs")
    try:
        result = example_decorator_disabled(-2)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 5: Default configuration (success)
    print("\n5. Default config + SUCCESS:")
    print("   Expected: ENTRY + EXIT (rc=0) logs (project default is False)")
    try:
        result = example_decorator_default(789)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n" + "="*70)
    print("Check telemetry logs to verify behavior")
    print("="*70 + "\n")


# Example 5: Production vs Development configuration
# ===================================================

def production_example():
    """
    In production, enable failure-only mode to reduce log volume:

    1. Set in .logbook.conf:
       failure_only = true

    2. Or use environment variable:
       export LOGBOOK_FAILURE_ONLY=true

    3. For specific high-value operations, override at decorator level:
       @auto_trace(logger, log_on_failure_only=False)
       def critical_payment_processing(...):
           # Always log this critical path
           ...
    """
    pass


def development_example():
    """
    In development, keep failure-only mode disabled for full visibility:

    1. Set in .logbook.conf:
       failure_only = false

    2. For specific noisy functions, enable at decorator level:
       @auto_trace(logger, log_on_failure_only=True)
       def chatty_helper_function(...):
           # Only log failures for this noisy function
           ...
    """
    pass


if __name__ == "__main__":
    # Run the hierarchy test
    test_failure_only_hierarchy()

    print("\nTo modify configuration:")
    print("1. Decorator: @auto_trace(logger, log_on_failure_only=True/False)")
    print("2. File: Add '# logbook: log_on_failure_only=true' in first 10 lines")
    print("3. Project: Create .logbook.conf or set LOGBOOK_FAILURE_ONLY env var")
