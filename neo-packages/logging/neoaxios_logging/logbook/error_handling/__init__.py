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
Error handling module for graceful degradation of logging failures.

This module provides comprehensive error handling to ensure that
logging failures never crash the application.
"""

from neoaxios_logging.logbook.error_handling.fallback import (
    FallbackOutputHandler,
    create_fallback_handler,
)

from neoaxios_logging.logbook.error_handling.recovery import (
    RecoveryManager,
    RetryConfig,
    ErrorCategory,
    get_recovery_manager,
)

from neoaxios_logging.logbook.error_handling.suppression import (
    ErrorSuppressor,
    suppress_logging_errors,
    suppress_and_log,
    suppress_logging_context,
    SafeLogger,
    make_logger_safe,
)

__all__ = [
    "FallbackOutputHandler",
    "create_fallback_handler",
    "RecoveryManager",
    "RetryConfig",
    "ErrorCategory",
    "get_recovery_manager",
    "ErrorSuppressor",
    "suppress_logging_errors",
    "suppress_and_log",
    "suppress_logging_context",
    "SafeLogger",
    "make_logger_safe",
]
