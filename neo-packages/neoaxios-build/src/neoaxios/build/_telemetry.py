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

"""Optional telemetry binding for the neoaxios-build system.

neoaxios-build's core function is producing wheels and Docker images.
Telemetry (provided by the `telemetry` top-level package in neoaxios-logging)
gives richer observability — structured logging, traces, flight recording —
but is not required for builds to run.

Consumers inside neoaxios-build import `get_telemetry` and `auto_trace`
from this module. When neoaxios-logging is installed, both resolve to the
real implementations. When it is not (e.g., running neoaxios-build in a
minimal environment), they resolve to explicit no-op implementations that
silently drop observability calls.

HAVE_TELEMETRY is exported for code that needs to branch on availability
(e.g., to skip an expensive trace-rich code path entirely). No silent
environment probing — the branching is at import time, once, deterministically.
"""

from __future__ import annotations

from typing import Any, Callable

try:
    from neoaxios_logging import get_telemetry as _real_get_telemetry
    from neoaxios_logging.logbook import auto_trace as _real_auto_trace

    HAVE_TELEMETRY = True
except ImportError:
    HAVE_TELEMETRY = False


if HAVE_TELEMETRY:
    get_telemetry = _real_get_telemetry
    auto_trace = _real_auto_trace
else:
    class _NullLogger:
        """No-op logger surface.

        Accepts any attribute access and returns a callable that drops its
        arguments. Matches the real `telemetry.get_telemetry(...)` return
        type closely enough that consumers need no conditional code.
        """

        def __getattr__(self, _name: str) -> Callable[..., None]:
            return _drop

    def _drop(*_args: Any, **_kwargs: Any) -> None:
        return None

    _null_logger = _NullLogger()

    def get_telemetry(_name: str) -> _NullLogger:
        return _null_logger

    def auto_trace(*args: Any, **kwargs: Any) -> Any:
        """No-op trace decorator.

        Supports both `@auto_trace` (called with the decorated function) and
        `@auto_trace(...)` (called with configuration kwargs, returns a
        decorator). Passes the function through unchanged in both forms.
        """
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return args[0]

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


__all__ = ["HAVE_TELEMETRY", "get_telemetry", "auto_trace"]
