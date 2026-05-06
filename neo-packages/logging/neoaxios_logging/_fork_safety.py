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
Fork-safety utilities for telemetry.

Ensures child processes reinitialize telemetry state after fork
to avoid inherited locks, timers, and file descriptors.

Note: Functions in this module are exempt from @auto_trace because this
is low-level telemetry bootstrap infrastructure. Instrumenting these
functions would create circular dependencies during telemetry initialization.
"""

from __future__ import annotations

import os
import threading
import weakref
from typing import Callable, List, Tuple

# Note: This module cannot use telemetry logging - it's imported during
# telemetry initialization, creating a circular import. Functions are
# exempt from @auto_trace (bootstrap infrastructure).

_fork_unsafe_instances: "weakref.WeakSet[object]" = weakref.WeakSet()
_class_locks: List[Tuple[type, str]] = []
_reset_callbacks: List[Callable[[], None]] = []


def register_fork_unsafe(instance: object) -> object:
    """Register an instance that must be reset after fork."""
    _fork_unsafe_instances.add(instance)
    return instance


def register_class_lock(cls: type, attr: str) -> None:
    """Register a class-level lock attribute to be replaced after fork."""
    _class_locks.append((cls, attr))


def register_reset_callback(callback: Callable[[], None]) -> None:
    """Register a callback to reset singleton state in forked children."""
    _reset_callbacks.append(callback)


def _is_rlock(lock: object) -> bool:
    return type(lock).__name__ == "RLock"


def _new_lock_from(lock: object) -> threading.Lock:
    if _is_rlock(lock):
        return threading.RLock()
    return threading.Lock()


def _after_fork_child() -> None:
    for cls, attr in _class_locks:
        try:
            current = getattr(cls, attr, None)
            if current is None:
                continue
            setattr(cls, attr, _new_lock_from(current))
        except Exception:
            continue

    for callback in _reset_callbacks:
        try:
            callback()
        except Exception:
            continue

    for instance in list(_fork_unsafe_instances):
        reset = getattr(instance, "_reset_after_fork", None)
        if callable(reset):
            try:
                reset()
            except Exception:
                continue


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)
