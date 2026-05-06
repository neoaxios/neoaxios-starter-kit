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

"""Shared CLI display helpers for build-tools validation scripts.

All user-facing terminal output in CLI scripts routes through this module
instead of raw ``print()`` calls. This provides a single formatting surface
for consistency and future extension (e.g., --quiet / --verbose modes).

Design
------
Functions in this module write to ``sys.stdout`` (default) or ``sys.stderr``
(error/warn). The ``--format json`` path in validate_contracts.py bypasses
these helpers intentionally — that path produces machine-parseable output and
must not have formatting applied. That bypass is documented at each call site.

Public API
----------
``info(msg)``:       Informational line to stdout.
``warn(msg)``:       Warning line to stdout.
``error(msg)``:      Error line to stderr.
``success(msg)``:    Success/pass line to stdout.
``rule(char, width)``: Horizontal rule (repeated character) to stdout.
``blank()``:         Blank line to stdout.
``report_header(title, width)``: Section header with top/bottom rules.
``report_row(msg)``: Single indented row inside a section body.
``report_divider(char, width)``: Mid-section divider rule.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Repo root inference — this file lives at
# neo-packages/neoaxios-build/scripts/_display.py; three parents up is the
# repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "neo-packages" / "neoaxios-build" / "src"))

from neoaxios_logging import auto_trace, get_telemetry  # noqa: E402

logger = get_telemetry(__name__)

# Default rule width for report_header / rule helpers.
_DEFAULT_WIDTH: int = 72


@auto_trace(logger)
def info(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    """Write an informational line to stdout.

    Args:
        msg:   Text to write.
        end:   Line terminator (default ``\\n``).
        flush: If True, flush stdout after writing.
    """
    print(msg, end=end, flush=flush)


@auto_trace(logger)
def warn(msg: str) -> None:
    """Write a warning line to stdout.

    Args:
        msg: Warning text to write.
    """
    print(f"WARNING: {msg}")


@auto_trace(logger)
def error(msg: str) -> None:
    """Write an error line to stderr.

    Args:
        msg: Error text to write.
    """
    print(f"ERROR: {msg}", file=sys.stderr)


@auto_trace(logger)
def success(msg: str) -> None:
    """Write a success/pass line to stdout.

    Args:
        msg: Success text to write.
    """
    print(msg)


@auto_trace(logger)
def blank() -> None:
    """Write a blank line to stdout."""
    print()


@auto_trace(logger)
def rule(char: str = "=", width: int = _DEFAULT_WIDTH) -> None:
    """Write a horizontal rule to stdout.

    Args:
        char:  Character to repeat (default ``=``).
        width: Total width of the rule (default 72).
    """
    print(char * width)


@auto_trace(logger)
def report_header(title: str, width: int = _DEFAULT_WIDTH) -> None:
    """Write a section header with top and bottom rules to stdout.

    Args:
        title: Header text.
        width: Total width of the surrounding rules (default 72).
    """
    print("=" * width)
    print(title)
    print("=" * width)


@auto_trace(logger)
def report_row(msg: str) -> None:
    """Write a single display row to stdout (used inside report sections).

    Args:
        msg: Row text; written verbatim with no additional indentation so
             callers retain control of alignment.
    """
    print(msg)


@auto_trace(logger)
def report_divider(char: str = "-", width: int = _DEFAULT_WIDTH) -> None:
    """Write a mid-section divider rule to stdout.

    Args:
        char:  Character to repeat (default ``-``).
        width: Total width of the divider (default 72).
    """
    print(char * width)
