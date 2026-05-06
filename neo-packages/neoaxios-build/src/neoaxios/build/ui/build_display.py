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

"""Display abstraction for build system output.

Terminal output flows through dedicated display abstraction modules,
not direct print statements.
"""

import sys
from typing import List, Optional

from neoaxios.build._telemetry import auto_trace, get_telemetry
from neoaxios.build.docker.models import DockerBuildResult

logger = get_telemetry(__name__)


def _visual_width(s: str) -> int:
    """Calculate visual width of string accounting for wide Unicode characters."""
    width = 0
    i = 0
    while i < len(s):
        code = ord(s[i])
        # Variation selectors (U+FE00-U+FE0F) are zero-width
        if 0xFE00 <= code <= 0xFE0F:
            i += 1
            continue
        # Check if followed by variation selector 16 (emoji presentation)
        next_is_emoji_vs = i + 1 < len(s) and ord(s[i + 1]) == 0xFE0F
        # Emoji range OR char with emoji variation selector = double-width
        if code >= 0x1F300 or next_is_emoji_vs:
            width += 2
        else:
            width += 1
        i += 1
    return width


def _pad_to_width(s: str, width: int) -> str:
    """Pad string to achieve target visual width."""
    current = _visual_width(s)
    if current < width:
        return s + " " * (width - current)
    return s[:width] if current > width else s


class BuildDisplay:
    """Display abstraction for build system terminal output.

    All user-facing output flows through this class to maintain separation
    between business logic and presentation layer.
    """

    @staticmethod
    @auto_trace(logger)
    def header(text: str, width: int = 60) -> None:
        """Display header with border.

        Args:
            text: Header text to display
            width: Total width of header border
        """
        print("=" * width)
        print(f"  {text}")
        print("=" * width)
        print("")

    @staticmethod
    @auto_trace(logger)
    def info(message: str) -> None:
        """Display informational message.

        Args:
            message: Message to display
        """
        print(message)

    @staticmethod
    @auto_trace(logger)
    def error(message: str) -> None:
        """Display error message to stderr.

        Args:
            message: Error message to display
        """
        print(f"Error: {message}", file=sys.stderr)

    @staticmethod
    @auto_trace(logger)
    def list_items(items: List[str], prefix: str = "  • ") -> None:
        """Display list of items with prefix.

        Args:
            items: List of items to display
            prefix: Prefix for each item
        """
        for item in items:
            print(f"{prefix}{item}")

    @staticmethod
    @auto_trace(logger)
    def section(title: str) -> None:
        """Display section title.

        Args:
            title: Section title to display
        """
        print(title)

    @staticmethod
    @auto_trace(logger)
    def newline() -> None:
        """Display blank line."""
        print("")

    @staticmethod
    @auto_trace(logger)
    def docker_summary_table(results: List[DockerBuildResult], output_dir) -> None:
        """Display Docker build results summary table.

        Args:
            results: List of Docker build results
            output_dir: Path to output directory for archives
        """
        print("")
        print("Docker Images")
        print("┌" + "─" * 42 + "┬" + "─" * 8 + "┬" + "─" * 7 + "┬" + "─" * 10 + "┬" + "─" * 7 + "┬" + "─" * 27 + "┐")
        print("│ {:40} │ {:6} │ {:5} │ {:8} │ {:5} │ {:25} │".format(
            "Image built", "Status", "Time", "Size", "Hash", "Archive"
        ))
        print("├" + "─" * 42 + "┼" + "─" * 8 + "┼" + "─" * 7 + "┼" + "─" * 10 + "┼" + "─" * 7 + "┼" + "─" * 27 + "┤")

        for result in results:
            # Status: cached, built, or failed (use visual-width padding for emojis)
            if not result.success:
                status = _pad_to_width("✗ fail", 6)
            elif result.cached:
                status = _pad_to_width("♻️ hit", 6)
            else:
                status = _pad_to_width("🔨 new", 6)

            time_str = f"{result.duration:.1f}s"
            name = result.image.full_name[:40]

            # Size: image size in MB
            if result.output_path and result.output_path.exists():
                size_mb = result.output_path.stat().st_size / (1024 * 1024)
                size_str = f"{size_mb:.1f}MB"
                archive_str = f"{result.output_path.name}"
            else:
                size_str = "-"
                archive_str = "-"

            # Hash: last 5 digits of image ID
            if result.image_id:
                # Image ID format: sha256:abcdef... - extract last 5 chars
                hash_str = result.image_id[-5:]
            else:
                hash_str = "-"

            # Use pre-padded status (visual width), standard format for rest
            print(f"│ {name:40} │ {status} │ {time_str:5} │ {size_str:8} │ {hash_str:5} │ {archive_str:25} │")

        print("└" + "─" * 42 + "┴" + "─" * 8 + "┴" + "─" * 7 + "┴" + "─" * 10 + "┴" + "─" * 7 + "┴" + "─" * 27 + "┘")

        # Compact summary
        succeeded = sum(1 for r in results if r.success)
        cached = sum(1 for r in results if r.cached)
        failed = sum(1 for r in results if not r.success)

        print(f"  Built: {succeeded - cached}  Cached: {cached}  Failed: {failed}  │  {output_dir}")

    @staticmethod
    @auto_trace(logger)
    def docker_pull_summary_table(results, output_dir) -> None:
        """Display 3rd-party Docker-image pull results as a summary table.

        Identical layout / column widths to :meth:`docker_summary_table`
        so 1st-party-build and 3rd-party-pull output read the same — the
        only visible difference is the header label ("Image pulled" vs
        "Image built") and a ``🔨 new`` cell in the pull table means
        "just pulled+archived" rather than "just built from Dockerfile".

        Args:
            results: List of ``ThirdPartyPullResult`` (from
                ``thirdparty_puller.pull_all_thirdparty``).
            output_dir: Path to the directory where archives landed
                (typically ``<repo>/docker-images``).
        """
        if not results:
            return
        print("")
        print("Third-Party Docker Images")
        print("┌" + "─" * 42 + "┬" + "─" * 8 + "┬" + "─" * 7 + "┬" + "─" * 10 + "┬" + "─" * 7 + "┬" + "─" * 27 + "┐")
        print("│ {:40} │ {:6} │ {:5} │ {:8} │ {:5} │ {:25} │".format(
            "Image pulled", "Status", "Time", "Size", "Hash", "Archive"
        ))
        print("├" + "─" * 42 + "┼" + "─" * 8 + "┼" + "─" * 7 + "┼" + "─" * 10 + "┼" + "─" * 7 + "┼" + "─" * 27 + "┤")

        for r in results:
            if not r.success:
                status = _pad_to_width("✗ fail", 6)
            elif r.cached:
                status = _pad_to_width("♻️ hit", 6)
            else:
                status = _pad_to_width("🔨 new", 6)

            time_str = f"{r.duration:.1f}s" if r.duration else "-"
            name = r.image_ref[:40]

            if r.archive_path and r.archive_path.exists():
                size_mb = r.archive_path.stat().st_size / (1024 * 1024)
                size_str = f"{size_mb:.1f}MB"
                archive_str = r.archive_path.name
            else:
                size_str = "-"
                archive_str = "-"

            # Last 5 chars of the archive content sha256 (analogous to
            # docker_summary_table's last-5-of-image-id convention).
            hash_str = (r.content_sha or "")[-5:] or "-"

            print(f"│ {name:40} │ {status} │ {time_str:5} │ {size_str:8} │ {hash_str:5} │ {archive_str:25} │")

        print("└" + "─" * 42 + "┴" + "─" * 8 + "┴" + "─" * 7 + "┴" + "─" * 10 + "┴" + "─" * 7 + "┴" + "─" * 27 + "┘")

        pulled = sum(1 for r in results if r.success and not r.cached)
        cached = sum(1 for r in results if r.cached)
        failed = sum(1 for r in results if not r.success)
        print(f"  Pulled: {pulled}  Cached: {cached}  Failed: {failed}  │  {output_dir}")

    @staticmethod
    @auto_trace(logger)
    def docker_failures(results: List[DockerBuildResult]) -> None:
        """Display Docker build failures.

        Args:
            results: List of Docker build results
        """
        failed_results = [r for r in results if not r.success]
        if failed_results:
            print("\nFailed images:")
            for r in failed_results:
                print(f"  ✗ {r.image.full_name}: {r.error_message}")
                if r.log_path:
                    print(f"    Log: {r.log_path}")
            print("\n  Full build logs: logs/build/")

    @staticmethod
    @auto_trace(logger)
    def file_written(description: str, file_path, relative_to=None) -> None:
        """Display file write confirmation.

        Args:
            description: Description of what was written
            file_path: Path to file that was written
            relative_to: Optional base path to make file_path relative
        """
        if relative_to:
            display_path = file_path.relative_to(relative_to)
        else:
            display_path = file_path
        print(f"\n  {description}: {display_path}")
