#!/usr/bin/env python3
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
Clean up old FlightRecorder log files.

This module provides functionality to clean up old FlightRecorder logs by either
deleting or compressing them based on age.

Command-line usage:
    neoaxios-fr-cleanup --older-than 30
    neoaxios-fr-cleanup --older-than 7 --compress --dry-run

Programmatic usage:
    from neoaxios_logging.scripts.cleanup import cleanup_old_logs

    cleanup_old_logs(
        log_dir=Path('.qrs/flight_recorder/sessions'),
        retention_days=30,
        dry_run=False,
        compress=False
    )
"""

import argparse
import gzip
import shutil
import sys
from pathlib import Path
from datetime import datetime, timedelta


def compress_file(file_path: Path) -> Path:
    """
    Compress a file using gzip.

    Args:
        file_path: Path to file to compress

    Returns:
        Path to compressed file

    Raises:
        OSError: If compression fails
    """
    compressed_path = file_path.with_suffix(file_path.suffix + '.gz')

    with open(file_path, 'rb') as f_in:
        with gzip.open(compressed_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Remove original file after successful compression
    file_path.unlink()
    return compressed_path


def cleanup_old_logs(log_dir: Path,
                     retention_days: int,
                     dry_run: bool = False,
                     compress: bool = False) -> int:
    """
    Remove or compress logs older than retention period.

    Args:
        log_dir: Directory containing log files
        retention_days: Number of days to retain logs
        dry_run: If True, only show what would be done
        compress: If True, compress old logs instead of deleting

    Returns:
        Number of files processed

    Examples:
        >>> from pathlib import Path
        >>> cleanup_old_logs(Path('.qrs/flight_recorder/sessions'), 30, dry_run=True)
        Dry run: Would have removed 5 file(s) totaling 1,234,567 bytes
        5

        >>> cleanup_old_logs(Path('.qrs/flight_recorder/sessions'), 7, compress=True)
        Compressed: .qrs/flight_recorder/sessions/2024-01-01/session.jsonl -> ...
        Compressed 10 file(s) totaling 5,678,901 bytes
        10
    """
    if not log_dir.exists():
        print(f"Log directory does not exist: {log_dir}")
        return 0

    cutoff_date = datetime.now() - timedelta(days=retention_days)
    processed_count = 0
    total_size = 0

    # Find all log files (including already compressed ones)
    patterns = ["**/*.jsonl", "**/*.jsonl.gz"] if not compress else ["**/*.jsonl"]

    for pattern in patterns:
        for log_file in log_dir.glob(pattern):
            try:
                # Get file modification time
                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)

                if mtime < cutoff_date:
                    file_size = log_file.stat().st_size
                    total_size += file_size

                    if dry_run:
                        action = "Would compress" if compress else "Would remove"
                        print(f"{action}: {log_file} "
                              f"(modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')}, "
                              f"size: {file_size:,} bytes)")
                    else:
                        if compress and log_file.suffix == '.jsonl':
                            # Compress the file
                            compressed_path = compress_file(log_file)
                            print(f"Compressed: {log_file} -> {compressed_path}")
                        else:
                            # Delete the file
                            log_file.unlink()
                            print(f"Removed: {log_file}")

                    processed_count += 1

            except Exception as e:
                print(f"Error processing {log_file}: {e}", file=sys.stderr)

    # Clean up empty directories
    if not dry_run and processed_count > 0:
        for dirpath in sorted(log_dir.rglob("*"), reverse=True):
            if dirpath.is_dir():
                try:
                    # Remove directory if empty
                    dirpath.rmdir()
                    print(f"Removed empty directory: {dirpath}")
                except OSError:
                    # Directory not empty, skip
                    pass

    # Print summary
    if processed_count > 0:
        action = "compressed" if compress else "removed"
        if dry_run:
            print(f"\nDry run: Would have {action} {processed_count} file(s) "
                  f"totaling {total_size:,} bytes")
        else:
            print(f"\n{action.capitalize()} {processed_count} file(s) "
                  f"totaling {total_size:,} bytes")
    else:
        print(f"No log files older than {retention_days} days found")

    return processed_count


def main():
    """
    Main entry point for the neoaxios-fr-cleanup CLI command.

    This function is registered as a console script entry point in setup.py.
    """
    parser = argparse.ArgumentParser(
        prog='neoaxios-fr-cleanup',
        description='Clean up old FlightRecorder logs',
        epilog='Example: neoaxios-fr-cleanup --older-than 30 --dry-run'
    )
    parser.add_argument(
        '--older-than',
        type=int,
        default=30,
        metavar='DAYS',
        help='Remove logs older than N days (default: 30)'
    )
    parser.add_argument(
        '--log-dir',
        type=Path,
        default=Path('.qrs/flight_recorder/sessions'),
        metavar='PATH',
        help='Log directory (default: .qrs/flight_recorder/sessions)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be deleted without deleting'
    )
    parser.add_argument(
        '--compress',
        action='store_true',
        help='Compress old logs instead of deleting'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s (neoaxios-logging 1.0.0)'
    )

    args = parser.parse_args()

    if args.older_than <= 0:
        print("Error: --older-than must be a positive number", file=sys.stderr)
        sys.exit(1)

    print(f"Cleaning up FlightRecorder logs in: {args.log_dir}")
    print(f"Looking for files older than {args.older_than} days")
    if args.dry_run:
        print("DRY RUN MODE - No files will be modified")
    print()

    try:
        processed = cleanup_old_logs(
            log_dir=args.log_dir,
            retention_days=args.older_than,
            dry_run=args.dry_run,
            compress=args.compress
        )

        sys.exit(0 if processed >= 0 else 1)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
