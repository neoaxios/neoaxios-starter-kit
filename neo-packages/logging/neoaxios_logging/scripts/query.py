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
Query FlightRecorder JSONL log files.

This module provides functionality to query and analyze FlightRecorder logs with
various filtering and formatting options.

Command-line usage:
    neoaxios-fr-query --level ERROR
    neoaxios-fr-query --trace-worker gw00
    neoaxios-fr-query --stats --group-by worker

Programmatic usage:
    from neoaxios_logging.scripts.query import query_events, find_failures

    # Find all errors
    errors = find_failures()

    # Query specific events
    events = query_events(test_name="test_foo", level="ERROR")

Usage:
    neoaxios-fr-query [OPTIONS]

Options:
    --test-name TEST_NAME    Filter by test name
    --level LEVEL           Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    --event PATTERN         Filter by event name pattern (glob-style, e.g., "pool_*")
    --worker NAME           Filter by worker name
    --field KEY=VALUE       Filter by field (e.g., --field exit_code=0)
    --since TIME            Show logs since (e.g., "1h", "30m", "2d")
    --tail N                Show only last N events
    --format FORMAT         Output format (json, text, csv, timeline)
    --stats                 Show aggregated statistics
    --group-by FIELD        Group statistics by field
    --show-context          Show context around errors
    --trace-worker NAME     Trace single worker lifecycle
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterator, Dict, Any, Optional, List
from collections import defaultdict, Counter
from fnmatch import fnmatch
import re


class FlightRecorderLogReader:
    """Simple JSONL log reader for FlightRecorder logs."""
    
    @staticmethod
    def read_jsonl(file_path: Path) -> Iterator[Dict[str, Any]]:
        """Read JSONL file line by line."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            # Skip malformed lines
                            continue
        except (IOError, OSError):
            # Skip files that can't be read
            pass
    
    @staticmethod
    def parse_time_delta(time_str: str) -> timedelta:
        """Parse time string like '1h', '30m', '2d' into timedelta."""
        match = re.match(r'^(\d+)([hdms])$', time_str)
        if not match:
            raise ValueError(f"Invalid time format: {time_str}")
        
        value, unit = match.groups()
        value = int(value)
        
        if unit == 's':
            return timedelta(seconds=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        else:
            raise ValueError(f"Unknown time unit: {unit}")
    
    @staticmethod
    def match_field_filter(event: Dict[str, Any], field_filter: str) -> bool:
        """
        Match event against field filter.

        Supports:
            key=value    Exact match
            key>value    Greater than (numeric)
            key<value    Less than (numeric)
            key>=value   Greater than or equal
            key<=value   Less than or equal
        """
        # Parse filter
        for op in ['>=', '<=', '>', '<', '=']:
            if op in field_filter:
                key, value = field_filter.split(op, 1)
                key = key.strip()
                value = value.strip()

                event_value = event.get(key)
                if event_value is None:
                    return False

                try:
                    if op == '=':
                        return str(event_value) == value
                    else:
                        # Numeric comparison
                        event_num = float(event_value)
                        filter_num = float(value)
                        if op == '>':
                            return event_num > filter_num
                        elif op == '<':
                            return event_num < filter_num
                        elif op == '>=':
                            return event_num >= filter_num
                        elif op == '<=':
                            return event_num <= filter_num
                except (ValueError, TypeError):
                    return False

        return False

    @classmethod
    def query_logs(cls,
                   log_dir: Path = None,
                   test_name: Optional[str] = None,
                   level: Optional[str] = None,
                   event_pattern: Optional[str] = None,
                   worker: Optional[str] = None,
                   field_filters: Optional[List[str]] = None,
                   since: Optional[str] = None,
                   tail: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Query logs with filters.

        Args:
            log_dir: Directory containing log files
            test_name: Filter by test name
            level: Filter by log level
            event_pattern: Filter by event name (glob pattern)
            worker: Filter by worker name
            field_filters: List of field filters (e.g., ["exit_code=0", "duration>1.0"])
            since: Show logs since this time ago
            tail: Only return last N events
        """
        if log_dir is None:
            log_dir = Path('.qrs/flight_recorder/sessions')

        # Calculate cutoff time if 'since' is specified
        cutoff_time = None
        if since:
            delta = cls.parse_time_delta(since)
            cutoff_time = datetime.now() - delta

        events = []

        # Read all matching log files
        for log_file in sorted(log_dir.glob("**/*.jsonl")):
            for event in cls.read_jsonl(log_file):
                # Apply filters
                if test_name and event.get('test_name') != test_name:
                    continue

                if level and event.get('flight_recorder_level') != level.upper():
                    continue

                if event_pattern and not fnmatch(event.get('event', ''), event_pattern):
                    continue

                if worker:
                    worker_match = (
                        event.get('worker') == worker or
                        event.get('worker_name') == worker
                    )
                    if not worker_match:
                        continue

                if field_filters:
                    if not all(cls.match_field_filter(event, f) for f in field_filters):
                        continue

                if cutoff_time:
                    try:
                        event_time = datetime.fromisoformat(
                            event.get('timestamp', '').replace('Z', '+00:00')
                        )
                        if event_time.replace(tzinfo=None) < cutoff_time:
                            continue
                    except (ValueError, TypeError):
                        continue

                if tail:
                    events.append(event)
                    if len(events) > tail:
                        events.pop(0)
                else:
                    yield event

        # If tail was specified, yield the last N events
        if tail:
            for event in events:
                yield event
    
    @staticmethod
    def format_event_text(event: Dict[str, Any]) -> str:
        """Format event as human-readable text."""
        timestamp = event.get('timestamp', 'unknown')
        level = event.get('flight_recorder_level', 'INFO')
        test_name = event.get('test_name', 'unknown')
        message = event.get('event', '')
        
        # Add any extra fields
        extras = []
        skip_fields = {'timestamp', 'flight_recorder_level', 'test_name', 'event', 
                      'test_id', 'start_time', 'elapsed_ms', 'thread_id', 'level'}
        for key, value in event.items():
            if key not in skip_fields:
                extras.append(f"{key}={value}")
        
        extra_str = f" [{', '.join(extras)}]" if extras else ""
        
        return f"{timestamp} [{level:8}] {test_name}: {message}{extra_str}"
    
    @staticmethod
    def format_event_csv(event: Dict[str, Any]) -> str:
        """Format event as CSV row."""
        import csv
        import io

        # Define standard field order
        fields = ['timestamp', 'flight_recorder_level', 'test_name', 'event']
        values = [str(event.get(f, '')) for f in fields]

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(values)
        return output.getvalue().strip()

    @staticmethod
    def format_event_timeline(event: Dict[str, Any], start_time: Optional[float] = None) -> str:
        """Format event for timeline view."""
        timestamp = event.get('timestamp', 'unknown')[:19]
        level = event.get('flight_recorder_level', 'INFO')
        event_name = event.get('event', '')
        worker = event.get('worker') or event.get('worker_name', '')

        # Calculate relative time if start provided
        if start_time and 'start_time' in event:
            relative_ms = (event['start_time'] - start_time) * 1000
            time_str = f"{relative_ms:7.0f}ms"
        else:
            time_str = timestamp

        # Format marker based on level
        marker = "🔴" if level == "ERROR" else "⚠️" if level == "WARNING" else "✓"

        # Build worker string
        worker_str = f" [{worker}]" if worker else ""

        # Add key details for common events
        details = []
        if 'error' in event:
            details.append(f"error={event['error']}")
        if 'duration' in event:
            details.append(f"duration={event['duration']:.2f}s")
        if 'elapsed_ms' in event:
            details.append(f"elapsed={event['elapsed_ms']:.0f}ms")

        detail_str = f" ({', '.join(details)})" if details else ""

        return f"  {marker} {time_str} {event_name:40}{worker_str}{detail_str}"

    @staticmethod
    def aggregate_stats(events: List[Dict[str, Any]], group_by: Optional[str] = None) -> Dict[str, Any]:
        """
        Aggregate event statistics.

        Args:
            events: List of events
            group_by: Optional field to group by

        Returns:
            Dictionary with aggregated stats
        """
        if not events:
            return {}

        stats = {
            'total_events': len(events),
            'event_types': Counter([e.get('event') for e in events]),
            'levels': Counter([e.get('flight_recorder_level', 'INFO') for e in events]),
        }

        if group_by:
            grouped = defaultdict(list)
            for event in events:
                key = event.get(group_by, 'unknown')
                grouped[key].append(event)

            stats['groups'] = {}
            for key, group_events in grouped.items():
                stats['groups'][key] = {
                    'count': len(group_events),
                    'event_types': Counter([e.get('event') for e in group_events]),
                    'errors': len([e for e in group_events if e.get('flight_recorder_level') == 'ERROR']),
                    'warnings': len([e for e in group_events if e.get('flight_recorder_level') == 'WARNING']),
                }

        # Calculate timing stats if duration fields present
        durations = [e.get('duration') for e in events if 'duration' in e]
        if durations:
            stats['timing'] = {
                'avg_duration': sum(durations) / len(durations),
                'min_duration': min(durations),
                'max_duration': max(durations),
            }

        return stats

    @staticmethod
    def format_stats(stats: Dict[str, Any]) -> str:
        """Format statistics for display."""
        lines = []
        lines.append("=" * 80)
        lines.append("FLIGHT RECORDER STATISTICS")
        lines.append("=" * 80)
        lines.append("")

        lines.append(f"Total Events: {stats.get('total_events', 0)}")
        lines.append("")

        # Event types
        if 'event_types' in stats:
            lines.append("Event Types:")
            for event_type, count in stats['event_types'].most_common():
                lines.append(f"  {event_type:40} {count:4} occurrences")
            lines.append("")

        # Levels
        if 'levels' in stats:
            lines.append("Event Levels:")
            for level, count in stats['levels'].most_common():
                lines.append(f"  {level:10} {count:4} events")
            lines.append("")

        # Groups
        if 'groups' in stats:
            lines.append("Grouped Statistics:")
            for group_key, group_stats in stats['groups'].items():
                lines.append(f"  {group_key}:")
                lines.append(f"    Total: {group_stats['count']} events")
                lines.append(f"    Errors: {group_stats['errors']}")
                lines.append(f"    Warnings: {group_stats['warnings']}")
                if group_stats['event_types']:
                    lines.append(f"    Top events: {', '.join([f'{k}({v})' for k, v in group_stats['event_types'].most_common(3)])}")
            lines.append("")

        # Timing
        if 'timing' in stats:
            lines.append("Timing Statistics:")
            lines.append(f"  Average: {stats['timing']['avg_duration']:.2f}s")
            lines.append(f"  Min: {stats['timing']['min_duration']:.2f}s")
            lines.append(f"  Max: {stats['timing']['max_duration']:.2f}s")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def trace_worker_lifecycle(events: List[Dict[str, Any]], worker_name: str) -> str:
        """
        Trace lifecycle of a specific worker.

        Args:
            events: All events
            worker_name: Worker to trace

        Returns:
            Formatted timeline of worker events
        """
        # Filter events for this worker
        worker_events = [
            e for e in events
            if e.get('worker') == worker_name or e.get('worker_name') == worker_name
        ]

        if not worker_events:
            return f"No events found for worker: {worker_name}"

        # Sort by timestamp
        worker_events.sort(key=lambda e: e.get('timestamp', ''))

        lines = []
        lines.append("=" * 80)
        lines.append(f"WORKER LIFECYCLE TRACE: {worker_name}")
        lines.append("=" * 80)
        lines.append("")

        # Get start time for relative timing
        start_time = worker_events[0].get('start_time') if worker_events else None

        for event in worker_events:
            lines.append(FlightRecorderLogReader.format_event_timeline(event, start_time))

        lines.append("")
        lines.append(f"Total events: {len(worker_events)}")

        return "\n".join(lines)


def main():
    """
    Main entry point for the neoaxios-fr-query CLI command.

    This function is registered as a console script entry point in setup.py.
    """
    parser = argparse.ArgumentParser(
        prog='neoaxios-fr-query',
        description='Query FlightRecorder logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show all ERROR events
  neoaxios-fr-query --level ERROR

  # Filter by event pattern
  neoaxios-fr-query --event "pool_connection_*"

  # Trace specific worker
  neoaxios-fr-query --trace-worker gw00

  # Show stats grouped by worker
  neoaxios-fr-query --stats --group-by worker

  # Find slow operations
  neoaxios-fr-query --event "*_complete" --field "duration>1.0"

  # Timeline view with relative timing
  neoaxios-fr-query --format timeline --event "pool_*"
        """
    )

    # Filtering options
    parser.add_argument('--test-name', help='Filter by test name')
    parser.add_argument('--level', help='Filter by log level (ERROR, WARNING, INFO)')
    parser.add_argument('--event', dest='event_pattern', help='Filter by event pattern (glob, e.g., "pool_*")')
    parser.add_argument('--worker', help='Filter by worker name')
    parser.add_argument('--field', dest='field_filters', action='append',
                       help='Filter by field (e.g., --field exit_code=0, --field duration>1.0)')
    parser.add_argument('--since', help='Show logs since (e.g., "1h", "30m")')
    parser.add_argument('--tail', type=int, help='Show only last N events')

    # Output options
    parser.add_argument('--format', choices=['json', 'text', 'csv', 'timeline'],
                       default='text', help='Output format')
    parser.add_argument('--stats', action='store_true',
                       help='Show aggregated statistics')
    parser.add_argument('--group-by', dest='group_by',
                       help='Group statistics by field (e.g., worker, event)')
    parser.add_argument('--trace-worker', dest='trace_worker',
                       help='Trace lifecycle of specific worker')

    # Data source
    parser.add_argument('--log-dir', type=Path,
                       default=Path('.qrs/flight_recorder/sessions'),
                       help='Log directory (default: .qrs/flight_recorder/sessions)')

    args = parser.parse_args()

    reader = FlightRecorderLogReader()

    try:
        # Collect all events for analysis
        events = list(reader.query_logs(
            log_dir=args.log_dir,
            test_name=args.test_name,
            level=args.level,
            event_pattern=args.event_pattern,
            worker=args.worker,
            field_filters=args.field_filters,
            since=args.since,
            tail=args.tail
        ))

        # Worker trace mode
        if args.trace_worker:
            print(reader.trace_worker_lifecycle(events, args.trace_worker))
            return

        # Stats mode
        if args.stats:
            stats = reader.aggregate_stats(events, group_by=args.group_by)
            print(reader.format_stats(stats))
            return

        # Output events in requested format
        if not events:
            print("No events found matching filters", file=sys.stderr)
            return

        # Print CSV header if needed
        if args.format == 'csv':
            print("timestamp,level,test_name,message")

        # Get start time for timeline format
        start_time = events[0].get('start_time') if events and args.format == 'timeline' else None

        for event in events:
            if args.format == 'json':
                print(json.dumps(event))
            elif args.format == 'text':
                print(reader.format_event_text(event))
            elif args.format == 'csv':
                print(reader.format_event_csv(event))
            elif args.format == 'timeline':
                print(reader.format_event_timeline(event, start_time))

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def query_events(test_name: Optional[str] = None,
                 level: Optional[str] = None,
                 event: Optional[str] = None,
                 since: Optional[str] = None,
                 tail: Optional[int] = None,
                 log_dir: Optional[Path] = None) -> list[Dict[str, Any]]:
    """
    Query FlightRecorder events (convenience wrapper).

    Args:
        test_name: Filter by test name
        level: Filter by log level (ERROR, WARNING, INFO)
        event: Filter by event type
        since: Show logs since time ago (e.g., "1h", "30m")
        tail: Return only last N events
        log_dir: Directory containing log files (default: .qrs/flight_recorder/sessions)

    Returns:
        List of matching events
    """
    reader = FlightRecorderLogReader()
    events = list(reader.query_logs(
        log_dir=log_dir,
        test_name=test_name,
        level=level,
        since=since,
        tail=tail
    ))

    # Filter by event type if specified
    if event:
        events = [e for e in events if e.get('event') == event]

    return events


def get_test_timeline(test_name: str, log_dir: Optional[Path] = None) -> list[Dict[str, Any]]:
    """
    Get complete timeline for a test.

    Args:
        test_name: Test name to query
        log_dir: Optional log directory

    Returns:
        List of all events for the test, sorted by timestamp
    """
    return query_events(test_name=test_name, log_dir=log_dir)


def find_failures(test_name: Optional[str] = None,
                  log_dir: Optional[Path] = None) -> list[Dict[str, Any]]:
    """
    Find all error/failure events.

    Args:
        test_name: Optional test name filter
        log_dir: Optional log directory

    Returns:
        List of error events
    """
    return query_events(test_name=test_name, level="ERROR", log_dir=log_dir)


if __name__ == '__main__':
    main()