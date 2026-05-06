#!/bin/bash
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
# Shared Entrypoint Library for NeoAxios Containers
#
# Provides common functions for container initialization:
# - Container ID detection (cgroup v1/v2, mountinfo, hostname)
# - Logbook telemetry directory setup (TELEMETRY_DIR)
# - Multi-process log directory initialization
# - System resource detection (CPU, RAM, worker count)
#
# Usage:
#   source /usr/local/lib/entrypoint-lib.sh
#   init_logbook_dir "my-service"
#   init_system_resources  # Optional: detect resources at boot
#   exec "$@"
#
# Environment Variables (inputs):
#   CONTAINER_LOG_DIR: Base log directory (default: /var/log/neo)
#   CONTAINER_ID: Override container ID detection (optional)
#   SERVICE_TYPE: Service type - "native" or "3rdparty" (default: native)
#   NEO_SYSTEM_*_OVERRIDE: Override detected system resources (optional)
#
# Environment Variables (outputs):
#   TELEMETRY_DIR: Set to the Logbook output directory
#   CONTAINER_ID: Set to detected/provided container ID
#   NEO_SYSTEM_CPU_LOGICAL_COUNT: Detected logical CPUs
#   NEO_SYSTEM_RAM_AVAILABLE_GB: Detected available RAM
#   NEO_APP_RECOMMENDED_WORKERS: Calculated worker count

set -e

# Default configuration
: "${CONTAINER_LOG_DIR:=/var/log/neo}"
: "${SERVICE_TYPE:=native}"

# ============================================================================
# detect_container_id - Detect the container ID using multiple methods
# ============================================================================
# Tries in order:
#   1. CONTAINER_ID env var (if already set by orchestrator)
#   2. Docker container ID from /proc/self/mountinfo (cgroup v2)
#   3. Docker container ID from /proc/self/cgroup (cgroup v1)
#   4. Hostname (works when not in host network mode)
#   5. Fallback to "unknown"
#
# Returns: 12-character container ID (or hostname/unknown)
# ============================================================================
detect_container_id() {
    # Return existing CONTAINER_ID if set
    if [ -n "${CONTAINER_ID:-}" ]; then
        echo "$CONTAINER_ID"
        return 0
    fi

    local cid=""

    # Method 1: Extract from mountinfo (cgroup v2)
    # Format: /var/lib/docker/containers/CONTAINER_ID_64_CHARS/...
    if [ -f /proc/self/mountinfo ]; then
        cid=$(grep -oE '/docker/containers/[0-9a-f]{64}' /proc/self/mountinfo 2>/dev/null | head -1 | sed 's|.*/||' | cut -c1-12)
    fi

    # Method 2: Extract from cgroup (cgroup v1)
    if [ -z "$cid" ] && [ -f /proc/self/cgroup ]; then
        cid=$(grep -oE '[0-9a-f]{64}' /proc/self/cgroup 2>/dev/null | head -1 | cut -c1-12)
    fi

    # Method 3: Use hostname
    if [ -z "$cid" ]; then
        cid=$(hostname 2>/dev/null)
    fi

    # Fallback to unknown
    cid="${cid:-unknown}"

    # Security: Validate format - prevent path traversal and shell injection
    # Only allow alphanumeric characters, hyphens, and underscores
    if ! echo "$cid" | grep -qE '^[a-zA-Z0-9_-]+$'; then
        echo "Warning: Invalid container ID format '$cid', using 'unknown'" >&2
        cid="unknown"
    fi

    echo "$cid"
}

# ============================================================================
# init_logbook_dir - Initialize single Logbook telemetry directory
# ============================================================================
# Creates the log directory structure and exports TELEMETRY_DIR.
#
# Usage:
#   init_logbook_dir "service-name" [service-type]
#
# Arguments:
#   $1 - Service name (required, e.g., "my-service", "my-worker")
#   $2 - Service type (optional, default: $SERVICE_TYPE or "native")
#
# Returns:
#   0 - Success, TELEMETRY_DIR exported
#   1 - Log directory not available/writable
#
# Side effects:
#   - Exports TELEMETRY_DIR
#   - Exports CONTAINER_ID
#   - Creates directory structure
# ============================================================================
init_logbook_dir() {
    local service_name="${1:?Service name required}"
    local service_type="${2:-${SERVICE_TYPE:-native}}"
    local container_id
    container_id=$(detect_container_id)

    if [ -d "$CONTAINER_LOG_DIR" ] && [ -w "$CONTAINER_LOG_DIR" ]; then
        local log_dir="${CONTAINER_LOG_DIR}/${container_id}/${service_type}/${service_name}"
        mkdir -p "$log_dir"

        export TELEMETRY_DIR="$log_dir"
        export CONTAINER_ID="$container_id"

        echo "Container log collection enabled:"
        echo "  Container ID: $container_id"
        echo "  Service: $service_name"
        echo "  Logbook dir: $log_dir"
        return 0
    else
        echo "Warning: Log directory not available or not writable: $CONTAINER_LOG_DIR"
        echo "Logbook telemetry will use default TELEMETRY_DIR."
        return 1
    fi
}

# ============================================================================
# init_logbook_dirs - Initialize multiple Logbook directories
# ============================================================================
# Creates multiple log subdirectories for multi-process services.
# Does NOT export TELEMETRY_DIR (caller must set per-process).
#
# Usage:
#   dirs=$(init_logbook_dirs "service-name" "subdir1" "subdir2" ...)
#   read -r DIR1 DIR2 <<< "$dirs"
#
# Arguments:
#   $1 - Service name (required)
#   $2+ - Subdirectory names (required, at least one)
#
# Returns:
#   0 - Success, prints space-separated directory paths
#   1 - Log directory not available/writable
#
# Output (stdout):
#   Space-separated list of created directory paths
#
# Side effects:
#   - Exports CONTAINER_ID
#   - Creates directory structure
# ============================================================================
init_logbook_dirs() {
    local service_name="${1:?Service name required}"
    shift

    if [ $# -eq 0 ]; then
        echo "Error: At least one subdirectory name required" >&2
        return 1
    fi

    local service_type="${SERVICE_TYPE:-native}"
    local container_id
    container_id=$(detect_container_id)
    local dirs=""

    if [ -d "$CONTAINER_LOG_DIR" ] && [ -w "$CONTAINER_LOG_DIR" ]; then
        local base_dir="${CONTAINER_LOG_DIR}/${container_id}/${service_type}/${service_name}"

        for subdir in "$@"; do
            local log_dir="${base_dir}/${subdir}"
            mkdir -p "$log_dir"
            dirs="${dirs:+$dirs }${log_dir}"
        done

        export CONTAINER_ID="$container_id"

        # All informational output to stderr - only paths to stdout for capture
        echo "Container log collection enabled:" >&2
        echo "  Container ID: $container_id" >&2
        echo "  Service: $service_name" >&2
        echo "  Logbook dirs: $dirs" >&2

        # Output directory paths for caller to capture (stdout only)
        echo "$dirs"
        return 0
    else
        echo "Warning: Log directory not available: $CONTAINER_LOG_DIR" >&2
        return 1
    fi
}

# ============================================================================
# log_collection_status - Print log collection configuration
# ============================================================================
# Utility function to display current log collection settings.
# ============================================================================
log_collection_status() {
    echo "Log Collection Status:"
    echo "  CONTAINER_LOG_DIR: ${CONTAINER_LOG_DIR:-not set}"
    echo "  CONTAINER_ID: ${CONTAINER_ID:-not detected}"
    echo "  TELEMETRY_DIR: ${TELEMETRY_DIR:-not set}"
    echo "  SERVICE_TYPE: ${SERVICE_TYPE:-native}"
}

# ============================================================================
# check_redis - Verify Redis connectivity using safe URL parsing
# ============================================================================
# Uses Python urllib.parse for safe URL parsing to prevent command
# injection via REDIS_URL environment variable.
#
# Usage:
#   check_redis                    # Uses REDIS_URL env var
#   check_redis "redis://host:6379"  # Uses provided URL
#
# Arguments:
#   $1 - Redis URL (optional, default: $REDIS_URL or redis://localhost:6379)
#
# Returns:
#   0 - Connection successful
#   1 - Connection failed or invalid URL
#
# Environment:
#   REDIS_URL: Default Redis connection URL if no argument provided
# ============================================================================
check_redis() {
    local redis_url="${1:-${REDIS_URL:-redis://localhost:6379}}"

    echo "Checking Redis connectivity..."

    # Pass URL via environment variable to avoid shell injection
    # Heredoc with quoted delimiter ('PYTHON_SCRIPT') prevents shell expansion
    _CHECK_REDIS_URL="$redis_url" python3 << 'PYTHON_SCRIPT'
import os
import socket
import sys
from urllib.parse import urlparse

redis_url = os.environ.get('_CHECK_REDIS_URL', 'redis://localhost:6379')

try:
    # Parse URL safely using urllib.parse
    parsed = urlparse(redis_url)

    # Validate scheme
    if parsed.scheme not in ('redis', 'rediss'):
        print(f"ERROR: Invalid Redis URL scheme: {parsed.scheme}", file=sys.stderr)
        print("Expected redis:// or rediss://", file=sys.stderr)
        sys.exit(1)

    # Extract host and port safely
    host = parsed.hostname or 'localhost'
    port = parsed.port or 6379

    # Validate port range
    if not (1 <= port <= 65535):
        print(f"ERROR: Invalid port number: {port}", file=sys.stderr)
        sys.exit(1)

    print(f"  Host: {host}")
    print(f"  Port: {port}")

    # Attempt TCP connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.close()

    print("Redis connectivity: OK")
    sys.exit(0)

except socket.timeout:
    print("ERROR: Connection to Redis timed out", file=sys.stderr)
    sys.exit(1)
except socket.error as e:
    print(f"ERROR: Cannot connect to Redis: {e}", file=sys.stderr)
    print("Ensure Redis is running and REDIS_URL is correct.", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: Redis connection check failed: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT

    return $?
}

# ============================================================================
# raise_fd_limit - Raise soft file descriptor limit to hard limit
# ============================================================================
# Docker containers default to soft=1024, hard=524288. Each gunicorn worker
# inherits the soft limit, capping connections per worker at ~1020 (minus
# internal FDs). Raising to the hard limit removes this bottleneck.
#
# Usage:
#   raise_fd_limit           # Raise and report
#   raise_fd_limit --quiet   # Raise silently
# ============================================================================
raise_fd_limit() {
    local quiet=false
    if [ "${1:-}" = "--quiet" ]; then
        quiet=true
    fi

    local soft hard
    soft=$(ulimit -Sn 2>/dev/null || echo "unknown")
    hard=$(ulimit -Hn 2>/dev/null || echo "unknown")

    if [ "$soft" = "$hard" ]; then
        [ "$quiet" = false ] && echo "File descriptor limit: $soft (already at hard limit)"
        return 0
    fi

    # Raise soft to hard
    if ulimit -n "$hard" 2>/dev/null; then
        [ "$quiet" = false ] && echo "File descriptor limit: $soft -> $hard (raised to hard limit)"
    else
        [ "$quiet" = false ] && echo "File descriptor limit: $soft (could not raise to $hard)"
    fi

    return 0
}

# ============================================================================
# tune_network_stack - Best-effort kernel network tuning for max connections
# ============================================================================
# Attempts to raise TCP connection limits for high-concurrency workloads.
# Succeeds silently when the container has write access to /proc/sys
# (e.g., --privileged or --cap-add NET_ADMIN). Reports current values
# when read-only (e.g., non-root, host network mode without capabilities).
#
# For host network mode: kernel params must be tuned on the host.
# For bridge mode: use docker run --sysctl or docker-compose sysctls:.
#
# Also raises the soft file descriptor limit to the hard limit so that
# workers can accept the maximum number of concurrent connections.
#
# Tuned parameters:
#   net.core.somaxconn        - Max accept queue depth (default: 4096)
#   net.ipv4.tcp_max_syn_backlog - Max half-open connections (default: 1024)
#   ulimit -n                 - File descriptors (raised to hard limit)
#
# Usage:
#   tune_network_stack           # Use defaults (65535)
#   tune_network_stack --quiet   # Suppress output
#
# Environment Variables:
#   NEO_SOMAXCONN: Target somaxconn value (default: 65535)
#   NEO_TCP_MAX_SYN_BACKLOG: Target SYN backlog (default: 65535)
# ============================================================================
tune_network_stack() {
    local quiet=false
    if [ "${1:-}" = "--quiet" ]; then
        quiet=true
    fi

    local somaxconn="${NEO_SOMAXCONN:-65535}"
    local syn_backlog="${NEO_TCP_MAX_SYN_BACKLOG:-65535}"
    local any_changed=false

    if [ "$quiet" = false ]; then
        echo "Network stack tuning:"
    fi

    # File descriptor limit — raise soft to hard
    raise_fd_limit $([ "$quiet" = true ] && echo "--quiet")

    # somaxconn — accept queue depth
    if echo "$somaxconn" > /proc/sys/net/core/somaxconn 2>/dev/null; then
        any_changed=true
        [ "$quiet" = false ] && echo "  net.core.somaxconn = $somaxconn (applied)"
    else
        local current
        current=$(cat /proc/sys/net/core/somaxconn 2>/dev/null || echo "unknown")
        if [ "$current" = "$somaxconn" ]; then
            [ "$quiet" = false ] && echo "  net.core.somaxconn = $current (already at target)"
        else
            [ "$quiet" = false ] && echo "  net.core.somaxconn = $current (target: $somaxconn — set on host or use --sysctl)"
        fi
    fi

    # tcp_max_syn_backlog — half-open connection queue
    if echo "$syn_backlog" > /proc/sys/net/ipv4/tcp_max_syn_backlog 2>/dev/null; then
        any_changed=true
        [ "$quiet" = false ] && echo "  net.ipv4.tcp_max_syn_backlog = $syn_backlog (applied)"
    else
        local current
        current=$(cat /proc/sys/net/ipv4/tcp_max_syn_backlog 2>/dev/null || echo "unknown")
        if [ "$current" = "$syn_backlog" ]; then
            [ "$quiet" = false ] && echo "  net.ipv4.tcp_max_syn_backlog = $current (already at target)"
        else
            [ "$quiet" = false ] && echo "  net.ipv4.tcp_max_syn_backlog = $current (target: $syn_backlog — set on host or use --sysctl)"
        fi
    fi

    if [ "$any_changed" = true ] && [ "$quiet" = false ]; then
        echo "  Kernel network params tuned for high concurrency"
    fi

    # Always return success — tuning is best-effort
    return 0
}

# ============================================================================
# init_prometheus_multiproc - Initialize Prometheus multiprocess directory
# ============================================================================
# When PROMETHEUS_MULTIPROC_DIR is set, prometheus_client uses filesystem-
# backed mmap files to share metrics across processes (gunicorn workers,
# Celery workers). The directory must exist BEFORE any process imports
# prometheus_client, and must be cleared on every container start to
# remove stale mmap files from previous runs.
#
# This function is in the shared library because any image that inherits
# FROM an image with PROMETHEUS_MULTIPROC_DIR set (e.g., app-runtime
# extends neoaxios_fastapi_kit) needs the directory created.
#
# Usage:
#   init_prometheus_multiproc           # Create/clear directory
#   init_prometheus_multiproc --quiet   # Create/clear silently
#
# Environment Variables:
#   PROMETHEUS_MULTIPROC_DIR: Directory for mmap files (optional)
# ============================================================================
init_prometheus_multiproc() {
    local quiet=false
    if [ "${1:-}" = "--quiet" ]; then
        quiet=true
    fi

    if [ -n "${PROMETHEUS_MULTIPROC_DIR:-}" ]; then
        rm -rf "$PROMETHEUS_MULTIPROC_DIR"
        mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
        [ "$quiet" = false ] && echo "Prometheus multiprocess directory: $PROMETHEUS_MULTIPROC_DIR"
    fi

    return 0
}

# ============================================================================
# init_system_resources - Detect system resources at container boot
# ============================================================================
# Runs secure_config resource detection early in the boot process, before
# the main application starts. This ensures NEO_SYSTEM_* and NEO_APP_*
# environment variables are available to all child processes.
#
# Uses secure_config.runtime for detection (psutil-based), which:
# - Detects CPU logical/physical count
# - Detects RAM total/available
# - Calculates recommended worker count based on CPU and RAM
# - Respects NEO_SYSTEM_*_OVERRIDE env vars for container limits
#
# Usage:
#   init_system_resources           # Detect and log
#   init_system_resources --quiet   # Detect without logging
#
# Arguments:
#   --quiet: Suppress output (optional)
#
# Returns:
#   0 - Success, env vars exported
#   1 - Detection failed (secure_config not available)
#
# Environment Variables Set:
#   NEO_SYSTEM_CPU_LOGICAL_COUNT: Logical CPUs (threads)
#   NEO_SYSTEM_CPU_PHYSICAL_COUNT: Physical CPU cores
#   NEO_SYSTEM_RAM_TOTAL_GB: Total RAM in GB
#   NEO_SYSTEM_RAM_AVAILABLE_GB: Available RAM in GB
#   NEO_APP_RAM_BUDGET_GB: Calculated RAM budget
#   NEO_APP_RECOMMENDED_WORKERS: Recommended worker count
#
# Example:
#   source /usr/local/lib/entrypoint-lib.sh
#   init_system_resources
#   echo "Starting with $NEO_APP_RECOMMENDED_WORKERS workers"
#   exec gunicorn -w "$NEO_APP_RECOMMENDED_WORKERS" ...
# ============================================================================
init_system_resources() {
    local quiet=false
    if [ "${1:-}" = "--quiet" ]; then
        quiet=true
    fi

    # Run detection via secure_config
    # The Python script exports env vars which we then source
    # Set TELEMETRY_DIR to /tmp if not already set to prevent Logbook from
    # trying to create .telemetry in a potentially non-writable directory
    local detection_output
    if ! detection_output=$(TELEMETRY_DIR="${TELEMETRY_DIR:-/tmp}" python3 << 'PYTHON_SCRIPT'
import os
import sys

try:
    from secure_config import (
        detect_system_resources,
        calculate_app_budget,
        calculate_recommended_workers,
    )

    # Run detection - this sets NEO_SYSTEM_* env vars
    resources = detect_system_resources()

    # Calculate budget and workers - this sets NEO_APP_* env vars
    budget = calculate_app_budget()
    workers = calculate_recommended_workers()

    # Output for bash to display (goes to stderr so it doesn't interfere with env export)
    print(f"  CPU Logical: {resources.cpu_logical_count}", file=sys.stderr)
    print(f"  CPU Physical: {resources.cpu_physical_count}", file=sys.stderr)
    print(f"  RAM Total: {resources.ram_total_gb} GB", file=sys.stderr)
    print(f"  RAM Available: {resources.ram_available_gb} GB", file=sys.stderr)
    print(f"  RAM Budget: {budget} GB", file=sys.stderr)
    print(f"  Recommended Workers: {workers}", file=sys.stderr)

    # Output env var exports for bash to eval (goes to stdout)
    # These are the key env vars that child processes need
    print(f"export NEO_SYSTEM_CPU_LOGICAL_COUNT={resources.cpu_logical_count}")
    print(f"export NEO_SYSTEM_CPU_PHYSICAL_COUNT={resources.cpu_physical_count}")
    print(f"export NEO_SYSTEM_RAM_TOTAL_GB={resources.ram_total_gb}")
    print(f"export NEO_SYSTEM_RAM_AVAILABLE_GB={resources.ram_available_gb}")
    print(f"export NEO_APP_RAM_BUDGET_GB={budget}")
    print(f"export NEO_APP_RECOMMENDED_WORKERS={workers}")

    sys.exit(0)

except ImportError as e:
    print(f"Warning: secure_config not available: {e}", file=sys.stderr)
    print("System resource detection skipped.", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"Warning: Resource detection failed: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_SCRIPT
2>&1); then
        # Detection failed - not fatal, just log warning
        if [ "$quiet" = false ]; then
            echo "System resource detection: skipped"
            echo "$detection_output"
        fi
        return 1
    fi

    # Parse output - stderr lines (info) vs stdout lines (exports)
    local info_lines=""
    local export_lines=""
    while IFS= read -r line; do
        if [[ "$line" == export\ * ]]; then
            export_lines="${export_lines}${line}"$'\n'
        else
            info_lines="${info_lines}${line}"$'\n'
        fi
    done <<< "$detection_output"

    # Execute the exports in current shell
    if [ -n "$export_lines" ]; then
        eval "$export_lines"
    fi

    # Display info if not quiet
    if [ "$quiet" = false ]; then
        echo "System resource detection:"
        echo -n "$info_lines"
    fi

    return 0
}
