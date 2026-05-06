#!/bin/sh
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
# neoaxios/redis entrypoint
#
# REDIS_MODE (default: cluster)
#   cluster    — concatenate redis.conf + cluster.conf → /tmp/redis-effective.conf,
#                then exec redis-server with CLI overrides in "$@"
#   standalone — exec redis-server /etc/redis/redis.conf with CLI overrides in "$@"
#   <other>    — exit non-zero with diagnostic to stderr
#
# CLUSTER_AUTO_BOOTSTRAP (default: 1 when REDIS_MODE=cluster)
#   1 — after redis-server is running, wait for PING; if cluster_slots_assigned:0
#       and only this node is known, run CLUSTER ADDSLOTSRANGE 0 16383 + CLUSTER
#       BUMPEPOCH to seat a single-node cluster. Required for single-node
#       test/dev cluster sites. `redis-cli --cluster create` is NOT used
#       because it rejects single-master clusters ("at least 3 nodes required").
#   0 — skip auto-bootstrap; rely on external orchestration (prod multi-node
#       via infra/scripts/bootstrap-redis-cluster.sh).
#
# Log-volume redirect: ${CONTAINER_LOG_DIR:-/var/log/neo}/$(hostname)/3rdparty/redis/redis.log

set -e

REDIS_MODE="${REDIS_MODE:-cluster}"
REDIS_PORT="${REDIS_PORT:-6379}"
CLUSTER_AUTO_BOOTSTRAP="${CLUSTER_AUTO_BOOTSTRAP:-1}"

# -- Resolve effective config path based on REDIS_MODE ---------------------
# Done before the log redirect so an invalid REDIS_MODE diagnostic reaches
# the container's stderr (visible via `docker logs`).
case "$REDIS_MODE" in
    cluster)
        # redis-server accepts exactly one positional config arg — concatenate
        # Tier-1 (redis.conf) + Tier-2 (cluster.conf) into a single effective file.
        cat /etc/redis/redis.conf /etc/redis/cluster.conf >/tmp/redis-effective.conf
        CONFIG_FILE=/tmp/redis-effective.conf
        ;;
    standalone)
        CONFIG_FILE=/etc/redis/redis.conf
        CLUSTER_AUTO_BOOTSTRAP=0
        ;;
    *)
        echo "entrypoint.sh: REDIS_MODE='$REDIS_MODE' is not valid (expected: cluster|standalone)" >&2
        exit 64
        ;;
esac

# Helper to read a scalar value from CLUSTER INFO via grep/cut (POSIX-safe,
# no awk field-splitting quirks).
_cluster_info_field() {
    printf '%s\n' "$1" | grep "^$2:" | head -n1 | cut -d: -f2 | tr -d '\r\n '
}

# -- Single-node cluster auto-bootstrap ----------------------------
# Runs in background: waits for redis-server to come up, then seats the node
# with all 16384 slots. No-op when CLUSTER_AUTO_BOOTSTRAP=0 or
# REDIS_MODE=standalone. Bootstrap output is intentionally kept on stderr so
# operators can see it via `docker logs` until log-volume redirect takes over.
if [ "$CLUSTER_AUTO_BOOTSTRAP" = "1" ] && [ "$REDIS_MODE" = "cluster" ]; then
    (
        # Wait for server readiness (up to ~30s).
        i=0
        while [ "$i" -lt 30 ]; do
            if redis-cli -p "$REDIS_PORT" PING 2>/dev/null | grep -q PONG; then
                break
            fi
            i=$((i + 1))
            sleep 1
        done
        if [ "$i" -ge 30 ]; then
            echo "entrypoint.sh: bootstrap gave up waiting for PING" >&2
            exit 0
        fi

        # CLUSTER INFO read is best-effort; absence is
        # handled explicitly by the defaulted checks below (slots_assigned
        # falls back to 0 → bootstrap is a no-op rather than guessing at a
        # cluster state we cannot confirm). A hard-failing read would
        # convert a transient redis-cli glitch into a cluster-state drift
        # signal; the parent redis-server keeps running either way.
        cluster_info=$(redis-cli -p "$REDIS_PORT" CLUSTER INFO 2>/dev/null || true)
        slots_assigned=$(_cluster_info_field "$cluster_info" cluster_slots_assigned)
        known_nodes=$(_cluster_info_field "$cluster_info" cluster_known_nodes)

        if [ "${slots_assigned:-0}" = "0" ] && [ "${known_nodes:-0}" = "1" ]; then
            echo "entrypoint.sh: seating single-node cluster (slots 0..16383)" >&2
            # Surface bootstrap failures explicitly so an operator can
            # detect a cluster stuck in fail state via `docker logs`. The
            # bootstrap subshell does NOT exit on failure because the main
            # redis-server has already taken over; shutting down the
            # subshell would not affect redis itself.
            if ! redis-cli -p "$REDIS_PORT" CLUSTER ADDSLOTSRANGE 0 16383 >/dev/null 2>&1; then
                echo "entrypoint.sh: CLUSTER ADDSLOTSRANGE failed — cluster may remain in fail state; inspect with 'redis-cli CLUSTER INFO'" >&2
            elif ! redis-cli -p "$REDIS_PORT" CLUSTER BUMPEPOCH >/dev/null 2>&1; then
                echo "entrypoint.sh: CLUSTER BUMPEPOCH failed after ADDSLOTSRANGE succeeded — cluster_state may stay fail until epoch settles" >&2
            fi
        fi
    ) &
fi

# -- Log-volume redirect (non-fatal if the log volume is not mounted) --
# The container log volume is mounted by integration test environments
# and by production deployment wrappers, but intentionally absent in test
# containers (testcontainers, local docker run for smoke tests).
# A hard failure here
# would break every CI/dev path that does not pre-create the mount; a
# best-effort redirect with continue-on-failure keeps redis-server's
# stdout/stderr on the container's original FDs, which docker logs still
# captures. Placed just before exec so any earlier diagnostic has already
# flushed to the container's original stderr.
LOG_DIR="${CONTAINER_LOG_DIR:-/var/log/neo}/$(hostname)/3rdparty/redis"
if mkdir -p "$LOG_DIR" 2>/dev/null; then
    exec >>"$LOG_DIR/redis.log" 2>&1 || true
fi

# -- Exec redis-server with the resolved config plus any CLI overrides -----
exec redis-server "$CONFIG_FILE" "$@"
