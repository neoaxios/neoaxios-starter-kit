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
# Container entrypoint for PostgreSQL + PgBouncer co-located image
#
# Starts PostgreSQL via the stock docker-entrypoint.sh, waits for readiness,
# then starts PgBouncer. Monitors both processes — if either exits, the
# other is terminated and the container exits with error.
#
# Ports:
#   5432: PostgreSQL direct (internal only)
#   6432: PgBouncer (client-facing)

set -e

# ── 3rdparty log collection ──────────────────────────────────────────
LOG_DIR="${CONTAINER_LOG_DIR:-/var/log/neo}/$(hostname)/3rdparty/postgresql"
# Best-effort log directory creation: when the container runs under
# TestGrid's --user 997:984 injection, the testbot uid cannot create
# directories under /var/log/ if the log volume isn't bind-mounted. If
# mkdir fails, leave on-disk logs at /dev/null — stdout still flows
# through `docker logs` via tee. A hard failure here would crash every
# deployment that doesn't pre-create the mount, with no diagnostic in
# `docker logs` except the mkdir error.
if mkdir -p "$LOG_DIR" 2>/dev/null; then
    PG_LOG_FILE="$LOG_DIR/postgresql.log"
    PGBOUNCER_LOG_FILE="$LOG_DIR/pgbouncer.log"
else
    PG_LOG_FILE=/dev/null
    PGBOUNCER_LOG_FILE=/dev/null
fi

# ── Clean stale PID from previous container run ──────────────────────
PGDATA="${PGDATA:-/var/lib/postgresql/data/pgdata}"
rm -f "$PGDATA/postmaster.pid"

# ── Start PostgreSQL in background ───────────────────────────────────
# PGDATA set to subdirectory to avoid initdb warning about non-empty mount point.
# PostgreSQL tuning matches the previous standalone configuration.
PGDATA="$PGDATA" docker-entrypoint.sh postgres \
    -c max_connections=300 \
    -c idle_session_timeout=30s \
    -c tcp_keepalives_idle=60 \
    -c tcp_keepalives_interval=10 \
    -c tcp_keepalives_count=3 \
    2>&1 | tee "$PG_LOG_FILE" &
PG_PID=$!

# ── Wait for PostgreSQL readiness ────────────────────────────────────
echo "Waiting for PostgreSQL to become ready..."
for i in $(seq 1 30); do
    if pg_isready -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -q 2>/dev/null; then
        echo "PostgreSQL ready after ${i}s"
        break
    fi
    if ! kill -0 $PG_PID 2>/dev/null; then
        echo "PostgreSQL process exited during startup"
        exit 1
    fi
    sleep 1
done

if ! pg_isready -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -q 2>/dev/null; then
    echo "PostgreSQL failed to become ready within 30s"
    kill $PG_PID 2>/dev/null || true
    exit 1
fi

# ── Generate PgBouncer userlist + start PgBouncer ────────────────────
# Both run as the ``postgres`` user (uid 70 in the alpine postgres
# image) — pgbouncer reads ``/tmp/pgbouncer-userlist.txt`` (written by
# the generate script) and the bind-mounted
# ``/etc/pgbouncer/extra-users.txt`` at startup.  Generating the
# userlist as root produced a 0600 root-owned file that pgbouncer-as-
# postgres couldn't read, crashing the container with "auth_file:
# Permission denied".  Running both as postgres makes the file
# postgres-owned from the start.
#
# The container path:
#   - root → drop via su-exec to postgres for both calls (standard
#     docker-compose deploy)
#   - non-root (--user already set by an orchestrator) → invoke directly;
#     su-exec errors out when not root
#
# generate-pgbouncer-userlist.sh's contract: writes to
# /tmp/pgbouncer-userlist.txt (matching pgbouncer.ini's hardcoded
# auth_file path); reads /etc/pgbouncer/extra-users.txt for
# multi-tenant userlist additions when present.  See that script's
# header for full input/output spec.
echo "Starting PgBouncer on port 6432..."
if [ "$(id -u)" = "0" ]; then
    su-exec postgres /usr/local/bin/generate-pgbouncer-userlist.sh
    su-exec postgres pgbouncer /etc/pgbouncer/pgbouncer.ini 2>&1 | tee "$PGBOUNCER_LOG_FILE" &
else
    /usr/local/bin/generate-pgbouncer-userlist.sh
    pgbouncer /etc/pgbouncer/pgbouncer.ini 2>&1 | tee "$PGBOUNCER_LOG_FILE" &
fi
PGBOUNCER_PID=$!

echo "Started PostgreSQL (PID: $PG_PID) and PgBouncer (PID: $PGBOUNCER_PID)"

# ── Graceful shutdown ────────────────────────────────────────────────
cleanup() {
    echo "Received shutdown signal, stopping processes..."
    kill -TERM $PGBOUNCER_PID $PG_PID 2>/dev/null || true
    wait $PGBOUNCER_PID $PG_PID 2>/dev/null || true
    echo "PostgreSQL and PgBouncer stopped"
    exit 0
}
trap cleanup SIGTERM SIGINT

# ── Monitor both processes ───────────────────────────────────────────
while kill -0 $PG_PID 2>/dev/null && kill -0 $PGBOUNCER_PID 2>/dev/null; do
    sleep 1
done

echo "One of the processes exited unexpectedly"
kill $PG_PID $PGBOUNCER_PID 2>/dev/null || true
exit 1
