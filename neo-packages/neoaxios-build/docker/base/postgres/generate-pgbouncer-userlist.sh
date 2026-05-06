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
# Generate the PgBouncer auth userlist at /tmp/pgbouncer-userlist.txt
# (the path pgbouncer.ini's auth_file directive hardcodes).
#
# Usage:
#   generate-pgbouncer-userlist.sh [output-path]
#
# Positional argument:
#   output-path  Optional override for the userlist file.  Default
#                /tmp/pgbouncer-userlist.txt — must match
#                pgbouncer.ini's auth_file in production.  The
#                override is for unit tests; production callers
#                MUST omit it so the path matches pgbouncer.ini.
#
# Inputs (environment):
#   POSTGRES_USER             primary role name     (default: postgres)
#   POSTGRES_PASSWORD         primary role password (default: postgres)
#   PGBOUNCER_EXTRA_USERS_FILE
#                             optional path to a deploy-host-owned
#                             file containing additional ``"user"
#                             "password"`` lines in pgbouncer userlist
#                             format.  Default
#                             /etc/pgbouncer/extra-users.txt.
#
# Mounted file format (PGBOUNCER_EXTRA_USERS_FILE):
#   Each non-blank, non-``#`` line MUST be in the literal pgbouncer
#   userlist format ``"user" "password"`` — the file is concatenated
#   verbatim onto the generated userlist.  Operators write secrets in
#   the exact format pgbouncer parses; no in-script translation, so
#   what's on disk is what pgbouncer sees.
#
# Output:
#   Userlist file (mode 0600), one quoted user/pass pair per line.
#   Primary user written first; extras appended in file order.
#
# Behaviour:
#   - Idempotent: rerun on every container start; truncates any prior
#     output before writing.
#   - Backwards compatible: when PGBOUNCER_EXTRA_USERS_FILE is absent
#     or empty, the output matches the pre-multi-tenant entrypoint.
#   - Hard fail when the extras file is present-but-unreadable: a
#     mounted file the operator intended to apply MUST be readable;
#     warn-and-fall-through would leave pgbouncer with an incomplete
#     userlist that the engine healthcheck can't detect, surfacing
#     downstream as cryptic auth errors.

set -e

USERLIST="${1:-/tmp/pgbouncer-userlist.txt}"
EXTRA_FILE="${PGBOUNCER_EXTRA_USERS_FILE:-/etc/pgbouncer/extra-users.txt}"

PRIMARY_USER="${POSTGRES_USER:-postgres}"
PRIMARY_PASS="${POSTGRES_PASSWORD:-postgres}"

# Ensure the parent directory exists (only relevant for the test
# override path; production /tmp is always writable).
mkdir -p "$(dirname "$USERLIST")"

# Truncate; primary user is always written first so single-user
# deployments produce identical output to the prior inlined logic.
printf '"%s" "%s"\n' "$PRIMARY_USER" "$PRIMARY_PASS" > "$USERLIST"

# Concatenate extra users when a deploy-host-mounted file is present.
# Skip blank lines and comments; everything else is appended verbatim
# (operator owns format correctness — pgbouncer's parser is the
# authority that catches malformed entries).
if [ -f "$EXTRA_FILE" ]; then
    if [ ! -r "$EXTRA_FILE" ]; then
        echo "ERROR: PGBOUNCER_EXTRA_USERS_FILE present but unreadable: $EXTRA_FILE" >&2
        echo "       This is a deploy misconfiguration — the operator mounted" >&2
        echo "       a userlist file pgbouncer can't read, so multi-tenant auth" >&2
        echo "       would fail at first connect with no signal at the engine" >&2
        echo "       healthcheck level.  Aborting container start." >&2
        exit 1
    elif [ -s "$EXTRA_FILE" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                ''|'#'*) continue ;;
            esac
            printf '%s\n' "$line" >> "$USERLIST"
        done < "$EXTRA_FILE"
    fi
fi

chmod 0600 "$USERLIST"
