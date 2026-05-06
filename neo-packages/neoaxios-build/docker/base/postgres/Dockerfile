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

# PostgreSQL 16 + PgBouncer co-located image
#
# PgBouncer provides transaction-mode connection pooling in front of PostgreSQL.
# Clients connect to port 6432 (PgBouncer), which proxies to 5432 (PostgreSQL).
#
# This prevents stale connections from crashed containers from exhausting
# PostgreSQL's max_connections limit in multi-host integration test deployments.
#
# Build (via make build-docker):
#   make build
#
# Ports:
#   5432: PostgreSQL direct (internal, not exposed to clients)
#   6432: PgBouncer (client-facing, transaction-mode pooling)

FROM postgres:16-alpine

LABEL maintainer="NeoAxios"
LABEL org.opencontainers.image.source="https://github.com/neoaxios/neoaxios-starter-kit"
LABEL org.opencontainers.image.description="PostgreSQL 16 with PgBouncer transaction-mode pooling (neoaxios/postgres)"

# Install PgBouncer
RUN apk add --no-cache pgbouncer

# Copy PgBouncer configuration
# userlist.txt is a placeholder — entrypoint generates runtime credentials in /tmp
COPY pgbouncer.ini /etc/pgbouncer/pgbouncer.ini
COPY userlist.txt /etc/pgbouncer/userlist.txt
RUN chown -R postgres:postgres /etc/pgbouncer

# Copy entrypoint + userlist generator.  The entrypoint delegates
# userlist composition to the generator so the multi-tenant logic is
# unit-testable in isolation (this codebase tests/test_pgbouncer_userlist_generator.py).
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY generate-pgbouncer-userlist.sh /usr/local/bin/generate-pgbouncer-userlist.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/generate-pgbouncer-userlist.sh

# PGDATA set to subdirectory to avoid initdb warning about non-empty mount point
ENV PGDATA=/var/lib/postgresql/data/pgdata

EXPOSE 5432 6432

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD pg_isready -q && \
        pg_isready -h 127.0.0.1 -p 6432 -q

ENTRYPOINT ["entrypoint.sh"]
