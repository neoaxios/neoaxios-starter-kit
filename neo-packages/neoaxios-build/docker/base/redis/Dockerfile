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

# NeoAxios Redis base image
#
# Bakes the canonical cache config (Tier-1) and cluster overlay (Tier-2)
# into a single image. The entrypoint selects the topology at runtime via
# REDIS_MODE (default: cluster).
#
# This is the single source of truth for Redis runtime config across
# dev (single-node cluster), CI (per-host cluster), and prod
# (3-master + 3-replica Nomad cluster). All nine historical deployment
# sites reference this image rather than re-declaring config.
#
# Build (via make build):
#   make build
#
# Ports:
#   ${REDIS_PORT:-6379}: Redis client port (overridable per deployment)
#   16379 + cluster-announce-bus-port: cluster gossip (when REDIS_MODE=cluster)

FROM redis:8.0-alpine@sha256:5f61955be8ab2ccee9372b84ae4d4da2e2b156f87281e3f218544055e7ee04d4

LABEL maintainer="NeoAxios"
LABEL org.opencontainers.image.source="https://github.com/neoaxios/neoaxios-starter-kit"
LABEL org.opencontainers.image.description="NeoAxios Redis with baked canonical cache config and cluster overlay"

# Canonical config — baked at build time, single source of truth
COPY redis.conf /etc/redis/redis.conf
COPY cluster.conf /etc/redis/cluster.conf

# Working directory for cluster-mode nodes.conf. Created world-writable so
# the image runs under any UID (rootless `--user <uid>` invocations,
# prod Nomad's forced UID, local docker run as root — all work). Persistent
# deployments (multi-node prod) override with `--dir /persistent/state`.
# The upstream /data directory is chown'd to the redis user (UID 999) so
# rootless execution paths cannot write cluster state there; see
# cluster.conf `dir /var/lib/neo-redis` for the full rationale.
RUN mkdir -p /var/lib/neo-redis && chmod 1777 /var/lib/neo-redis

# Entrypoint handles REDIS_MODE (standalone|cluster), log-volume redirect,
# and single-node cluster auto-bootstrap (CLUSTER_AUTO_BOOTSTRAP=1)
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD redis-cli -p ${REDIS_PORT:-6379} ping | grep -q PONG

ENTRYPOINT ["entrypoint.sh"]
