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

# Minimal Python base with common system dependencies
# Base: Debian Bookworm slim (~51 MB compressed)
#
# Provides:
# - Non-root user (neoaxios)
# - uv package manager
# - secure_config for runtime resource detection
# - entrypoint-lib.sh for container initialization
FROM python:3.12-slim-bookworm

LABEL maintainer="NeoAxios"
LABEL org.opencontainers.image.source="https://github.com/neoaxios/neoaxios-starter-kit"
LABEL org.opencontainers.image.description="NeoAxios Python base image"

# Security: create non-root user
RUN groupadd -r neoaxios && useradd -r -g neoaxios neoaxios

# Install common system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install uv for fast package installation
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# WHEELS_HASH is passed by build system - changes when wheel content changes
ARG WHEELS_HASH
# Copy wheels (populated by build system before docker build)
COPY wheels/ /wheels/

# Install secure_config for runtime resource detection (CPU, RAM, workers).
# This enables init_system_resources() in entrypoint-lib.sh.
# Note: neoaxios-logging is a dependency of secure_config.
# Two-prong WHEELS_HASH cache invalidation (enforced by neoaxios-build's
# DockerfileLinter): (1) cache-mount id is suffixed with ${WHEELS_HASH}
# so uv's per-version extraction cache is keyed per wheel set; (2) the
# RUN body echoes ${WHEELS_HASH} so BuildKit's layer cache key changes
# when wheels change (BuildKit excludes --mount metadata from cache keys).
RUN --mount=type=cache,id=uv-python-slim-${WHEELS_HASH},target=/root/.cache/uv \
    echo "wheels_hash=${WHEELS_HASH}" \
    && uv pip install --system --find-links=/wheels/ \
    neoaxios-secure-config \
    neoaxios-logging \
    && rm -rf /wheels/

# Install shared entrypoint library for container initialization
# Provides: detect_container_id(), init_logbook_dir(), init_system_resources()
COPY scripts/entrypoint-lib.sh /usr/local/lib/entrypoint-lib.sh
RUN chmod +x /usr/local/lib/entrypoint-lib.sh

# Python environment settings
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
