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

# NeoAxios base with foundation packages pre-installed
# NOTE: Only FOUNDATION packages - application packages go in app images
#
# Inherits from python-slim which provides:
# - uv package manager
# - secure_config for runtime resource detection
# - entrypoint-lib.sh for container initialization
FROM neoaxios/python:3.12-slim

LABEL maintainer="NeoAxios"
LABEL org.opencontainers.image.source="https://github.com/neoaxios/neoaxios-starter-kit"
LABEL org.opencontainers.image.description="NeoAxios foundation base image"

# Switch to root for package installation
USER root

# WHEELS_HASH is passed by build system - changes when wheel content changes
# Used as cache ID to bust uv cache only when wheels actually change
ARG WHEELS_HASH
# Copy wheels (populated by build system)
COPY wheels/ /wheels/

# Install foundation/shared packages (uv inherited from python-slim)
# Cache ID includes WHEELS_HASH so cache is invalidated when wheels change
# Note: secure_config and neoaxios-logging are inherited from python-slim
RUN --mount=type=cache,id=uv-neoaxios-base,target=/root/.cache/uv \
    uv pip install --system --find-links=/wheels/ \
    # Foundation packages only (not in python-slim).
    # Application packages (neoaxios_fastapi_kit, sse-kit, etc.) install in their
    # own derived images, not here — see the Dockerfile header principle.
    neoaxios-config \
    neoaxios-resilience-kit \
    neoaxios-secure-cache \
    neoaxios-fastapi-kit \
    # ASGI server stack (required for FastAPI apps)
    gunicorn>=21.0.0 \
    uvicorn>=0.24.0 \
    && rm -rf /wheels/

# Common runtime settings
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO

# Network scale defaults — tuned for high-concurrency workloads
# Applied by entrypoint-lib.sh tune_network_stack() when container has
# NET_ADMIN capability. For host network mode: set on host via sysctl.
# For bridge mode: also settable via docker run --sysctl or compose sysctls:.
ENV NEO_SOMAXCONN=65535
ENV NEO_TCP_MAX_SYN_BACKLOG=65535

# entrypoint-lib.sh is inherited from python-slim at /usr/local/lib/entrypoint-lib.sh

# Run as non-root (inherits user from python-slim)
USER neoaxios
