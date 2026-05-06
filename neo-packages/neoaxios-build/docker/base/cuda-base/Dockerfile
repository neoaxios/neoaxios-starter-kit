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

# GPU-accelerated base image with CUDA and PyTorch
#
# Provides:
# - PyTorch 2.5.1 with CUDA 12.1 support
# - Non-root user (neoaxios, UID 997) compatible with rootless orchestrators
# - uv for fast parallel package installation
# - entrypoint-lib.sh for container initialization
#
# Used by: GPU-accelerated services
# Does NOT depend on wheels - avoids bootstrap issues

FROM pytorch/pytorch:2.5.1-cuda12.1-cudnn9-runtime

LABEL maintainer="NeoAxios"
LABEL org.opencontainers.image.source="https://github.com/neoaxios/neoaxios-starter-kit"
LABEL org.opencontainers.image.description="NeoAxios CUDA base image with PyTorch GPU support"

# System setup: install curl, uv, and create non-root user in a single layer
ENV UV_INSTALL_DIR=/usr/local/bin
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && groupadd -r neoaxios && useradd -r -u 997 -g neoaxios neoaxios

# Install shared entrypoint library for container initialization
# Provides: detect_container_id(), init_logbook_dir(), init_system_resources()
COPY scripts/entrypoint-lib.sh /usr/local/lib/entrypoint-lib.sh
RUN chmod +x /usr/local/lib/entrypoint-lib.sh

# Python environment settings
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Ensure proper ownership of common directories
RUN mkdir -p /app /home/neoaxios && \
    chown -R neoaxios:neoaxios /app /home/neoaxios && \
    chmod 755 /home/neoaxios

WORKDIR /app
