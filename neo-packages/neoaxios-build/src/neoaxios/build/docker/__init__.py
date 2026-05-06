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

"""Docker build module for NeoAxios build system.

Provides auto-discovery and incremental building of Docker images
across a multi-package Python project.

Classes:
    DockerImage: Dataclass representing a Docker image to build
    DockerImageDiscovery: Discovers Docker images in the repository
    DockerBuilder: Builds Docker images with caching
"""

from neoaxios.build.docker.models import DockerImage, DockerBuildResult
from neoaxios.build.docker.discovery import DockerImageDiscovery
from neoaxios.build.docker.builder import DockerBuilder
from neoaxios.build.docker.cache_resolver import (
    ImageCacheMiss,
    ResolvedImage,
    resolve_required_images,
)

__all__ = [
    "DockerImage",
    "DockerBuildResult",
    "DockerImageDiscovery",
    "DockerBuilder",
    "ImageCacheMiss",
    "ResolvedImage",
    "resolve_required_images",
]
