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

"""Data models for Docker image builds."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class DockerImage:
    """Represents a Docker image to be built.

    Attributes:
        name: Image name (e.g., "app-runtime")
        tag: Image tag (e.g., "latest", "v1.0.0")
        path: Path to docker/ directory containing Dockerfile
        dockerfile: Path to Dockerfile
        context: Build context directory
        base_image: FROM image (e.g., "neoaxios/base:latest")
        wheel_dependencies: Required wheels from dist/
        image_dependencies: Required images (build order)
        registry: Optional registry prefix
        always_rebuild: Skip cache and rebuild on every build
    """

    name: str
    tag: str
    path: Path
    dockerfile: Path
    context: Path
    base_image: Optional[str] = None
    wheel_dependencies: list[str] = field(default_factory=list)
    image_dependencies: list[str] = field(default_factory=list)
    registry: Optional[str] = None
    always_rebuild: bool = False

    def __post_init__(self):
        """Validate and convert paths."""
        if isinstance(self.path, str):
            self.path = Path(self.path)
        if isinstance(self.dockerfile, str):
            self.dockerfile = Path(self.dockerfile)
        if isinstance(self.context, str):
            self.context = Path(self.context)

    @property
    def full_name(self) -> str:
        """Return full image name with registry and tag.

        Returns:
            Full image name (e.g., "myorg/app:latest")
        """
        if self.registry:
            return f"{self.registry}/{self.name}:{self.tag}"
        return f"{self.name}:{self.tag}"

    @property
    def short_name(self) -> str:
        """Return image name without registry.

        Returns:
            Short image name (e.g., "app-runtime:latest")
        """
        return f"{self.name}:{self.tag}"

    def __repr__(self) -> str:
        """String representation for debugging."""
        deps = f", deps={self.image_dependencies}" if self.image_dependencies else ""
        wheels = f", wheels={len(self.wheel_dependencies)}" if self.wheel_dependencies else ""
        return f"DockerImage({self.full_name}{deps}{wheels})"


@dataclass
class DockerBuildResult:
    """Result of a Docker image build.

    Attributes:
        image: The DockerImage that was built
        success: Whether build succeeded
        cached: Whether result was from cache
        duration: Build duration in seconds
        image_id: Docker image ID (sha256)
        output_path: Path to tar.gz file in docker-images/
        error_message: Error message if build failed
        start_time: Build start timestamp
        end_time: Build end timestamp
    """

    image: DockerImage
    success: bool
    cached: bool
    duration: float
    image_id: Optional[str] = None
    output_path: Optional[Path] = None
    error_message: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    build_stderr: Optional[str] = None
    log_path: Optional[Path] = None

    def save_log(self) -> None:
        """Save build log to file.

        Writes a structured log file containing the full build stderr output.
        No-op when log_path or build_stderr is None (cache hits, skipped builds).
        """
        if self.log_path is None or self.build_stderr is None:
            return

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.log_path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write(f"  Building: {self.image.full_name}\n")
            f.write("=" * 60 + "\n")
            if self.start_time:
                f.write(f"Start Time: {self.start_time.isoformat()}\n")
            f.write("\n")

            f.write("=== Build Output ===\n")
            f.write(self.build_stderr)
            f.write("\n\n")

            if self.end_time:
                f.write(f"End Time: {self.end_time.isoformat()}\n")
            f.write(f"Duration: {self.duration:.3f}s\n")
            f.write(f"Status: {'SUCCESS' if self.success else 'FAILED'}\n")

    def to_dict(self) -> dict:
        """Serialize to dictionary.

        Returns:
            Dictionary with build result data
        """
        return {
            "image": self.image.full_name,
            "success": self.success,
            "cached": self.cached,
            "duration": self.duration,
            "image_id": self.image_id,
            "output_path": str(self.output_path) if self.output_path else None,
            "error_message": self.error_message,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "log_path": str(self.log_path) if self.log_path else None,
        }
