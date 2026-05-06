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

"""Data models for the build system."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import json


@dataclass
class BuildPackage:
    """Represents a package to be built.

    Attributes:
        name: Directory name (e.g., "shared")
        package_dir: Path to package directory containing pyproject.toml
        log_path: Path where build logs will be saved
        metadata_path: Path where JSON metadata will be saved
        has_contracts_yaml: Whether package has contracts.yaml (consumer)
        has_manifest_yaml: Whether package has contracts/manifest.yaml (provider)
        pyproject_path: Path to pyproject.toml
        display_name: Package name from pyproject.toml (e.g., "neoaxios-test-foundation")
    """
    name: str
    package_dir: Path
    log_path: Path
    metadata_path: Path
    has_contracts_yaml: bool = False
    has_manifest_yaml: bool = False
    pyproject_path: Optional[Path] = None
    display_name: Optional[str] = None

    def __post_init__(self):
        """Validate package configuration after initialization."""
        if not self.name:
            raise ValueError("Package name cannot be empty")

        # Convert strings to Path objects if needed
        if isinstance(self.package_dir, str):
            self.package_dir = Path(self.package_dir)
        if isinstance(self.log_path, str):
            self.log_path = Path(self.log_path)
        if isinstance(self.metadata_path, str):
            self.metadata_path = Path(self.metadata_path)
        if self.pyproject_path and isinstance(self.pyproject_path, str):
            self.pyproject_path = Path(self.pyproject_path)

        # Default display_name to directory name if not provided
        if self.display_name is None:
            self.display_name = self.name

        # Validate package directory exists
        if not self.package_dir.exists():
            raise ValueError(f"Package directory not found: {self.package_dir}")

        if not self.package_dir.is_dir():
            raise ValueError(f"Package path is not a directory: {self.package_dir}")

    def __repr__(self) -> str:
        """String representation for debugging."""
        contracts = []
        if self.has_contracts_yaml:
            contracts.append("VAL")
        if self.has_manifest_yaml:
            contracts.append("PUB")
        contract_str = f", contracts={'+'.join(contracts)}" if contracts else ""
        return f"BuildPackage(name={self.name!r}, dir={self.package_dir}{contract_str})"


@dataclass
class BuildResult:
    """Result of a package build.

    Attributes:
        package: The BuildPackage that was built
        exit_code: Process exit code (0 = success, non-zero = failure)
        duration: Build duration in seconds
        stdout: Captured standard output
        stderr: Captured standard error
        operations: List of operations performed (e.g., ["wheel", "contracts-publish"])
        start_time: Build start timestamp
        end_time: Build end timestamp
        failure_stage: Stage where build failed (e.g., "wheel", "contract-validate", "types-generate")
        error_message: First error line extracted from stderr/stdout
    """
    package: BuildPackage
    exit_code: int
    duration: float
    stdout: str
    stderr: str
    operations: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    failure_stage: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def success(self) -> bool:
        """Returns True if the build succeeded (exit code 0)."""
        return self.exit_code == 0

    def to_json(self) -> dict:
        """Serialize build result to JSON-compatible dictionary.

        Returns:
            Dictionary with all build metadata
        """
        return {
            "package": self.package.name,
            "package_dir": str(self.package.package_dir),
            "has_contracts": self.package.has_contracts_yaml or self.package.has_manifest_yaml,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration,
            "exit_code": self.exit_code,
            "success": self.success,
            "operations": self.operations,
            "stdout_lines": len(self.stdout.splitlines()),
            "stderr_lines": len(self.stderr.splitlines()),
        }

    def save_metadata(self, path: Optional[Path] = None) -> None:
        """Save build metadata to JSON file.

        Args:
            path: Override path (defaults to package.metadata_path)
        """
        target_path = path or self.package.metadata_path

        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        with open(target_path, 'w') as f:
            json.dump(self.to_json(), f, indent=2)

    def save_log(self, path: Optional[Path] = None) -> None:
        """Save build logs to file.

        Args:
            path: Override path (defaults to package.log_path)
        """
        target_path = path or self.package.log_path

        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        with open(target_path, 'w') as f:
            # Write header
            f.write("=" * 60 + "\n")
            f.write(f"  Building: {self.package.name}\n")
            f.write("=" * 60 + "\n")
            if self.start_time:
                f.write(f"Start Time: {self.start_time.isoformat()}\n")
            f.write("\n")

            # Write stdout
            if self.stdout:
                f.write("=== Build Output ===\n")
                f.write(self.stdout)
                f.write("\n\n")

            # Write stderr if present
            if self.stderr:
                f.write("=== Errors ===\n")
                f.write(self.stderr)
                f.write("\n\n")

            # Write footer
            if self.end_time:
                f.write(f"End Time: {self.end_time.isoformat()}\n")
            f.write(f"Duration: {self.duration:.3f}s\n")
            f.write(f"Exit Code: {self.exit_code}\n")
            f.write(f"Status: {'SUCCESS' if self.success else 'FAILED'}\n")
