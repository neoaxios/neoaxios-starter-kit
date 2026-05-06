#!/usr/bin/env python3
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
"""Emit structured Docker image discovery JSON from build.yaml.

Reads the `docker_images:` section of build.yaml and produces a JSON
document consumable by CI pipelines (e.g., `.github/workflows/deploy.yml`)
to drive per-image build/sign/deploy loops.

Unlike `docker_scan_paths` (glob-based auto-discovery used by
DockerImageDiscovery during `make build`), `docker_images` is an explicit
enumeration. The two mechanisms are additive: globs keep local builds
self-discovering, while docker_images gives CI a deterministic contract.

Output schema:
    [
        {
            "name": "<image-short-name>",
            "dockerfile_path": "<path relative to repo root>",
            "context": "<path relative to repo root>"
        },
        ...
    ]

The script fails if:
  - build.yaml is missing.
  - `docker_images` is missing or empty.
  - Any entry lacks name/dockerfile_path/context.
  - Any declared dockerfile_path does not exist on disk.

The script raises cleanly on bad input — there is no fallback behavior.

Usage:
    # Print JSON to stdout
    python3 neo-packages/neoaxios-build/scripts/discover_docker_images.py

    # Write JSON to a file
    python3 neo-packages/neoaxios-build/scripts/discover_docker_images.py \\
        --output images.json

    # Use a non-default repo root
    python3 neo-packages/neoaxios-build/scripts/discover_docker_images.py \\
        --repo-root /path/to/repo
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

# Repo root inference — this script lives at
# neo-packages/neoaxios-build/scripts/discover_docker_images.py,
# three parents up from the script == repo root.
_REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent.parent.parent

# Ensure the build package is importable for module-logger discovery.
sys.path.insert(0, str(_REPO_ROOT_DEFAULT / "neo-packages" / "neoaxios-build" / "src"))

from neoaxios_logging import auto_trace, get_telemetry  # noqa: E402

import _display as display  # noqa: E402

logger = get_telemetry(__name__)


@dataclass(frozen=True)
class DiscoveredImage:
    """A single image entry after validation.

    Attributes:
        name: Registry short name (matches the image short_name in ACR).
        dockerfile_path: Path to the Dockerfile, repo-root-relative.
        context: Build context directory, repo-root-relative.
    """

    name: str
    dockerfile_path: str
    context: str

    @auto_trace(logger)
    def to_dict(self) -> dict:
        """Serialize to the JSON-schema dict used by CI consumers."""
        return {
            "name": self.name,
            "dockerfile_path": self.dockerfile_path,
            "context": self.context,
        }


@auto_trace(logger)
def load_docker_images(repo_root: Path) -> List[DiscoveredImage]:
    """Load and validate the `docker_images` section of build.yaml.

    Args:
        repo_root: Absolute path to the repository root containing build.yaml.

    Returns:
        List of DiscoveredImage in the order they appear in build.yaml.
        Order is deterministic: YAML preserves insertion order via PyYAML.

    Raises:
        FileNotFoundError: build.yaml is missing.
        ValueError: docker_images is missing/empty or any entry is malformed.
    """
    config_path = repo_root / "build.yaml"
    if not config_path.is_file():
        raise FileNotFoundError(
            f"build.yaml not found at {config_path}. "
            f"discover_docker_images.py requires a valid build.yaml to operate."
        )

    with open(config_path, "r") as fh:
        raw = yaml.safe_load(fh)

    if not raw:
        raise ValueError(f"build.yaml at {config_path} is empty")

    entries = raw.get("docker_images")
    if not entries:
        raise ValueError(
            "build.yaml missing required 'docker_images' section "
            "(or it is empty). Add one entry per Dockerfile with "
            "name, dockerfile_path, and context keys."
        )

    if not isinstance(entries, list):
        raise ValueError(
            f"build.yaml 'docker_images' must be a list, got "
            f"{type(entries).__name__}"
        )

    result: List[DiscoveredImage] = []
    seen_names: set[str] = set()

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"docker_images[{idx}] must be a mapping, got "
                f"{type(entry).__name__}"
            )

        for key in ("name", "dockerfile_path", "context"):
            if key not in entry:
                raise ValueError(
                    f"docker_images[{idx}] missing required key '{key}'. "
                    f"Entry keys: {sorted(entry.keys())}"
                )
            if not isinstance(entry[key], str) or not entry[key]:
                raise ValueError(
                    f"docker_images[{idx}] '{key}' must be a non-empty "
                    f"string, got: {entry[key]!r}"
                )

        name = entry["name"]
        dockerfile_path = entry["dockerfile_path"]
        context = entry["context"]

        if name in seen_names:
            raise ValueError(
                f"docker_images[{idx}] duplicate image name {name!r}. "
                f"Each image name must be unique."
            )
        seen_names.add(name)

        absolute_dockerfile = repo_root / dockerfile_path
        if not absolute_dockerfile.is_file():
            raise ValueError(
                f"docker_images[{idx}] name={name!r}: Dockerfile not found "
                f"at {absolute_dockerfile}. dockerfile_path must resolve "
                f"to an existing file relative to the repo root."
            )

        absolute_context = repo_root / context
        if not absolute_context.is_dir():
            raise ValueError(
                f"docker_images[{idx}] name={name!r}: context directory "
                f"not found at {absolute_context}. context must resolve "
                f"to an existing directory relative to the repo root."
            )

        result.append(
            DiscoveredImage(
                name=name,
                dockerfile_path=dockerfile_path,
                context=context,
            )
        )

    return result


@auto_trace(logger)
def emit(images: List[DiscoveredImage], output: Optional[Path]) -> None:
    """Serialize images as JSON and write to stdout or the given path.

    Args:
        images: Sequence of validated images to emit.
        output: Optional path to write JSON to. If None, writes to stdout.
    """
    payload = [img.to_dict() for img in images]
    text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text, encoding="utf-8")


@auto_trace(logger)
def main() -> int:
    """CLI entry point.

    Returns:
        0 on success; 1 on validation/IO errors.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Emit docker_images from build.yaml as structured JSON. "
            "Fails non-zero on missing/malformed configuration."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_REPO_ROOT_DEFAULT,
        help="Repository root containing build.yaml (default: derived from script path)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON to this path instead of stdout",
    )
    args = parser.parse_args()

    try:
        images = load_docker_images(args.repo_root)
    except (FileNotFoundError, ValueError) as exc:
        display.error(str(exc))
        return 1

    emit(images, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
