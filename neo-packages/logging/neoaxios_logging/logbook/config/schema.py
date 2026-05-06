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

"""
Logbook Configuration Schema

Defines the configuration data classes for Logbook, including:
- Log level configuration (per-component levels)
- Output configuration (file handlers, buffering, rotation)
- Processor configuration (callsite, exceptions, unicode)
- Filter configuration (pattern-based filtering)
- Flush policies
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

from neoaxios_logging.common.types import LogLevel


class BufferMode(Enum):
    """Buffer modes for file output."""
    WRITE_THROUGH = "write_through"
    LINE_BUFFERED = "line_buffered"
    SMALL = "small_buffer"
    DEFAULT = "default_buffer"
    LARGE = "large_buffer"
    UNBOUNDED = "unbounded"


class RotationType(Enum):
    """File rotation types."""
    SIZE = "size"
    TIME = "time"
    HYBRID = "hybrid"


@dataclass
class CallsiteConfig:
    """Configuration for automatic source location tracking."""
    enabled: bool = True
    parameters: List[str] = field(default_factory=lambda: ["filename", "func_name", "lineno"])
    additional_ignores: List[str] = field(default_factory=lambda: ["telemetry.logbook"])


@dataclass
class ExceptionConfig:
    """Configuration for exception rendering."""
    format: str = "dict"  # or "string" for legacy
    include_locals: bool = False
    include_chain: bool = True
    max_frames: int = 50


@dataclass
class UnicodeConfig:
    """Configuration for unicode safety."""
    encoding: str = "utf-8"
    errors: str = "replace"  # or "ignore", "strict"
    fallback_encoding: str = "latin-1"


@dataclass
class RotationConfig:
    """Configuration for log file rotation."""
    type: RotationType = RotationType.SIZE
    max_bytes: int = 100 * 1024 * 1024  # 100MB
    backup_count: int = 10
    when: str = "midnight"  # For time-based rotation
    interval: int = 1
    compress: Optional[str] = None  # "gzip", "bz2", "xz", or None


@dataclass
class FlushPolicyConfig:
    """Configuration for buffer flush policies."""
    on_error: bool = True
    on_warning: bool = False
    on_interval: int = 5  # seconds, 0 = disabled
    on_buffer_full: bool = True
    on_exit: bool = True
    on_signal: Optional[str] = None  # e.g., "SIGUSR1"


@dataclass
class OutputConfig:
    """Configuration for a single output destination."""
    name: str
    type: str = "file"  # or "stream"
    path: Optional[str] = None
    level: LogLevel = LogLevel.ERROR
    components: str = "*"  # Component filter pattern
    buffer_mode: BufferMode = BufferMode.DEFAULT
    buffer_size: Optional[int] = None  # Custom buffer size in bytes
    flush_policy: FlushPolicyConfig = field(default_factory=FlushPolicyConfig)
    rotation: RotationConfig = field(default_factory=RotationConfig)
    format: str = "json"  # "json", "logfmt", "console"
    stream: str = "stderr"  # For stream type
    permissions: int = 0o640
    sanitize_enabled: bool = False
    sanitize_patterns: List[str] = field(default_factory=list)


@dataclass
class FilterRule:
    """Configuration for a single filter rule."""
    component: str
    level: Optional[LogLevel] = None
    message_pattern: Optional[str] = None
    action: str = "drop"  # or "keep"


@dataclass
class FieldMapping:
    """Configuration for field name mapping."""
    preset: str = "none"  # "datadog", "grafana", "elk", "custom", "none"
    custom_mappings: Dict[str, str] = field(default_factory=dict)


@dataclass
class LogbookConfig:
    """
    Main configuration for Logbook.

    This is the primary configuration object loaded from telemetry.yaml or
    constructed programmatically.
    """

    # Log level configuration
    level: LogLevel = LogLevel.ERROR
    component_levels: Dict[str, LogLevel] = field(default_factory=dict)

    # Output configuration
    outputs: List[OutputConfig] = field(default_factory=list)

    # Processor configuration
    callsite: CallsiteConfig = field(default_factory=CallsiteConfig)
    exceptions: ExceptionConfig = field(default_factory=ExceptionConfig)
    unicode: UnicodeConfig = field(default_factory=UnicodeConfig)

    # Filter configuration
    filters: List[FilterRule] = field(default_factory=list)

    # Field mapping
    field_mapping: FieldMapping = field(default_factory=FieldMapping)

    # Presets
    presets: Dict[str, Dict[str, LogLevel]] = field(default_factory=dict)

    # Feature flags
    enabled: bool = True
    console_enabled: bool = False

    # Legacy compatibility
    log_dir: str = ".telemetry"
    log_file: str = "telemetry.log"
    format: str = "json"

    def get_component_level(self, component: str) -> LogLevel:
        """
        Get the minimum log level for a component.

        Uses hierarchical matching:
        1. Exact match
        2. Wildcard prefix match (longest first)
        3. Base level
        """
        # Exact match
        if component in self.component_levels:
            return self.component_levels[component]

        # Wildcard prefix match (longest prefix wins)
        matches = []
        for pattern, lvl in self.component_levels.items():
            if pattern.endswith("*"):
                prefix = pattern[:-1]  # Remove trailing *
                if component.startswith(prefix):
                    matches.append((len(prefix), lvl))
            elif pattern.endswith(".*"):
                prefix = pattern[:-2]  # Remove trailing .*
                if component.startswith(prefix + ".") or component == prefix:
                    matches.append((len(prefix), lvl))

        if matches:
            # Return level with longest matching prefix
            matches.sort(key=lambda x: x[0], reverse=True)
            return matches[0][1]

        # Base level
        return self.level

    def load_preset(self, preset_name: str) -> None:
        """
        Load a preset configuration.

        Presets are predefined level configurations (e.g., development, production, troubleshooting).
        """
        if preset_name not in self.presets:
            raise ValueError(f"Unknown preset: {preset_name}")

        preset = self.presets[preset_name]
        self.component_levels.update(preset)

        # Apply wildcard level to base level if present
        if "*" in preset:
            self.level = preset["*"]

        # Enable console for development preset
        if preset_name == "development":
            self.console_enabled = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary format."""
        from dataclasses import asdict
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogbookConfig":
        """Create configuration from dictionary."""
        # Ensure presets are always present
        if "presets" not in data:
            data["presets"] = {
                "development": {"*": LogLevel.DEBUG},
                "production": {"*": LogLevel.ERROR},
                "troubleshooting": {"*": LogLevel.ERROR}
            }

        # Convert string log levels to LogLevel enum
        if "level" in data and isinstance(data["level"], str):
            try:
                data["level"] = LogLevel[data["level"].upper()]
            except KeyError:
                valid_levels = [level.name for level in LogLevel]
                raise ValueError(
                    f"Invalid logbook.level: {data['level']}. "
                    f"Must be one of: {', '.join(valid_levels)}"
                )

        if "component_levels" in data:
            component_levels = {}
            for component, lvl in data["component_levels"].items():
                if isinstance(lvl, str):
                    try:
                        component_levels[component] = LogLevel[lvl.upper()]
                    except KeyError:
                        valid_levels = [level.name for level in LogLevel]
                        raise ValueError(
                            f"Invalid log level for component '{component}': {lvl}. "
                            f"Must be one of: {', '.join(valid_levels)}"
                        )
                else:
                    component_levels[component] = lvl
            data["component_levels"] = component_levels

        if "presets" in data:
            presets = {}
            for preset_name, preset_levels in data["presets"].items():
                preset = {}
                for component, level in preset_levels.items():
                    if isinstance(level, str):
                        try:
                            preset[component] = LogLevel[level.upper()]
                        except KeyError:
                            valid_levels = [level.name for level in LogLevel]
                            raise ValueError(
                                f"Invalid log level in preset '{preset_name}' for component '{component}': {level}. "
                                f"Must be one of: {', '.join(valid_levels)}"
                            )
                    else:
                        preset[component] = level
                presets[preset_name] = preset
            data["presets"] = presets

        # Convert outputs
        if "outputs" in data:
            outputs = []
            for output_data in data["outputs"]:
                # Convert enums
                if "level" in output_data and isinstance(output_data["level"], str):
                    output_data["level"] = LogLevel[output_data["level"].upper()]
                if "buffer_mode" in output_data and isinstance(output_data["buffer_mode"], str):
                    output_data["buffer_mode"] = BufferMode(output_data["buffer_mode"])

                # Convert nested configs
                if "rotation" in output_data and isinstance(output_data["rotation"], dict):
                    rotation_data = output_data["rotation"]
                    if "type" in rotation_data and isinstance(rotation_data["type"], str):
                        rotation_data["type"] = RotationType(rotation_data["type"])
                    output_data["rotation"] = RotationConfig(**rotation_data)

                if "flush_policy" in output_data and isinstance(output_data["flush_policy"], dict):
                    output_data["flush_policy"] = FlushPolicyConfig(**output_data["flush_policy"])

                outputs.append(OutputConfig(**output_data))
            data["outputs"] = outputs

        # Convert nested configs
        if "callsite" in data and isinstance(data["callsite"], dict):
            data["callsite"] = CallsiteConfig(**data["callsite"])

        if "exceptions" in data and isinstance(data["exceptions"], dict):
            data["exceptions"] = ExceptionConfig(**data["exceptions"])

        if "unicode" in data and isinstance(data["unicode"], dict):
            data["unicode"] = UnicodeConfig(**data["unicode"])

        if "field_mapping" in data and isinstance(data["field_mapping"], dict):
            data["field_mapping"] = FieldMapping(**data["field_mapping"])

        if "filters" in data:
            filters = []
            for filter_data in data["filters"]:
                if "level" in filter_data and isinstance(filter_data["level"], str):
                    filter_data["level"] = LogLevel[filter_data["level"].upper()]
                filters.append(FilterRule(**filter_data))
            data["filters"] = filters

        return cls(**data)

    @classmethod
    def create_default(cls) -> "LogbookConfig":
        """Create default configuration."""
        return cls(
            level=LogLevel.ERROR,
            presets={
                "development": {
                    "*": LogLevel.DEBUG
                },
                "production": {
                    "*": LogLevel.ERROR
                },
                "troubleshooting": {
                    "*": LogLevel.ERROR
                }
            }
        )
