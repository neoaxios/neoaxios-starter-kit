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

"""Exception hierarchy for secure_config.

All exceptions inherit from SecureConfigError for easy catching.
"""

from typing import Optional


class SecureConfigError(Exception):
    """Base exception for all secure_config errors."""

    pass


class ConfigNotFoundError(SecureConfigError):
    """Configuration file not found at specified path."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Configuration file not found: {path}")


class ConfigPermissionError(SecureConfigError):
    """Configuration file has insecure permissions."""

    def __init__(self, message: str, path: Optional[str] = None) -> None:
        self.path = path
        super().__init__(message)


class ConfigParseError(SecureConfigError):
    """Failed to parse configuration file."""

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Failed to parse config at {path}: {detail}")


class ConfigValidationError(SecureConfigError):
    """Configuration failed schema validation."""

    def __init__(self, message: str, errors: Optional[list] = None) -> None:
        self.errors = errors or []
        super().__init__(message)


class ConfigResolutionError(SecureConfigError):
    """Failed to resolve value source (env: or file://)."""

    def __init__(self, message: str, field: Optional[str] = None, source: Optional[str] = None) -> None:
        self.field = field
        self.source = source
        super().__init__(message)


class ComponentNotFoundError(SecureConfigError):
    """Requested component not registered in registry."""

    def __init__(self, component: str, available: Optional[list[str]] = None) -> None:
        self.component = component
        self.available = available or []
        msg = f"Component '{component}' not registered"
        if self.available:
            msg += f". Available: {', '.join(self.available)}"
        super().__init__(msg)


class ComponentExistsError(SecureConfigError):
    """Component already registered in registry."""

    def __init__(self, component: str) -> None:
        self.component = component
        super().__init__(f"Component '{component}' already registered")


class ConfigDriftError(SecureConfigError):
    """Static configuration field changed during reload.

    Raised when drift_policy="block" and a non-refreshable field
    has a different value in the new configuration.
    """

    def __init__(
        self,
        component: str,
        field: str,
        old_value: str,
        new_value: str,
    ) -> None:
        self.component = component
        self.field = field
        self.old_value = old_value
        self.new_value = new_value
        super().__init__(
            f"Configuration drift detected for component '{component}': "
            f"static field '{field}' changed from '{old_value}' to '{new_value}'. "
            f"Static fields cannot change during reload. "
            f"Use drift_policy='warn' or 'allow' to permit this change."
        )


class NoPreviousConfigError(SecureConfigError):
    """No previous configuration available for rollback."""

    def __init__(self, component: str) -> None:
        self.component = component
        super().__init__(
            f"No previous configuration available for component '{component}'. "
            f"Rollback requires a prior reload_config() call."
        )
