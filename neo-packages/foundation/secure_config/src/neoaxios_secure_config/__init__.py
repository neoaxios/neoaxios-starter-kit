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

"""secure_config - Security-hardened configuration for sensitive settings.

A configuration package that uses JSON and YAML formats with file-driven value
sources for maximum simplicity and auditability. Supports multiple independent
component configurations within a single process.

## Terminology

- **Component**: A named unit within your application that requires configuration
  (e.g., "auth", "database", "cache"). Each component has exactly one configuration.
- **Configuration**: The validated settings for a component, loaded from a JSON file.
- **Schema**: A Pydantic model that defines the structure and validation rules for
  a component's configuration.

Example:
    ```python
    from pathlib import Path
    from neoaxios_secure_config import register_config, get_config, SecureSchema, Field, SecretStr

    class AuthConfig(SecureSchema):
        tenant_id: str = Field(description="Azure AD tenant")
        client_secret: SecretStr = Field(description="Client credential")
        cache_ttl: int = Field(default=300)

    # Register configuration for the "auth" component
    register_config("auth", Path("/etc/myapp/auth.json"), AuthConfig)

    # Retrieve the auth component's configuration anywhere in your code
    config = get_config("auth")

    # Access secret value explicitly (prevents accidental logging):
    secret = config.client_secret.get_secret_value()

    # Safe for logging - automatically masked:
    print(config.client_secret)  # Output: **********
    ```

Config file example (`/etc/myapp/auth.json`):
    ```json
    {
        "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
        "client_secret": "env:AZURE_CLIENT_SECRET",
        "cache_ttl": 300
    }
    ```

Value source syntax:
    - `"literal"` - Use as-is
    - `"env:VAR_NAME"` - Read from environment variable
    - `"file:///path"` - Read from file with permission validation
"""

from neoaxios_secure_config.errors import (
    ComponentExistsError,
    ComponentNotFoundError,
    ConfigDriftError,
    ConfigNotFoundError,
    ConfigParseError,
    ConfigPermissionError,
    ConfigResolutionError,
    ConfigValidationError,
    NoPreviousConfigError,
    SecureConfigError,
)
from neoaxios_secure_config.loader import LoadedConfig, load_secure_config, load_secure_config_with_env, load_yaml
from neoaxios_secure_config.resolver import DEFAULT_ALLOWED_DIRS, extract_env_vars, resolve_value
from neoaxios_secure_config.registry import (
    ConfigInfo,
    LoaderCallback,
    ReloadResult,
    ensure_registered,
    ensure_registered_with_loader,
    get_config,
    get_config_info,
    get_config_or_none,
    get_extracted_env_vars,
    has_previous_config,
    list_components,
    register_config,
    register_config_with_loader,
    reload_config,
    rollback_config,
)
from neoaxios_secure_config.schema import ExtractedEnvVars, Field, ResolvableModel, SecretStr, SecureSchema, mask_secrets_in_model
from neoaxios_secure_config.runtime import (
    GpuStatus,
    SystemResources,
    calculate_app_budget,
    calculate_recommended_workers,
    detect_gpu,
    detect_system_resources,
    get_app_ram_budget_gb,
    get_cpu_logical_count,
    get_cpu_physical_count,
    get_ram_available_gb,
    get_ram_total_gb,
    get_recommended_workers,
    log_app_budget,
    log_runtime_detection,
    log_system_resources,
)
from neoaxios_secure_config.docker_compose_validator import (
    ValidationResult,
    validate_ram_shares,
)

__version__ = "0.2.1"

__all__ = [
    # Schema
    "SecureSchema",
    "ResolvableModel",
    "SecretStr",
    "Field",
    "ExtractedEnvVars",
    "mask_secrets_in_model",
    # Registry API
    "register_config",
    "register_config_with_loader",
    "ensure_registered",
    "ensure_registered_with_loader",
    "get_config",
    "get_config_or_none",
    "reload_config",
    "rollback_config",
    "has_previous_config",
    "list_components",
    "get_config_info",
    "get_extracted_env_vars",
    "ConfigInfo",
    "ReloadResult",
    "LoaderCallback",
    # Direct loading
    "load_secure_config",
    "load_secure_config_with_env",
    "load_yaml",
    "LoadedConfig",
    # Value resolution
    "resolve_value",
    "extract_env_vars",
    "DEFAULT_ALLOWED_DIRS",
    # Errors
    "SecureConfigError",
    "ConfigNotFoundError",
    "ConfigPermissionError",
    "ConfigParseError",
    "ConfigValidationError",
    "ConfigResolutionError",
    "ConfigDriftError",
    "NoPreviousConfigError",
    "ComponentNotFoundError",
    "ComponentExistsError",
    # Runtime resource detection
    "SystemResources",
    "GpuStatus",
    "detect_system_resources",
    "detect_gpu",
    "get_cpu_logical_count",
    "get_cpu_physical_count",
    "get_ram_total_gb",
    "get_ram_available_gb",
    # App budget calculation
    "calculate_app_budget",
    "calculate_recommended_workers",
    "get_app_ram_budget_gb",
    "get_recommended_workers",
    # Startup logging
    "log_system_resources",
    "log_app_budget",
    "log_runtime_detection",
    # Docker Compose validation
    "validate_ram_shares",
    "ValidationResult",
]
