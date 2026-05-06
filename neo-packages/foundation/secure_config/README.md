# neoaxios-secure-config

Security-hardened configuration for sensitive settings. Uses JSON and YAML formats
with file-driven value sources for simplicity and auditability, and supports
multiple independent component configurations within a single process.

## Install

```bash
pip install neoaxios-secure-config
```

Requires Python 3.10+. Depends on `pydantic>=2.0`, `neoaxios-logging>=1.1.0`, and
`pyyaml>=6.0`.

## Concepts

- **Component** — a named unit within your application that requires configuration
  (e.g. `auth`, `database`, `cache`). Each component has exactly one configuration.
- **Configuration** — the validated settings for a component, loaded from a JSON or
  YAML file.
- **Schema** — a Pydantic model that defines the structure and validation rules for
  a component's configuration.

## Quickstart

```python
from pathlib import Path
from neoaxios_secure_config import register_config, get_config, SecureSchema, Field, SecretStr

class AuthConfig(SecureSchema):
    tenant_id: str = Field(description="Azure AD tenant")
    client_secret: SecretStr = Field(description="Client credential")
    cache_ttl: int = Field(default=300)

# Register configuration for the "auth" component
register_config("auth", Path("/etc/myapp/auth.json"), AuthConfig)

# Retrieve the configuration anywhere in your code
config = get_config("auth")

# Access the secret explicitly (prevents accidental logging)
secret = config.client_secret.get_secret_value()

# Safe for logging — automatically masked
print(config.client_secret)  # **********
```

Config file (`/etc/myapp/auth.json`):

```json
{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "client_secret": "env:AZURE_CLIENT_SECRET",
    "cache_ttl": 300
}
```

## Value source syntax

Within a config file, scalar values can be one of:

| Form | Meaning |
|---|---|
| `"literal"` | Use as-is. |
| `"env:VAR_NAME"` | Read from the environment variable `VAR_NAME`. |
| `"file:///path"` | Read the file's contents (with permission validation). |

Resolution is performed at config-load time and is TOCTOU-safe (the file path is
opened once and read from the open handle).

## Modules

| Module | Purpose |
|---|---|
| `secure_config.schema` | `SecureSchema`, `ResolvableModel`, `SecretStr`, `mask_secrets_in_model`. |
| `secure_config.loader` | `load_secure_config`, `load_secure_config_with_env`, `load_yaml`. |
| `secure_config.resolver` | `resolve_value`, `extract_env_vars`, `DEFAULT_ALLOWED_DIRS`. |
| `secure_config.registry` | Per-component registration, retrieval, reload, and rollback. |
| `secure_config.runtime` | Detects CPU, RAM, and GPU resources; computes worker budgets. |
| `secure_config.docker_compose_validator` | Validates RAM-share declarations in `docker-compose.yml`. |
| `secure_config.errors` | Exception hierarchy rooted at `SecureConfigError`. |

## License

Apache License 2.0. See [LICENSE](LICENSE).
