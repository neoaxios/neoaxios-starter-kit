# neoaxios-config

Shared configuration infrastructure for NeoAxios packages. Provides a
hierarchical YAML loader with documented override precedence, deep-merge
semantics, and environment-variable substitution.

## Install

```bash
pip install neoaxios-config
```

Requires Python 3.8+. Depends on `pyyaml>=5.1` and `neoaxios-logging>=1.1.0`.

## What it provides

| Symbol | Purpose |
|---|---|
| `ConfigLoader` | Loads a named component's config by walking the override hierarchy and deep-merging the layers in precedence order. |
| `ConfigPathResolver` | Resolves the canonical paths for system / user / project / environment-specific / local-override config files. |
| `HierarchicalSettings` | Pydantic-friendly settings wrapper for accessing merged config. |
| `apply_env_overrides_recursive` | Walks a nested dict and substitutes any `${VAR}` references with environment-variable values. |
| `expand_env_vars`, `yaml_path_to_env_var`, `convert_value` | Lower-level helpers for env-var substitution. |
| `deep_merge`, `merge_multiple` | Recursive YAML merge utilities (later layers override earlier). |

## Override precedence

Highest priority wins. Each layer that exists is merged on top of all lower
layers; missing layers are skipped.

1. Environment variables (`NEO_<COMPONENT>_<KEY>=value`)
2. Explicit override path (passed at runtime)
3. Local developer overrides (`./.neoaxios.local.yaml`, gitignored)
4. Environment-specific (`./config/environments/${NEO_ENV}/<component>.yaml`)
5. Project workspace (`./config/packages/<component>.yaml`)
6. User config (`~/.config/neoaxios/<component>.yaml`)
7. System-wide config (`/etc/neoaxios/<component>.yaml`)
8. Bundled defaults (shipped inside each package's wheel)

## Quickstart

```python
from pathlib import Path
from neoaxios_config import ConfigLoader

loader = ConfigLoader("logging")
merged = loader.load(bundled_defaults_path=Path("defaults.yaml"))
print(merged["level"])
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
