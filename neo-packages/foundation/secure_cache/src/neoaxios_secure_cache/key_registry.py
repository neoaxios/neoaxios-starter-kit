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

"""Central Cache Key Registry.

Provides a thread-safe singleton registry that loads approved Redis key patterns
from per-package YAML configuration files. Each package owns a
``cache-key-registry.yaml`` at its directory root; the loader discovers and
merges every per-package file into one in-memory registry. Used by
ValidatingCacheWrapper (test-only) to reject undeclared keys, and by review
agents to audit key usage.

Usage:
    from neoaxios_secure_cache.key_registry import (
        load_cache_key_registry_from_root,   # primary entrypoint
        load_cache_key_registry,             # single-file (tests / explicit)
        get_cache_key_schema,
        list_cache_keys,
        list_cache_keys_by_component,
    )

    # Discover all per-package cache-key-registry.yaml files under the
    # repository root and merge them.
    load_cache_key_registry_from_root("/path/to/repo")

    # Or, load a single file (tests, smoke):
    load_cache_key_registry("/path/to/cache-key-registry.yaml")

    # Query registered keys
    schema = get_cache_key_schema("auth:permissions")
    all_keys = list_cache_keys()
    auth_keys = list_cache_keys_by_component("neoaxios_fastapi_kit.auth")

"""

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union

import yaml
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)


@dataclass(frozen=True)
class CacheKeySchema:
    """Descriptor for a registered cache key pattern.

    Attributes:
        name: Registry key name (e.g., "auth:permissions")
        pattern: Key pattern template (e.g., "{user_scope}:permissions")
        scope: Scope tier ("user", "tenant", "app", "global")
        component: Owning component (e.g., "neoaxios_fastapi_kit.auth")
        feature: Feature name (e.g., "permissions")
        description: Human-readable description
        ttl_seconds: Default TTL in seconds, or None if TTL is computed
        value_type: String describing the cached value type
    """

    name: str
    pattern: str
    scope: str
    component: str
    feature: str
    description: str
    ttl_seconds: Optional[int] = None
    value_type: str = ""


class CacheKeyRegistry:
    """Thread-safe singleton registry of approved cache key patterns.

    Follows the SecureConfigRegistry pattern: load once, query anywhere.
    The registry is loaded from a YAML file and provides query methods
    for inspecting registered key patterns.
    """

    _instance: Optional["CacheKeyRegistry"] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._schemas: dict[str, CacheKeySchema] = {}
        self._loaded = False

    @classmethod
    @auto_trace(logger)
    def get_instance(cls) -> "CacheKeyRegistry":
        """Get or create the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    @auto_trace(logger)
    def reset(cls) -> None:
        """Reset the singleton (for testing only)."""
        with cls._lock:
            cls._instance = None

    @auto_trace(logger)
    def load_from_file(self, path: str) -> None:
        """Load key patterns from a single YAML registry file.

        Replaces any previously-loaded schemas. Prefer
        :meth:`load_from_files` or :meth:`load_from_root` for the
        per-package model.

        Args:
            path: Path to the cache-key-registry.yaml file

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file has invalid structure
        """
        self._schemas = self._parse_file(Path(path))
        self._loaded = True
        logger.info(
            f"Cache key registry loaded: {len(self._schemas)} patterns from {path}"
        )

    @auto_trace(logger)
    def load_from_files(self, paths: Iterable[Union[str, Path]]) -> None:
        """Load and merge key patterns from multiple per-package files.

        Each file declares the keys owned by one package. Key names must be
        globally unique across all files; a duplicate is treated as a
        declaration conflict (rather than silent override) and raises
        :class:`ValueError`.

        Args:
            paths: Iterable of cache-key-registry.yaml file paths.

        Raises:
            FileNotFoundError: If any file does not exist
            ValueError: If a file has invalid structure or a key name is
                declared in more than one file.
        """
        merged: dict[str, CacheKeySchema] = {}
        origins: dict[str, str] = {}
        n_files = 0
        for raw_path in paths:
            p = Path(raw_path)
            schemas = self._parse_file(p)
            for name, schema in schemas.items():
                if name in merged:
                    raise ValueError(
                        f"Duplicate cache key declaration: {name!r} appears in "
                        f"both {origins[name]} and {p}. Each cache key must be "
                        f"declared in exactly one package's "
                        f"cache-key-registry.yaml."
                    )
                merged[name] = schema
                origins[name] = str(p)
            n_files += 1
        self._schemas = merged
        self._loaded = True
        logger.info(
            f"Cache key registry loaded: {len(merged)} patterns from {n_files} files"
        )

    @auto_trace(logger)
    def load_from_root(self, root: Union[str, Path]) -> None:
        """Discover every per-package ``cache-key-registry.yaml`` under
        ``root`` and merge them into the registry.

        Excludes paths under ``.venv/``, ``build/lib/``, ``node_modules/``,
        and ``.git/``.

        Args:
            root: Repository (or workspace) root to scan.

        Raises:
            FileNotFoundError: If the root path does not exist
            ValueError: If any discovered file is malformed or there is a
                duplicate declaration.
        """
        files = list(self.discover(root))
        self.load_from_files(files)

    @staticmethod
    def discover(root: Union[str, Path]) -> list[Path]:
        """Return per-package cache-key-registry.yaml paths under ``root``.

        Excludes any path under ``.venv/``, ``build/lib/``, ``node_modules/``,
        ``.git/``, or whose basename starts with ``.``.
        """
        root_path = Path(root)
        if not root_path.exists():
            raise FileNotFoundError(f"Cache key registry root not found: {root}")
        excluded = {".venv", "build", "node_modules", ".git", "__pycache__", ".pytest_cache"}
        results: list[Path] = []
        for candidate in root_path.rglob("cache-key-registry.yaml"):
            parts = set(candidate.parts)
            if "build" in parts and "lib" in parts:
                # build/lib/ artifact
                continue
            if any(p in excluded for p in candidate.parts):
                continue
            results.append(candidate)
        return sorted(results)

    @staticmethod
    def _parse_file(registry_path: Path) -> dict[str, "CacheKeySchema"]:
        """Parse one cache-key-registry.yaml file. Returns its schemas."""
        if not registry_path.exists():
            raise FileNotFoundError(
                f"Cache key registry not found: {registry_path}"
            )
        with open(registry_path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "keys" not in data:
            raise ValueError(
                f"Invalid cache key registry format in {registry_path}: "
                "expected top-level 'keys' mapping"
            )
        schemas: dict[str, CacheKeySchema] = {}
        for name, entry in data["keys"].items():
            if not isinstance(entry, dict):
                raise ValueError(
                    f"Invalid entry for key '{name}' in {registry_path}: "
                    f"expected mapping"
                )
            schemas[name] = CacheKeySchema(
                name=name,
                pattern=entry.get("pattern", ""),
                scope=entry.get("scope", ""),
                component=entry.get("component", ""),
                feature=entry.get("feature", ""),
                description=entry.get("description", ""),
                ttl_seconds=entry.get("ttl_seconds"),
                value_type=entry.get("value_type", ""),
            )
        return schemas

    @auto_trace(logger)
    def get(self, name: str) -> Optional[CacheKeySchema]:
        """Get a registered key schema by name.

        Args:
            name: Registry key name (e.g., "auth:permissions")

        Returns:
            CacheKeySchema if found, None otherwise
        """
        return self._schemas.get(name)

    @auto_trace(logger)
    def list_keys(self) -> list[str]:
        """List all registered key names.

        Returns:
            Sorted list of registered key names
        """
        return sorted(self._schemas.keys())

    @auto_trace(logger)
    def list_by_component(self, component: str) -> list[CacheKeySchema]:
        """List all key schemas for a given component.

        Args:
            component: Component name (e.g., "neoaxios_fastapi_kit.auth")

        Returns:
            List of matching CacheKeySchema entries
        """
        return [
            s for s in self._schemas.values()
            if s.component == component
        ]

    @auto_trace(logger)
    def list_by_feature(self, feature: str) -> list[CacheKeySchema]:
        """List all key schemas for a given feature.

        Args:
            feature: Feature name (e.g., "permissions")

        Returns:
            List of matching CacheKeySchema entries
        """
        return [
            s for s in self._schemas.values()
            if s.feature == feature
        ]

    @auto_trace(logger)
    def list_by_scope(self, scope: str) -> list[CacheKeySchema]:
        """List all key schemas for a given scope tier.

        Args:
            scope: Scope tier ("user", "tenant", "app", "global")

        Returns:
            List of matching CacheKeySchema entries
        """
        return [
            s for s in self._schemas.values()
            if s.scope == scope
        ]

    @auto_trace(logger)
    def is_registered(self, name: str) -> bool:
        """Check if a key name is registered.

        Args:
            name: Registry key name

        Returns:
            True if registered
        """
        return name in self._schemas

    @property
    def is_loaded(self) -> bool:
        """Whether the registry has been loaded from a file."""
        return self._loaded

    @property
    def schemas(self) -> list[CacheKeySchema]:
        """Return all registered schemas.

        Returns:
            List of all registered CacheKeySchema entries
        """
        return list(self._schemas.values())

    def __len__(self) -> int:
        return len(self._schemas)


# =============================================================================
# Module-level convenience functions
# =============================================================================


@auto_trace(logger)
def load_cache_key_registry(path: str) -> CacheKeyRegistry:
    """Load the cache key registry from a single YAML file.

    Prefer :func:`load_cache_key_registry_from_root` for the per-package
    model. This entrypoint is kept for tests and explicit one-off loads.

    Args:
        path: Path to the cache-key-registry.yaml file

    Returns:
        The loaded CacheKeyRegistry singleton
    """
    registry = CacheKeyRegistry.get_instance()
    registry.load_from_file(path)
    return registry


@auto_trace(logger)
def load_cache_key_registry_from_root(root: Union[str, Path]) -> CacheKeyRegistry:
    """Discover and load every per-package ``cache-key-registry.yaml``
    under ``root`` into the singleton registry.

    Args:
        root: Repository (or workspace) root to scan.

    Returns:
        The loaded CacheKeyRegistry singleton
    """
    registry = CacheKeyRegistry.get_instance()
    registry.load_from_root(root)
    return registry


@auto_trace(logger)
def get_cache_key_schema(name: str) -> Optional[CacheKeySchema]:
    """Get a registered key schema by name.

    Args:
        name: Registry key name (e.g., "auth:permissions")

    Returns:
        CacheKeySchema if found, None otherwise
    """
    return CacheKeyRegistry.get_instance().get(name)


@auto_trace(logger)
def list_cache_keys() -> list[str]:
    """List all registered key names.

    Returns:
        Sorted list of registered key names
    """
    return CacheKeyRegistry.get_instance().list_keys()


@auto_trace(logger)
def list_cache_keys_by_component(component: str) -> list[CacheKeySchema]:
    """List all key schemas for a given component.

    Args:
        component: Component name (e.g., "neoaxios_fastapi_kit.auth")

    Returns:
        List of matching CacheKeySchema entries
    """
    return CacheKeyRegistry.get_instance().list_by_component(component)


__all__ = [
    "CacheKeySchema",
    "CacheKeyRegistry",
    "load_cache_key_registry",
    "load_cache_key_registry_from_root",
    "get_cache_key_schema",
    "list_cache_keys",
    "list_cache_keys_by_component",
]
