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

"""Test-only cache key validation wrapper.

Wraps any CacheBackend to validate that all cache keys are declared in the
Central Cache Key Registry. Zero production overhead — this module is only
imported in test environments.

Usage:
    from neoaxios_secure_cache.testing.validation import ValidatingCacheWrapper
    from neoaxios_secure_cache.key_registry import CacheKeyRegistry

    registry = CacheKeyRegistry()
    # Discover every per-package cache-key-registry.yaml under the repo root
    # and merge them into a single in-memory registry.
    registry.load_from_root("/path/to/repo")

    wrapper = ValidatingCacheWrapper(inner=memory_backend, registry=registry)
    await wrapper.set("undeclared:key", value, ttl_seconds=60)
    # Raises CacheKeyNotRegisteredError

Enforcement layers:
    1. Test-time: ValidatingCacheWrapper wraps backends — undeclared keys fail tests
    2. Architecture: Key builder functions are the public API
    3. Review agents: Detect raw key string construction in code review

"""

from typing import Any, Optional

from neoaxios_logging import TraceDisabledReason, auto_trace, get_telemetry

from neoaxios_secure_cache.key_registry import CacheKeyRegistry
from neoaxios_secure_cache.protocols import CacheBackend

logger = get_telemetry(__name__)


class CacheKeyNotRegisteredError(Exception):
    """Raised when a cache key does not match any registered pattern.

    This error indicates a test is using a cache key that hasn't been declared
    in any package's cache-key-registry.yaml. Fix by either:
    1. Adding the key pattern to the owning package's registry (preferred)
    2. Using a registered key builder function from the appropriate domain module
    """

    def __init__(self, key: str, context: str = ""):
        self.key = key
        msg = f"Cache key not registered: {key!r}"
        if context:
            msg += f" ({context})"
        super().__init__(msg)


class ValidatingCacheWrapper:
    """Test-only wrapper that validates cache keys against the registry.

    Wraps a CacheBackend and intercepts all operations to verify that keys
    match registered patterns. Raises CacheKeyNotRegisteredError for
    undeclared keys.

    The registry MUST be loaded before constructing this wrapper. Passing
    an unloaded registry raises ValueError immediately — no silent passthrough.

    This wrapper implements the CacheBackend protocol by delegation, so it
    can be used as a drop-in replacement in test fixtures.

    Args:
        inner: The actual CacheBackend to delegate to
        registry: CacheKeyRegistry with loaded key patterns (must be loaded)

    Raises:
        ValueError: If registry is not loaded
    """

    def __init__(self, inner: CacheBackend, registry: CacheKeyRegistry) -> None:
        if not registry.is_loaded:
            raise ValueError(
                "ValidatingCacheWrapper requires a loaded CacheKeyRegistry. "
                "Call registry.load_from_file() before constructing the wrapper."
            )
        self._inner = inner
        self._registry = registry
        # Compile match plans once at init (no per-call _build_matchers)
        (
            self._scoped_features,
            self._has_prefix_patterns,
            self._global_matchers,
            self._domain_names,
            self._domain_suffix_matchers,
        ) = self._build_matchers()

    # Minimum segments for any scoped key: CacheNamespace.base() produces 9
    # segments (org:X:env:X:svc:X:app:X:version), plus at least 1 feature.
    _MIN_SCOPED_SEGMENTS = 10

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _build_matchers(
        self,
    ) -> tuple[
        dict[str, tuple[int, str]],
        bool,
        list[tuple[int, dict[int, str]]],
        set[str],
        dict[str, list[tuple[int, dict[int, str], bool]]],
    ]:
        """Build match structures from the registry schemas.

        Returns:
            Tuple of (scoped_features, has_prefix_patterns, global_matchers,
            domain_names, domain_suffix_matchers):
            - scoped_features: feature_name -> (trailing_segments, scope)
            - has_prefix_patterns: whether any "prefix" features exist
            - global_matchers: list of (segment_count, {position: literal})
            - domain_names: set of registered domain names from domain-scoped entries
            - domain_suffix_matchers: domain_name -> list of
              (suffix_segment_count, {position: literal}, exact_match)
        """
        scoped_features: dict[str, tuple[int, str]] = {}
        has_prefix_patterns = False
        global_matchers: list[tuple[int, dict[int, str]]] = []
        domain_names: set[str] = set()
        domain_suffix_matchers: dict[str, list[tuple[int, dict[int, str], bool]]] = {}

        for schema in self._registry.schemas:
            if schema.scope in ("user", "tenant", "app"):
                if schema.feature == "prefix":
                    has_prefix_patterns = True
                    continue
                self._extract_scoped_feature(schema.pattern, schema.scope, scoped_features)
            elif schema.scope == "domain":
                # Registry key name convention: "{domain}:{feature}"
                # e.g. "ratelimit:sliding_window" → domain = "ratelimit"
                domain_name = schema.name.split(":")[0]
                domain_names.add(domain_name)
                # Extract suffix pattern for structural validation
                suffix = self._extract_domain_suffix(schema.pattern)
                if suffix is not None:
                    suffix_parts = suffix.split(":")
                    suffix_literals = {
                        i: part
                        for i, part in enumerate(suffix_parts)
                        if not (part.startswith("{") and part.endswith("}"))
                    }
                    # If last segment is a literal, require exact count;
                    # if last is a variable, allow trailing segments (minimum count)
                    last_is_literal = not (
                        suffix_parts[-1].startswith("{")
                        and suffix_parts[-1].endswith("}")
                    )
                    if domain_name not in domain_suffix_matchers:
                        domain_suffix_matchers[domain_name] = []
                    domain_suffix_matchers[domain_name].append(
                        (len(suffix_parts), suffix_literals, last_is_literal)
                    )
            elif schema.scope == "global":
                pattern_parts = schema.pattern.split(":")
                literals = {
                    i: part for i, part in enumerate(pattern_parts)
                    if not (part.startswith("{") and part.endswith("}"))
                }
                global_matchers.append((len(pattern_parts), literals))

        return (
            scoped_features,
            has_prefix_patterns,
            global_matchers,
            domain_names,
            domain_suffix_matchers,
        )

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _extract_scoped_feature(
        pattern: str,
        scope: str,
        scoped_features: dict[str, tuple[int, str]],
    ) -> None:
        """Extract a scoped feature from a pattern template.

        Parses patterns like ``{user_scope}:permissions`` to extract the
        feature segment name and trailing segment count.

        Args:
            pattern: Key pattern template
            scope: Scope tier (user, tenant, app)
            scoped_features: Dict to update with extracted feature
        """
        if not (pattern.startswith("{") and "}" in pattern):
            return
        after_scope = pattern.split("}", 1)[1]
        if not after_scope.startswith(":"):
            return
        tail_parts = after_scope[1:].split(":")
        feature_segment = tail_parts[0]
        if feature_segment:
            trailing = len(tail_parts) - 1
            scoped_features[feature_segment] = (trailing, scope)

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _match_scoped_key(
        key: str,
        parts: list[str],
        scoped_features: dict[str, tuple[int, str]],
    ) -> bool:
        """Check if a scoped key matches any registered feature pattern.

        Validates both positive constraints (required markers for a scope)
        and negative constraints (forbidden markers for a scope):
        - app-scoped keys must NOT contain ``:t:`` or ``:u:`` markers
        - tenant-scoped keys must contain ``:t:`` but NOT ``:u:``
        - user-scoped keys must contain both ``:t:`` and ``:u:``

        Args:
            key: Full cache key string
            parts: Key split by ':'
            scoped_features: feature_name -> (trailing_segments, scope)

        Returns:
            True if the key matches a registered scoped pattern
        """
        if ":env:" not in key or ":svc:" not in key:
            return False
        for feature, (trailing, scope) in scoped_features.items():
            pos = len(parts) - 1 - trailing
            if pos < 0 or parts[pos] != feature:
                continue
            # Positive: user-scoped features require :u: marker
            if scope == "user" and ":u:" not in key:
                continue
            # Positive: user/tenant-scoped features require :t: marker
            if scope in ("user", "tenant") and ":t:" not in key:
                continue
            # Negative: app-scoped features must NOT have tenant/user markers
            if scope == "app" and (":t:" in key or ":u:" in key):
                continue
            # Negative: tenant-scoped features must NOT have user markers
            if scope == "tenant" and ":u:" in key:
                continue
            return True
        return False

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _match_global_key(
        parts: list[str],
        global_matchers: list[tuple[int, dict[int, str]]],
    ) -> bool:
        """Check if a global key matches any registered pattern.

        Args:
            parts: Key split by ':'
            global_matchers: list of (segment_count, {position: literal})

        Returns:
            True if the key matches a registered global pattern
        """
        for expected_count, literals in global_matchers:
            if len(parts) != expected_count:
                continue
            if all(parts[pos] == lit for pos, lit in literals.items()):
                return True
        return False

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _extract_domain_suffix(pattern: str) -> str | None:
        """Extract the suffix portion of a domain-scoped pattern.

        Parses patterns like ``{domain_scope}:cache:{cache_key}`` to yield
        ``cache:{cache_key}``.

        Args:
            pattern: Full key pattern from registry

        Returns:
            Suffix string after ``{domain_scope}:``, or None if pattern
            doesn't follow the expected format.
        """
        prefix = "{domain_scope}:"
        if pattern.startswith(prefix):
            return pattern[len(prefix):]
        return None

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _resolve_namespace_structure(
        key: str,
        parts: list[str],
    ) -> tuple[str, list[str]] | None:
        """Validate namespace structure and extract domain name and suffix.

        Verifies that the key has valid structural labels (org, env, svc, app,
        optionally div) at the correct positions and that ``:d:`` appears at
        the expected position. Returns the domain name and suffix segments if
        valid, or None if the structure is invalid.

        Args:
            key: Full cache key string
            parts: Key split by ':'

        Returns:
            Tuple of (domain_name, suffix_parts) if structure is valid,
            None otherwise.
        """
        if ":env:" not in key or ":svc:" not in key:
            return None

        has_division = len(parts) > 2 and parts[2] == "div"
        if has_division:
            d_label_pos = 11
            required_labels = ((0, "org"), (2, "div"), (4, "env"), (6, "svc"), (8, "app"))
        else:
            d_label_pos = 9
            required_labels = ((0, "org"), (2, "env"), (4, "svc"), (6, "app"))

        for pos, label in required_labels:
            if len(parts) <= pos or parts[pos] != label:
                return None

        if len(parts) < d_label_pos + 2:
            return None

        if parts[d_label_pos] != "d":
            return None

        domain_name = parts[d_label_pos + 1]
        suffix_parts = parts[d_label_pos + 2:]
        if not suffix_parts:
            return None

        return domain_name, suffix_parts

    @staticmethod
    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _match_domain_key(
        key: str,
        parts: list[str],
        domain_names: set[str],
        domain_suffix_matchers: dict[str, list[tuple[int, dict[int, str], bool]]],
    ) -> bool:
        """Check if a domain-scoped key matches a registered domain pattern.

        Domain-scoped keys have the structure:
            org:{org}[:div:{div}]:env:{env}:svc:{svc}:app:{app}:{version}:d:{domain}:{suffix...}

        The ``:d:`` label must appear at the exact structural position after the
        version segment. The domain name must be registered, and the suffix
        after the domain must match a registered suffix pattern (segment count
        and literal positions).

        Args:
            key: Full cache key string
            parts: Key split by ':'
            domain_names: Set of registered domain names
            domain_suffix_matchers: domain -> list of (count, literals, exact)

        Returns:
            True if the key matches a registered domain-scoped pattern
        """
        if not domain_names:
            return False

        resolved = ValidatingCacheWrapper._resolve_namespace_structure(key, parts)
        if resolved is None:
            return False

        domain_name, suffix_parts = resolved
        if domain_name not in domain_names:
            return False

        # If no suffix matchers for this domain, accept on domain name alone
        # (backward-compatible for entries without parseable patterns)
        matchers = domain_suffix_matchers.get(domain_name)
        if not matchers:
            return True

        suffix_len = len(suffix_parts)
        for expected_count, literals, exact in matchers:
            if exact:
                # Last segment is literal — require exact segment count
                if suffix_len != expected_count:
                    continue
            else:
                # Last segment is variable — allow trailing segments
                if suffix_len < expected_count:
                    continue
            if all(suffix_parts[pos] == lit for pos, lit in literals.items()):
                return True

        return False

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _validate_key(self, key: str) -> None:
        """Validate a cache key against registered patterns.

        Scoped keys (user/tenant/app scope) must:
        1. Start with ``org:`` (proving CacheNamespace involvement)
        2. Have at least 10 segments (namespace base + feature minimum)
        3. Contain namespace structural markers (``:env:`` and ``:svc:``)
        4. Contain scope-appropriate markers (``:t:`` for tenant/user,
           ``:u:`` for user)
        5. Have the registered feature at the correct position from end
           (terminal for most patterns, or at a pattern-defined offset)

        Global keys must structurally match a registered pattern: literal
        segments at declared positions and the correct total segment count.

        Args:
            key: The cache key to validate

        Raises:
            CacheKeyNotRegisteredError: If key doesn't match any registered pattern
        """
        parts = key.split(":")

        if key.startswith("org:"):
            if len(parts) >= self._MIN_SCOPED_SEGMENTS:
                # Check user/tenant/app scoped features
                if self._match_scoped_key(key, parts, self._scoped_features):
                    return
                # Check domain-scoped keys (structural + suffix matching)
                if self._match_domain_key(
                    key, parts, self._domain_names, self._domain_suffix_matchers,
                ):
                    return
            if key.endswith(":") and self._has_prefix_patterns:
                if len(parts) >= self._MIN_SCOPED_SEGMENTS:
                    return
        elif self._match_global_key(parts, self._global_matchers):
            return

        raise CacheKeyNotRegisteredError(key)

    @auto_trace(logger, disabled=TraceDisabledReason.CALLER_TRACED)
    def _validate_prefix(self, prefix: str) -> None:
        """Validate a prefix used for invalidation.

        Prefixes are valid if they end with ":" and could be a valid prefix
        for any registered key pattern.

        Args:
            prefix: The prefix to validate

        Raises:
            CacheKeyNotRegisteredError: If prefix doesn't match any registered pattern
        """
        if not prefix.endswith(":"):
            raise CacheKeyNotRegisteredError(
                prefix, context="invalidation prefix must end with ':'"
            )

        # Any prefix that starts with "org:" is a valid namespace prefix
        if prefix.startswith("org:"):
            return

        # Global prefixes
        for schema in self._registry.schemas:
            if schema.scope == "global":
                pattern_prefix = schema.pattern.split("{")[0]
                if prefix.startswith(pattern_prefix):
                    return

        raise CacheKeyNotRegisteredError(
            prefix, context="prefix does not match any registered pattern"
        )

    @auto_trace(logger)
    async def get(self, key: str) -> Optional[Any]:
        """Validate key and delegate to inner backend."""
        self._validate_key(key)
        return await self._inner.get(key)

    @auto_trace(logger)
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Validate key and delegate to inner backend."""
        self._validate_key(key)
        await self._inner.set(key, value, ttl_seconds=ttl_seconds)

    @auto_trace(logger)
    async def delete(self, key: str) -> None:
        """Validate key and delegate to inner backend."""
        self._validate_key(key)
        await self._inner.delete(key)

    @auto_trace(logger)
    async def exists(self, key: str) -> bool:
        """Validate key and delegate to inner backend."""
        self._validate_key(key)
        return await self._inner.exists(key)

    @auto_trace(logger)
    async def invalidate_by_prefix(self, prefix: str) -> int:
        """Validate prefix and delegate to inner backend."""
        self._validate_prefix(prefix)
        return await self._inner.invalidate_by_prefix(prefix)

    @auto_trace(logger)
    async def keys_by_prefix(self, prefix: str) -> list[str]:
        """Validate prefix and delegate to inner backend."""
        self._validate_prefix(prefix)
        return await self._inner.keys_by_prefix(prefix)

    @property
    def default_ttl_seconds(self) -> int:
        """Delegate to inner backend."""
        return self._inner.default_ttl_seconds
