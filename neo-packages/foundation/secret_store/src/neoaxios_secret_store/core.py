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

"""Vault-backed secret store for distributed Python services.

Multiple services that need rotatable credentials (third-party API keys,
inter-service tokens, database passwords, etc.) consume the
``SecretStoreProtocol``. The module is kept in a foundation package so
cross-service peer imports are avoided — consumers depend on
``secret_store`` directly.

Scope:
    Shared abstraction across services that must pull rotatable
    credentials from HashiCorp Vault. The Protocol surface is the
    stable contract; the concrete ``VaultSecretStore`` is the only
    implementation shipped for production.

Operational guarantees:
    - Every public function and method is traced via ``@auto_trace``.
    - Secrets are returned as ``SecretStr``; log context carries only
      key-name hashes, never raw secret values.
    - If Vault is unreachable, ``VaultUnavailableError`` is raised.
      There is no env-var or file fallback — Vault is a hard dependency,
      and callers must surface the error rather than silently degrade.
    - TTL and HTTP timeout are imported from ``secure_cache.defaults``;
      no hardcoded infrastructure numbers.

Rotation semantics:
    - ``get_secret`` is read-through with TTL caching. The TTL is *never*
      refreshed on a cache hit — each entry expires exactly
      ``SECRET_STORE_CACHE_TTL_SECONDS`` after the fetch that populated
      it.
    - ``rotate_secret`` evicts a single key, causing the next
      ``get_secret`` to round-trip Vault. This gives credential-rolling
      runbooks a clean rolling-restart hook.
    - ``clear_cache`` evicts every entry (operator use during drills or
      full rotation).

Stage separation (live vs. sandbox):
    Each instance targets exactly one Vault mount point + base path, set
    from config at construction time. A typical production layout is::

        VaultSecretStore(
            VaultConfig(
                ...,
                mount_point="secret",
                base_path="shared/myservice/live",
            )
        )

    A sandbox store is instantiated from the same class against
    ``secret/shared/myservice/sandbox``. There is no ``is_sandbox``
    boolean on the protocol surface — the caller chooses the store.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import hvac
from hvac.exceptions import (
    Forbidden,
    InvalidPath,
    Unauthorized,
    VaultDown,
    VaultError,
)

from neoaxios_secure_cache.defaults import (
    SECRET_STORE_CACHE_TTL_SECONDS,
    SECRET_STORE_HTTP_TIMEOUT_SECONDS,
)
from neoaxios_secure_config import SecretStr
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)

__all__ = [
    "SecretStoreProtocol",
    "VaultSecretStore",
    "VaultConfig",
    "VaultAuthError",
    "VaultUnavailableError",
    "SecretNotFoundError",
]


class VaultAuthError(RuntimeError):
    """Raised when Vault rejects the AppRole login."""


class VaultUnavailableError(RuntimeError):
    """Raised when Vault is unreachable or returns a 5xx error.

    Callers MUST NOT fall back to env vars or config files — Vault is a
    hard dependency. Fail closed and surface the error so the operator
    sees it.
    """


class SecretNotFoundError(KeyError):
    """Raised when the requested key does not exist in Vault."""


@runtime_checkable
class SecretStoreProtocol(Protocol):
    """Contract for fetching rotatable secrets.

    Implementations must return ``SecretStr`` so downstream code cannot
    accidentally log raw values via ``str()`` or ``repr()``. Rotation
    must be explicit — caches MUST NOT auto-refresh TTLs on read.
    """

    async def get_secret(self, key: str) -> SecretStr:  # pragma: no cover - protocol
        """Return the current value for ``key``.

        Args:
            key: Key name within the store's configured base path
                (e.g. ``"api_key"`` for ``secret/shared/myservice/live``).

        Returns:
            ``SecretStr`` whose ``.get_secret_value()`` yields the raw
            string. Pydantic masks the repr to prevent accidental logs.

        Raises:
            SecretNotFoundError: The path does not exist in Vault.
            VaultUnavailableError: Vault cannot be reached or returned
                a server error. Callers must NOT fall back to other
                sources; surface the error to the operator.
            VaultAuthError: The configured AppRole credentials are no
                longer valid (e.g. Secret ID expired).
        """
        ...

    async def rotate_secret(self, key: str) -> None:  # pragma: no cover - protocol
        """Evict ``key`` from the cache so the next ``get_secret`` refetches.

        This is the rotation hook used by the Secrets Rotation runbook.
        It does NOT write to Vault — rotation writes are performed
        out-of-band by the operator or a CI job.
        """
        ...

    async def clear_cache(self) -> None:  # pragma: no cover - protocol
        """Evict every cached secret from this store instance."""
        ...


@dataclass(frozen=True)
class VaultConfig:
    """Configuration for :class:`VaultSecretStore`.

    Attributes:
        url: Vault server URL, e.g. ``"https://vault.example.com"``.
        role_id: AppRole role ID (non-secret).
        secret_id: AppRole secret ID wrapped in ``SecretStr`` so it
            cannot be accidentally logged via ``repr(config)``.
        mount_point: KV v2 mount point (default ``"secret"``).
        base_path: Path within the mount that scopes the store (e.g.
            ``"shared/myservice/live"``). Must NOT include the mount.
        cache_ttl_seconds: TTL for in-process cache entries; read-through
            only, never refreshed on hit.
        http_timeout_seconds: Connect + read timeout for Vault calls.
        namespace: Optional Vault Enterprise namespace header. ``None``
            in OSS deployments.
    """

    url: str
    role_id: str
    secret_id: SecretStr
    base_path: str
    mount_point: str = "secret"
    cache_ttl_seconds: int = SECRET_STORE_CACHE_TTL_SECONDS
    http_timeout_seconds: float = SECRET_STORE_HTTP_TIMEOUT_SECONDS
    namespace: str | None = None


@dataclass
class _CacheEntry:
    """Single cached secret with its absolute expiry monotonic timestamp."""

    value: SecretStr
    expires_at: float


# notrace: pure helper, called from traced get_secret path; must stay stable for log redaction
def _hash_key(key: str) -> str:
    """Return a short, non-reversible tag for ``key`` safe to log.

    Uses BLAKE2b-128 truncated to 12 hex chars. Log consumers can
    correlate "which key" across events without seeing the key name
    verbatim (also protects against path-like keys leaking structural
    info about Vault layout).
    """
    return hashlib.blake2b(key.encode("utf-8"), digest_size=6).hexdigest()


class VaultSecretStore:
    """Vault (KV v2 + AppRole) implementation of :class:`SecretStoreProtocol`.

    Thread safety:
        Instances are safe to share across asyncio tasks. Cache
        mutations are guarded by a per-instance ``asyncio.Lock``.
        The underlying ``hvac.Client`` is synchronous; its blocking
        calls are pushed to the default executor via
        ``asyncio.to_thread`` so they do not block the event loop.

    Boot semantics:
        The AppRole login happens lazily on the first ``get_secret``
        or ``rotate_secret`` call, then the resulting token is reused
        until Vault rejects it. If Vault is unreachable at that moment,
        ``VaultUnavailableError`` is raised — there is no silent
        fallback and no retry loop (retries belong in the caller's
        supervisor).
    """

    def __init__(self, config: VaultConfig, *, client: hvac.Client | None = None) -> None:
        """Instantiate the store.

        Args:
            config: Validated :class:`VaultConfig`.
            client: Optional pre-built ``hvac.Client``. Tests inject a
                mock client here; production leaves this ``None`` and
                lets the store build its own.
        """
        self._config = config
        self._client = client or hvac.Client(
            url=config.url,
            namespace=config.namespace,
            timeout=config.http_timeout_seconds,
        )
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._login_lock = asyncio.Lock()
        self._logged_in: bool = False

    @auto_trace(logger)
    async def get_secret(self, key: str) -> SecretStr:
        """Return the current value for ``key``, using the TTL cache.

        Cache entries live exactly ``cache_ttl_seconds`` from the moment
        they are inserted and are NOT refreshed on read. Callers that
        need a forced refresh should call :meth:`rotate_secret` first.
        """
        key_tag = _hash_key(key)
        async with self._lock:
            entry = self._cache.get(key)
            if entry is not None and entry.expires_at > time.monotonic():
                logger.info(
                    "secret_store_cache_hit",
                    context={"key_tag": key_tag, "source": "cache"},
                )
                return entry.value

        # Miss or expired: fetch under the login lock so only one task pays
        # the cost on first use (or after a TTL tick).
        value = await self._fetch_from_vault(key)
        async with self._lock:
            self._cache[key] = _CacheEntry(
                value=value,
                expires_at=time.monotonic() + self._config.cache_ttl_seconds,
            )
        logger.info(
            "secret_store_cache_miss_filled",
            context={"key_tag": key_tag, "ttl_seconds": self._config.cache_ttl_seconds},
        )
        return value

    @auto_trace(logger)
    async def rotate_secret(self, key: str) -> None:
        """Evict ``key`` from the cache.

        The next :meth:`get_secret` will round-trip Vault and pick up
        the new value. This is the hook a credential-rotation runbook
        calls during a rolling restart.
        """
        key_tag = _hash_key(key)
        async with self._lock:
            existed = self._cache.pop(key, None) is not None
        logger.info(
            "secret_store_rotate",
            context={"key_tag": key_tag, "evicted": existed},
        )

    @auto_trace(logger)
    async def clear_cache(self) -> None:
        """Evict every cached secret from this instance."""
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
        logger.info("secret_store_clear_cache", context={"evicted_count": count})

    @auto_trace(logger)
    async def _fetch_from_vault(self, key: str) -> SecretStr:
        """Round-trip Vault to read the named key at the configured base path.

        Logs only non-sensitive context (key hash, HTTP status class).
        Raises domain-specific errors so callers can distinguish between
        "not provisioned yet" and "infrastructure broken".
        """
        key_tag = _hash_key(key)
        if not self._logged_in:
            await self._login()

        try:
            response = await asyncio.to_thread(
                self._client.secrets.kv.v2.read_secret_version,
                mount_point=self._config.mount_point,
                path=self._config.base_path,
                raise_on_deleted_version=True,
            )
        except InvalidPath as exc:
            logger.log_error(
                SecretNotFoundError(f"key missing at base path: {key_tag}"),
                context={"key_tag": key_tag, "mount_point": self._config.mount_point},
            )
            raise SecretNotFoundError(key) from exc
        except (Unauthorized, Forbidden) as exc:
            # Token expired or policy denies — drop login state so the
            # next call re-authenticates before retrying at a higher level.
            self._logged_in = False
            logger.log_error(
                VaultAuthError(f"vault auth rejected for key_tag={key_tag}"),
                context={"key_tag": key_tag, "http_class": "4xx"},
            )
            raise VaultAuthError("Vault rejected the request") from exc
        except VaultDown as exc:
            logger.log_error(
                VaultUnavailableError(f"vault sealed/down for key_tag={key_tag}"),
                context={"key_tag": key_tag, "http_class": "5xx"},
            )
            raise VaultUnavailableError("Vault is sealed or down") from exc
        except VaultError as exc:
            # Connection errors, timeouts, and generic 5xx bubble up as
            # VaultError in hvac. Translate to unavailable — callers must
            # not silently fall back.
            logger.log_error(
                VaultUnavailableError(f"vault transport error for key_tag={key_tag}"),
                context={"key_tag": key_tag, "error_type": type(exc).__name__},
            )
            raise VaultUnavailableError("Vault transport error") from exc

        data = (response or {}).get("data", {}).get("data") or {}
        if key not in data:
            logger.log_error(
                SecretNotFoundError(f"key absent from response: {key_tag}"),
                context={"key_tag": key_tag},
            )
            raise SecretNotFoundError(key)

        return SecretStr(str(data[key]))

    @auto_trace(logger)
    async def _login(self) -> None:
        """Authenticate via AppRole and store the Vault token on the client.

        Uses an async lock so concurrent first-time readers share the
        single login RPC.
        """
        async with self._login_lock:
            if self._logged_in:
                # Another task won the race; nothing to do.
                return
            try:
                await asyncio.to_thread(
                    self._client.auth.approle.login,
                    role_id=self._config.role_id,
                    secret_id=self._config.secret_id.get_secret_value(),
                )
            except (Unauthorized, Forbidden) as exc:
                logger.log_error(
                    VaultAuthError("vault approle login rejected"),
                    context={"role_id_tag": _hash_key(self._config.role_id)},
                )
                raise VaultAuthError("Vault AppRole login rejected") from exc
            except VaultDown as exc:
                logger.log_error(
                    VaultUnavailableError("vault sealed during approle login"),
                    context={"role_id_tag": _hash_key(self._config.role_id)},
                )
                raise VaultUnavailableError("Vault sealed during login") from exc
            except VaultError as exc:
                logger.log_error(
                    VaultUnavailableError("vault transport error during approle login"),
                    context={
                        "role_id_tag": _hash_key(self._config.role_id),
                        "error_type": type(exc).__name__,
                    },
                )
                raise VaultUnavailableError("Vault login transport error") from exc

            self._logged_in = True
            logger.info(
                "secret_store_login_ok",
                context={"role_id_tag": _hash_key(self._config.role_id)},
            )
