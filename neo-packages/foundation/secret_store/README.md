# neoaxios-secret-store

Vault-backed secret store for distributed Python services. Provides an async
`Protocol` for fetching rotatable secrets and a HashiCorp Vault implementation
backed by the AppRole auth method, KV v2 secrets engine, in-process TTL
caching, and structured error semantics.

## What's in the box

- **`SecretStoreProtocol`** — async contract: `get_secret(key) → SecretStr`,
  `rotate_secret(key)`, `clear_cache()`. Lets your code depend on the
  abstraction; tests inject a fake.
- **`VaultSecretStore`** — concrete HashiCorp Vault implementation using
  `hvac` (sync client), with blocking calls offloaded to an asyncio executor.
  AppRole login is lazy and reused until Vault rejects it.
- **`VaultConfig`** — frozen dataclass for connection params (URL, AppRole
  role/secret IDs, KV mount + base path, optional Enterprise namespace, TTL,
  HTTP timeout).
- **Structured error hierarchy** — `VaultAuthError`, `VaultUnavailableError`,
  `SecretNotFoundError`. Callers can distinguish "credentials wrong" from
  "Vault wedged" from "key not provisioned yet."

## Design choices

- **Fail-closed.** If Vault is unreachable, `VaultUnavailableError` is raised.
  There is no env-var or file fallback — Vault is a hard dependency, and
  silently degrading to weaker secret material is the wrong behavior. Retries
  belong in the caller's supervisor, not in the library.
- **TTL never refreshes on read.** Cached entries expire exactly
  `cache_ttl_seconds` after the fetch that populated them. This makes the
  blast radius of a stale credential bounded and predictable.
- **Rotation is explicit.** `rotate_secret(key)` evicts a single entry.
  `clear_cache()` evicts all. Neither writes to Vault — rotation writes are
  performed out-of-band by the operator or a CI job.
- **Live vs. sandbox separation by instance.** Each `VaultSecretStore`
  targets exactly one mount + base path. There is no `is_sandbox` boolean on
  the protocol surface; the caller chooses which store to use.
- **Secrets never logged.** Returned values are `SecretStr` (Pydantic) so
  `repr()` and `str()` mask the value. Telemetry context carries only short
  BLAKE2b hashes of key names so log consumers can correlate "which key" across
  events without seeing key names verbatim.

## Installation

```bash
pip install neoaxios-secret-store
```

Or from the monorepo:

```bash
pip install -e neo-packages/foundation/secret_store
```

## Quick start

```python
from neoaxios_secure_config import SecretStr
from neoaxios_secret_store import VaultConfig, VaultSecretStore

config = VaultConfig(
    url="https://vault.example.com",
    role_id="acme-app-role",
    secret_id=SecretStr("..."),       # AppRole secret ID
    mount_point="secret",
    base_path="shared/myservice/live",
)

store = VaultSecretStore(config)

# Read a secret (caches for 5 min by default).
api_key = await store.get_secret("third_party_api_key")
client = ThirdPartyClient(api_key=api_key.get_secret_value())

# Force a refresh on next read (e.g. after a rotation event).
await store.rotate_secret("third_party_api_key")
```

### Plugging in via the protocol

```python
from neoaxios_secret_store import SecretStoreProtocol

class MyService:
    def __init__(self, secrets: SecretStoreProtocol) -> None:
        self._secrets = secrets

    async def call_upstream(self) -> dict:
        api_key = await self._secrets.get_secret("upstream_key")
        ...
```

Tests can pass a fake implementation that satisfies `SecretStoreProtocol`
without touching Vault.

## Operational notes

- **AppRole credentials.** The `secret_id` is a `SecretStr` — never log it,
  and never put it in source control. Provision via your existing secret
  injection pipeline (e.g. environment variable + `secure_config` loader).
- **Vault token reuse.** The store logs in once per process and reuses the
  token until Vault returns 401/403 (e.g. expired token, policy change). On
  401/403 the store discards its login state and the next call re-authenticates.
- **Vault namespace (Enterprise).** Pass `namespace=` in `VaultConfig` if you
  run Vault Enterprise. OSS deployments leave it `None`.
- **TTL tuning.** `SECRET_STORE_CACHE_TTL_SECONDS` (from `secure_cache.defaults`)
  is 300s by default. Reduce it if your rotation cadence is faster than every
  five minutes; otherwise leave it alone.

## License

Apache 2.0. See [LICENSE](LICENSE).
