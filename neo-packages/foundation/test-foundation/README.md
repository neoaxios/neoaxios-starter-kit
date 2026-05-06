# neoaxios-test-foundation

Shared pytest infrastructure for NeoAxios packages: configuration, fixtures,
mocks, and Redis test helpers. Imported into each package's `conftest.py` so
the same primitives drive tests across the stack.

## What's in the box

### Configuration (`test_config`)

- `get_llm_model_name()` / `get_llm_backend_url()` — env-var-aware getters for
  LLM endpoints. Resolution order: explicit env override (`TEST_MODEL`,
  `NEO_LLM_MODEL`, `NEO_LLM_BASE_URL`, `NEO_LLM_BACKEND_HOST`), auto-discovery
  via `/v1/models`, then the `DEFAULT_LLM_MODEL` sentinel that fails loudly if
  nothing is configured.

### Fixtures (`fixtures`)

- `temp_dir_factory` — isolated temp dirs per test
- `flight_recorder` / `flight_recorder_with_file` / `flight_recorder_persistent`
  — three FlightRecorder variants for in-memory, file-backed, and persistent
  telemetry
- `mock_llm_server` — module-scoped MockLLMServer with health-check verification
- `sample_json_schemas` — JSON Schemas for basic response, error, and LLM
  completion validation
- `performance_timer` — context-manager timer with `assert_faster_than(s)`
- `isolation_checker` — registers state and verifies tests don't mutate it
- `sample_llm_responses` / `sample_test_results` — realistic sample payloads
- Assertion helpers: `assert_valid_json_schema`, `assert_no_print_statements`

### Mocks

- **`MockLLMServer`** — Flask-based, OpenAI-compatible
  `/v1/chat/completions` server. Static, dynamic, custom, and error response
  modes. Configurable rate-limit and error injection
  (`auth_error`, `timeout`, `invalid_json`, `rate_limit`). Auto-port allocation.
- **`MockSSHServer`** — Paramiko-based mock SSH server with command handlers,
  pattern matching, and error injection (`connection_refused`, `auth_failure`,
  `command_timeout`).
- **`MockServiceEndpoint`** — Generic Flask mock for testing HTTP service-call
  stages. Static, echo, and custom-handler response modes; OpenAPI spec
  generation; configurable response delay.

### Redis utilities

- `make_test_namespace()` — `CacheNamespace` with a UUID-scoped `org` so
  parallel test workers cannot collide on keys
- `cleanup_namespace_keys()` / `cleanup_with_fallback()` — SCAN-based teardown
  with `unlink` (default) or `expire` modes, batched through a non-transactional
  pipeline
- `detect_cluster_nodes()` / `check_cluster_available()` /
  `make_requires_redis_cluster_marker()` / `create_cluster_client()` — Redis
  Cluster detection for cluster-only integration tests

### Statistics

- `compute_percentiles(latencies)` → `{p50, p95, p99, avg, min, max}` for scale
  and performance test reporting

## Installation

```bash
pip install neoaxios-test-foundation
```

Or from the monorepo:

```bash
pip install -e neo-packages/foundation/test-foundation
```

## Quick start

### Use as a pytest plugin

In your package's `conftest.py`:

```python
pytest_plugins = ["neoaxios_test_foundation.fixtures"]
```

All fixtures listed above are now available in your tests.

### Selective imports

```python
# conftest.py
from neoaxios_test_foundation.fixtures import (
    flight_recorder,
    mock_llm_server,
    sample_json_schemas,
)
```

### Mock a downstream HTTP service

```python
import pytest
from neoaxios_test_foundation.mock_service_endpoint import MockServiceEndpoint

@pytest.fixture(scope="module")
def echo_service():
    server = MockServiceEndpoint(path="/v1/process", operation_id="processItem")
    server.set_response({"status": "ok", "items_processed": 1})
    server.start()
    yield server
    server.stop()

def test_calls_service(echo_service):
    import requests
    response = requests.post(f"{echo_service.url}/v1/process", json={"name": "test"})
    assert response.status_code == 200
    assert echo_service.get_request_count() == 1
```

### Per-test Redis namespace

```python
from neoaxios_test_foundation import make_test_namespace, cleanup_namespace_keys

@pytest.fixture
async def test_namespace(redis_client):
    ns = make_test_namespace(domain="ratelimit")
    yield ns
    await cleanup_namespace_keys(redis_client, ns)
```

## Configuration

Set the LLM backend in your environment (developer-local):

```bash
export NEO_LLM_BASE_URL=http://127.0.0.1:12345/v1
export NEO_LLM_MODEL=my-model
```

`get_llm_model_name()` and `get_llm_backend_url()` read these at call time;
`get_llm_model_name()` additionally falls back to a one-shot
`/v1/models` autodiscovery against the configured backend before
returning the `DEFAULT_LLM_MODEL` sentinel.

## License

Apache 2.0. See [LICENSE](LICENSE).
