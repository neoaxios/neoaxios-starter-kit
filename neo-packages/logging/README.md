# neoaxios-logging

Production-level telemetry for distributed systems. Combines two complementary subsystems:

- **Logbook** — structured application logging built on `structlog`, with TRACE-level
  function-entry/exit instrumentation via the `@auto_trace` decorator, per-component log
  level filtering, automatic source-location capture, and Unicode-safe rendering.
- **FlightRecorder** — timeline-based event recording for tests and debugging. Captures
  ordered events with millisecond timestamps, persists JSONL session files to disk
  (rotated), and provides query/cleanup CLI tools.

Plus diagnostics, performance analysis, and a hierarchical YAML-driven configuration loader
that reads from environment variables, files, or per-package overrides.

## Install

```bash
pip install neoaxios-logging
```

Requires Python 3.8+. Depends on `structlog>=23.0`, `psutil>=5.8`, and `pyyaml>=5.1`.

## Quickstart — Logbook

```python
from neoaxios_logging import auto_trace, get_telemetry

logger = get_telemetry(__name__)

@auto_trace(logger)
def process(payload: dict) -> dict:
    logger.info("processing", size=len(payload))
    return {"ok": True}
```

Set `TELEMETRY_ENABLED=true` to enable Logbook output (off by default; see
`telemetry/config/defaults/logging.yaml` for the full schema).

## Quickstart — FlightRecorder

```python
from neoaxios_logging.flight_recorder import FlightRecorder

with FlightRecorder("integration-test") as fr:
    fr.event("request.start", path="/api/x")
    # ... run test ...
    fr.event("request.end", status=200)
```

By default sessions are written to `.qrs/flight_recorder/sessions/{date}/`. Override
with the `FLIGHT_RECORDER_OUTPUT_DIR` environment variable.

## Console scripts

Installed by the package:

| Command | Purpose |
|---|---|
| `neoaxios-fr-query` (alias `neo-fr-query`) | Query and inspect FlightRecorder session files |
| `neoaxios-fr-cleanup` (alias `neo-fr-cleanup`) | Compress or delete old session files |

## Layout

```
telemetry/
  logbook/         # Logbook implementation
  flight_recorder/ # FlightRecorder implementation
  diagnostics/     # Environment / runtime / plugin health checks
  config/          # Hierarchical config loader and defaults
  scripts/         # CLI tools (query, cleanup)
  common/          # Shared types and utilities
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
