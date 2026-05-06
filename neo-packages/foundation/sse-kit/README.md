# neoaxios-sse-kit

Server-Sent Events (W3C `text/event-stream`) parsing and serialization. Provides the
typed `SSEEvent` dataclass, a parser for converting raw SSE text into events, a formatter
for serializing dicts into SSE wire format, and a byte-level frame extractor that
preserves exact delimiter bytes (suitable for HMAC-signed streams).

## Install

```bash
pip install neoaxios-sse-kit
```

Requires Python 3.11+. Depends on `neoaxios-logging>=1.0`.

## Usage

### Parsing

```python
from neoaxios_sse_kit import parse_sse_event

raw = "event: message\ndata: {\"hello\": \"world\"}\n\n"
event = parse_sse_event(raw)
print(event.event, event.data)
```

### Formatting

```python
from neoaxios_sse_kit import format_sse_event

wire = format_sse_event({"event": "message", "data": {"ok": True}})
```

### Byte-exact frame extraction

```python
from neoaxios_sse_kit import extract_complete_events

# Splits a byte buffer at SSE frame boundaries (\n\n / \r\n\r\n) without
# rewriting CR/LF — suitable for HMAC-signed payloads.
complete, remainder = extract_complete_events(buffer)
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
