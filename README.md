# ebpf-sensor

eBPF event pipeline with pluggable sources and sinks.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync
```

## Usage

```python
from sources.replay import ReplayEventSource
from sinks.record import RecordEventSink

source = ReplayEventSource("events.ndjson")
sink = RecordEventSink("recorded.ndjson")
for event in source.events():
    sink.write(event)
sink.close()
```

## Development

```bash
uv run pytest                                           # tests
uv run python -m mypy sources/ sinks/ event.py tests/  # type check
uv run ruff format .                                   # format
uv run ruff check .                                    # lint
```

## License

MIT
