# ebpf-sensor

eBPF event pipeline with pluggable sources and sinks.
Companion for [this article about BPF](https://dfa1.github.io/articles/from-bpf-to-ebpf-twenty-years-later).


## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync
```

## Usage

```python
from sources.ebpf import EBPFEventSource
from sinks.kafka import KafkaEventSink

source = EBPFEventSource(bpf_prog=open("prog.c").read())
sink = KafkaEventSink(bootstrap_servers="localhost:9092", topic="events")
for event in source.events():
    sink.write(event)
```

## Development

```bash
uv run python -m pytest                                 # tests
uv run python -m mypy sources/ sinks/ event.py tests/  # type check
uv run ruff format .                                   # format
uv run ruff check .                                    # lint
```

## License

MIT
