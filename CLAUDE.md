# ebpf-sensor

## Commands

```bash
uv run python -m pytest                                 # run tests
uv run python -m mypy sources/ sinks/ event.py tests/  # type check
uv run ruff format .                                   # format
uv run ruff check .                                    # lint
```

## Conventions

- **Always** use `uv run <tool>` — NEVER `.venv/bin/...` directly
- `EventSource` and `EventSink` are `Protocol` classes (not ABC)
- `Event.timestamp` is `int` nanoseconds since boot
- `ReplayEventSource` yields `Event` directly (parses NDJSON)
- `mypy --strict` must pass clean

## Testing

- Only mock types you own — never mock third-party types (e.g. `bcc.BPF`) directly; wrap them in a local `Protocol` and mock that instead
