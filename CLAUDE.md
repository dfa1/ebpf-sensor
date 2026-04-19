# ebpf-sensor

## Commands

```bash
uv run python -m pytest tests/ -v   # run tests
uv run python -m mypy sources/ sinks/ event.py tests/  # type check
```

## Conventions

- Use `uv` for all Python tooling (not `.venv/bin/...` directly)
- `EventSource` and `EventSink` are `Protocol` classes (not ABC)
- `Event.timestamp` is `int` nanoseconds since boot
- `ReplayEventSource` yields `Event` directly (parses NDJSON)
- `mypy --strict` must pass clean
