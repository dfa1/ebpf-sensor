# ebpf-sensor

## Commands

```bash
uv run python -m pytest                                 # run tests
uv run python -m mypy sources/ sinks/ event.py tests/  # type check
uv run ruff format .                                   # format
uv run ruff check .                                    # lint
```

## Conventions

- **Always** use `uv run <tool>` — NEVER `.venv/bin/...` directly, bare `python`, or bare `pip`
- If `uv` is not on PATH, check `~/.local/bin/uv` before falling back
- `EventSource` and `EventSink` are `Protocol` classes (not ABC)
- `Event.timestamp` is `int` nanoseconds since boot
- `ReplayEventSource` yields `Event` directly (parses NDJSON)
- `mypy --strict` must pass clean

## Testing

- Only mock types you own — never mock third-party types (e.g. `bcc.BPF`) directly; wrap them in a local `Protocol` and mock that instead
- Use dependency injection for mocks, never `sys.modules` / conftest monkey-patching
- Test filenames: snake_case only (no hyphens)
- A task is NOT complete until `uv run python -m pytest` passes and you paste the output
- **No string checks** — do not assert that specific string literals appear inside generated code (e.g. `assert "kprobe__foo" in prog`). These tests are brittle, test implementation not behavior, and break on trivial renames. Test observable behavior: return types, exceptions, inequality of distinct outputs, determinism.

## Exploration

- Before asking about file locations or class definitions, search first: `rg -n "class ClassName"` or Glob/Grep
- Only ask the user if search returns nothing
