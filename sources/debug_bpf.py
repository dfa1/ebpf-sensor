from typing import Iterator, Protocol

from event import Event


class _BPFTracer(Protocol):
    def trace_fields(self) -> Iterator[tuple[bytes, int, int, int, float, bytes]]: ...


class DebugBpfEventSource:
    def __init__(self, bpf: _BPFTracer) -> None:
        self._bpf = bpf

    def events(self) -> Iterator[Event]:
        for task, pid, cpu, flags, ts, msg in self._bpf.trace_fields():
            try:
                yield Event(
                    timestamp=int(ts * 1_000_000_000),
                    pid=int(pid),
                    process=task.decode(errors="replace"),
                    payload=msg.decode(errors="replace"),
                )
            except (ValueError, AttributeError):
                continue
