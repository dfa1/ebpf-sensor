from typing import Iterator

from bcc import BPF  # type: ignore[import-not-found]

from event import Event


class EBPFEventSource:
    def __init__(self, bpf_prog: str) -> None:
        self._bpf = BPF(text=bpf_prog)

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
