import ctypes
from typing import Callable, Iterator, Protocol

from event import Event

TASK_COMM_LEN = 16
_PAYLOAD_LEN = 256


class _BpfEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("payload", ctypes.c_char * _PAYLOAD_LEN),
    ]


class _PerfTable(Protocol):
    def open_perf_buffer(self, callback: Callable[..., None]) -> None: ...


class _BPFPerfSource(Protocol):
    def __getitem__(self, name: str) -> _PerfTable: ...
    def perf_buffer_poll(self, timeout: int = 10) -> None: ...


class BpfEventSource:
    def __init__(self, bpf: _BPFPerfSource, table: str = "events") -> None:
        self._bpf = bpf
        self._table = table

    def events(self) -> Iterator[Event]:
        pending: list[Event] = []

        def _callback(cpu: int, data: ctypes.c_void_p, size: int) -> None:
            e = ctypes.cast(data, ctypes.POINTER(_BpfEvent)).contents
            pending.append(
                Event(
                    timestamp=int(e.ts),
                    pid=int(e.pid),
                    process=e.comm.decode(errors="replace"),
                    payload=e.payload.decode(errors="replace"),
                )
            )

        self._bpf[self._table].open_perf_buffer(_callback)
        while True:
            self._bpf.perf_buffer_poll(timeout=10)
            yield from pending
            pending.clear()
