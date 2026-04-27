import ctypes
from itertools import islice
from typing import Callable
from unittest.mock import MagicMock

from event import Event
from sources.bpf import BpfEventSource, _BpfEvent, _PAYLOAD_LEN, TASK_COMM_LEN


def test_bpfevent_layout() -> None:
    assert ctypes.sizeof(_BpfEvent) == 288  # 8+4+16+256 rounded up to u64 alignment
    assert _BpfEvent.ts.offset == 0
    assert _BpfEvent.pid.offset == 8
    assert _BpfEvent.comm.offset == 12
    assert _BpfEvent.payload.offset == 28


def _make_raw(ts: int, pid: int, comm: bytes, payload: bytes) -> _BpfEvent:
    e = _BpfEvent()
    e.ts = ts
    e.pid = pid
    e.comm = comm
    e.payload = payload
    return e


def _source_with_events(raws: list[_BpfEvent]) -> BpfEventSource:
    mock_table = MagicMock()
    mock_bpf = MagicMock()
    mock_bpf.__getitem__.return_value = mock_table

    stored: list[Callable[..., None]] = []
    mock_table.open_perf_buffer.side_effect = lambda cb: stored.append(cb)

    fired = [False]

    def fake_poll(timeout: int = 10) -> None:
        if not fired[0]:
            fired[0] = True
            for raw in raws:
                stored[0](0, ctypes.addressof(raw), ctypes.sizeof(raw))

    mock_bpf.perf_buffer_poll.side_effect = fake_poll
    return BpfEventSource(mock_bpf)


def test_yields_event_from_perf_buffer() -> None:
    raw = _make_raw(1_000_000_000, 1234, b"bash", b"tcp_connect port=443")
    source = _source_with_events([raw])
    (event,) = islice(source.events(), 1)
    assert event == Event(
        timestamp=1_000_000_000,
        pid=1234,
        process="bash",
        payload="tcp_connect port=443",
    )


def test_timestamp_passes_through_unchanged() -> None:
    raw = _make_raw(9_999_999_999, 1, b"proc", b"msg")
    source = _source_with_events([raw])
    (event,) = islice(source.events(), 1)
    assert event.timestamp == 9_999_999_999


def test_yields_multiple_events_in_order() -> None:
    raws = [
        _make_raw(1, 1, b"bash", b"cmd1"),
        _make_raw(2, 2, b"curl", b"cmd2"),
        _make_raw(3, 3, b"python", b"cmd3"),
    ]
    source = _source_with_events(raws)
    events = list(islice(source.events(), 3))
    assert [e.pid for e in events] == [1, 2, 3]
    assert [e.process for e in events] == ["bash", "curl", "python"]


def test_decodes_bytes_with_replacement_on_errors() -> None:
    raw = _make_raw(1, 1, b"proc\xff", b"pay\xff")
    source = _source_with_events([raw])
    (event,) = islice(source.events(), 1)
    assert "\ufffd" in event.process
    assert "\ufffd" in event.payload


def test_uses_named_table() -> None:
    mock_table = MagicMock()
    mock_bpf = MagicMock()
    mock_bpf.__getitem__.return_value = mock_table
    mock_table.open_perf_buffer.side_effect = lambda cb: None
    mock_bpf.perf_buffer_poll.side_effect = RuntimeError("stop")

    source = BpfEventSource(mock_bpf, table="my_events")
    try:
        next(source.events())
    except RuntimeError:
        pass
    mock_bpf.__getitem__.assert_called_once_with("my_events")
