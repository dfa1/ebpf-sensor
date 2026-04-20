from typing import Iterator
from unittest.mock import MagicMock

from event import Event
from sources.ebpf import EBPFEventSource


def _make_row(
    task: bytes, pid: int, ts: float, msg: bytes
) -> tuple[bytes, int, int, int, float, bytes]:
    return (task, pid, 0, 0, ts, msg)


def _source_with_rows(
    rows: list[tuple[bytes, int, int, int, float, bytes]],
) -> EBPFEventSource:
    mock_bpf = MagicMock()
    mock_bpf.trace_fields.return_value = iter(rows)
    return EBPFEventSource(mock_bpf)


def test_yields_event_from_trace_fields() -> None:
    source = _source_with_rows(
        [_make_row(b"bash", 1234, 1.0, b"execve /bin/ls")]
    )
    events = list(source.events())
    assert events == [
        Event(timestamp=1_000_000_000, pid=1234, process="bash", payload="execve /bin/ls")
    ]


def test_timestamp_converted_to_nanoseconds() -> None:
    source = _source_with_rows([_make_row(b"proc", 1, 2.5, b"msg")])
    (event,) = source.events()
    assert event.timestamp == 2_500_000_000


def test_yields_multiple_events_in_order() -> None:
    rows = [
        _make_row(b"bash", 1, 1.0, b"cmd1"),
        _make_row(b"curl", 2, 2.0, b"cmd2"),
        _make_row(b"python", 3, 3.0, b"cmd3"),
    ]
    source = _source_with_rows(rows)
    events = list(source.events())
    assert [e.pid for e in events] == [1, 2, 3]
    assert [e.process for e in events] == ["bash", "curl", "python"]


def test_empty_trace_yields_nothing() -> None:
    source = _source_with_rows([])
    assert list(source.events()) == []


def test_skips_row_with_non_decodable_task() -> None:
    bad_task = MagicMock()
    bad_task.decode.side_effect = AttributeError
    mock_bpf = MagicMock()
    mock_bpf.trace_fields.return_value = iter([(bad_task, 1, 0, 0, 1.0, b"msg")])
    source = EBPFEventSource(mock_bpf)
    assert list(source.events()) == []


def test_skips_row_with_invalid_pid() -> None:
    mock_bpf = MagicMock()
    mock_bpf.trace_fields.return_value = iter([(b"proc", "not-an-int", 0, 0, 1.0, b"msg")])
    source = EBPFEventSource(mock_bpf)
    assert list(source.events()) == []


def test_decodes_bytes_with_replacement_on_errors() -> None:
    source = _source_with_rows([_make_row(b"proc\xff", 1, 1.0, b"pay\xff")])
    (event,) = source.events()
    assert "\ufffd" in event.process or event.process == "proc\ufffd"
    assert "\ufffd" in event.payload or event.payload == "pay\ufffd"


def test_implements_event_source_protocol() -> None:
    source = _source_with_rows([])
    assert isinstance(source.events(), Iterator)
