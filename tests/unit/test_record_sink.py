import json
from pathlib import Path

import pytest

from event import Event
from sinks.record import RecordEventSink


@pytest.fixture
def event() -> Event:
    return Event(timestamp=1_000_000_000, pid=1234, process="bash", payload="execve /bin/ls")


def test_write_stores_event_in_memory(tmp_path: Path, event: Event) -> None:
    sink = RecordEventSink(str(tmp_path / "out.ndjson"))
    sink.write(event)
    sink.close()

    assert sink.events == [event]


def test_write_appends_ndjson_line(tmp_path: Path, event: Event) -> None:
    path = tmp_path / "out.ndjson"
    sink = RecordEventSink(str(path))
    sink.write(event)
    sink.close()

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "timestamp": 1_000_000_000,
        "pid": 1234,
        "process": "bash",
        "payload": "execve /bin/ls",
    }


def test_write_multiple_events_order(tmp_path: Path) -> None:
    events = [
        Event(timestamp=i * 1_000_000_000, pid=i, process=f"proc{i}", payload=f"data{i}")
        for i in range(5)
    ]
    path = tmp_path / "out.ndjson"
    sink = RecordEventSink(str(path))
    for e in events:
        sink.write(e)
    sink.close()

    assert sink.events == events
    lines = path.read_text().splitlines()
    assert len(lines) == 5
    for i, line in enumerate(lines):
        assert json.loads(line)["pid"] == i


def test_write_flushes_immediately(tmp_path: Path, event: Event) -> None:
    path = tmp_path / "out.ndjson"
    sink = RecordEventSink(str(path))
    sink.write(event)
    # file not closed yet — flush must have written content
    assert path.read_text().strip() != ""
    sink.close()


def test_empty_sink_has_no_events(tmp_path: Path) -> None:
    sink = RecordEventSink(str(tmp_path / "out.ndjson"))
    sink.close()

    assert sink.events == []


def test_close_creates_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "out.ndjson"
    sink = RecordEventSink(str(path))
    sink.close()

    assert path.exists()
    assert path.read_text() == ""
