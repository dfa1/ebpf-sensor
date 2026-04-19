import json
from pathlib import Path

import pytest

from event import Event
from sinks.record import RecordEventSink
from sources.replay import ReplayEventSource


@pytest.fixture
def replay_file(tmp_path: Path) -> tuple[Path, list[dict[str, object]]]:
    events: list[dict[str, object]] = [
        {
            "timestamp": 1_000_000_000,
            "pid": 1234,
            "process": "bash",
            "payload": "execve /bin/ls",
        },
        {
            "timestamp": 2_000_000_000,
            "pid": 5678,
            "process": "curl",
            "payload": "connect 1.2.3.4:80",
        },
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path, events


def test_replay_source_feeds_record_sink(
    replay_file: tuple[Path, list[dict[str, object]]],
) -> None:
    path, raw_events = replay_file
    expected = [Event(**e) for e in raw_events]  # type: ignore[arg-type]

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for event in source.events():
        sink.send(event)

    assert sink.events == expected


def test_replay_source_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("")

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for event in source.events():
        sink.send(event)

    assert sink.events == []


def test_replay_source_preserves_order(tmp_path: Path) -> None:
    events = [
        {
            "timestamp": i * 1_000_000_000,
            "pid": i,
            "process": f"proc{i}",
            "payload": f"data{i}",
        }
        for i in range(10)
    ]
    path = tmp_path / "ordered.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for event in source.events():
        sink.send(event)

    assert [e.pid for e in sink.events] == list(range(10))
