import json

import pytest

from event import Event
from sinks.record import RecordEventSink
from sources.replay import ReplayEventSource


def _parse(line: str) -> Event:
    d = json.loads(line)
    return Event(
        timestamp=d["timestamp"],
        pid=d["pid"],
        process=d["process"],
        payload=d["payload"],
    )


@pytest.fixture
def replay_file(tmp_path):
    events = [
        {"timestamp": 1.0, "pid": 1234, "process": "bash", "payload": "execve /bin/ls"},
        {"timestamp": 2.0, "pid": 5678, "process": "curl", "payload": "connect 1.2.3.4:80"},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path, events


def test_replay_source_feeds_record_sink(replay_file):
    path, raw_events = replay_file
    expected = [
        Event(**{k: v for k, v in e.items()}) for e in raw_events
    ]

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for line in source.events():
        sink.send(_parse(line))

    assert sink.events == expected


def test_replay_source_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for line in source.events():
        sink.send(_parse(line))

    assert sink.events == []


def test_replay_source_preserves_order(tmp_path):
    events = [
        {"timestamp": float(i), "pid": i, "process": f"proc{i}", "payload": f"data{i}"}
        for i in range(10)
    ]
    path = tmp_path / "ordered.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    source = ReplayEventSource(str(path))
    sink = RecordEventSink()

    for line in source.events():
        sink.send(_parse(line))

    assert [e.pid for e in sink.events] == list(range(10))
