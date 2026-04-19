import json
from dataclasses import asdict

from event import Event


class RecordEventSink:
    def __init__(self, path: str) -> None:
        self._path = path
        self.events: list[Event] = []
        self._file = open(path, "w")

    def write(self, event: Event) -> None:
        self.events.append(event)
        self._file.write(json.dumps(asdict(event)) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()
