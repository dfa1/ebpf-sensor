import json
from typing import Iterator

from event import Event


class ReplayEventSource:
    """Feed recorded events from a NDJSON file — useful for testing."""

    def __init__(self, path: str) -> None:
        self.path = path

    def events(self) -> Iterator[Event]:
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield Event(**json.loads(line))
