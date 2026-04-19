from typing import Protocol

from event import Event


class EventSink(Protocol):
    def write(self, event: Event) -> None: ...
