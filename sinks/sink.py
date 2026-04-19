from typing import Protocol

from event import Event


class EventSink(Protocol):
    def send(self, event: Event) -> None: ...
