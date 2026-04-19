from typing import Iterator, Protocol

from event import Event


class EventSource(Protocol):
    def events(self) -> Iterator[Event]: ...
