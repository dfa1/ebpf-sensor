from abc import ABC, abstractmethod
from typing import Iterator
from event import Event

class EventSource(ABC):

    @abstractmethod
    def events(self) -> Iterator[Event]:
        pass
