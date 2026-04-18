from abc import ABC, abstractmethod

class EventSink(ABC):
    @abstractmethod
    def send(self, event: dict) -> None:
        pass
