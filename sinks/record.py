from event import Event
from sinks.sink import EventSink


class RecordEventSink(EventSink):
    def __init__(self):
        self.events = []

    def send(self, event: Event) -> None:
        self.events.append(event)
