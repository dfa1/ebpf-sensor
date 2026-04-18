class RecordEventSink(EventSink):
    def __init__(self):
        self.events = []

    def send(self, event: Event) -> None:
        self.events.append(event)
