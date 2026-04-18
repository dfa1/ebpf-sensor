class ReplayEventSource(EventSource):
    """Feed recorded events from a file — useful for testing"""
    def __init__(self, path: str):
        self.path = path

    def events(self) -> Iterator[str]:
        with open(self.path) as f:
            for line in f:
                yield line.strip()
