class EventSource(ABC):

    @abstractmethod
    def events(self) -> Iterator[KernelEvent]:
        pass
