class EBPFEventSource(EventSource):
    def __init__(self, bpf_prog: str):
        self.b = BPF(text=bpf_prog)

    def events(self) -> Iterator[Event]:
       for fields in self.b.trace_fields():
          try:
             yield fields.decode(errors='replace')
          except AttributeError:
             continue
