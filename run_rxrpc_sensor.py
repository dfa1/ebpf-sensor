"""One-shot sensor: load dirtyfrag_rxrpc, write first event to file, then exit."""

import signal
import sys

from bcc import BPF  # type: ignore[import-not-found]

from sinks.record import RecordEventSink
from sources.bpf import BpfEventSource
from sources.predefined_programs import dirtyfrag_rxrpc

OUTPUT = "rxrpc_events.ndjson"

sink = RecordEventSink(OUTPUT)
bpf = BPF(text=dirtyfrag_rxrpc())
source = BpfEventSource(bpf, table="events", check="dirtyfrag_rxrpc")


def _shutdown(sig: int, _: object) -> None:
    sink.close()
    sys.exit(0)


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

print(f"[sensor] dirtyfrag_rxrpc loaded — writing events to {OUTPUT}", flush=True)
for event in source.events():
    sink.write(event)
    print(f"[sensor] event: {event}", flush=True)
    sink.close()
    sys.exit(0)
