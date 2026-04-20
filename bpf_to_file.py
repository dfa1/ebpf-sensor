"""Read eBPF events and write them to a local NDJSON file."""

import argparse
import signal
import sys

from bcc import BPF  # type: ignore[import-not-found]

from sinks.record import RecordEventSink
from sources.ebpf import EBPFEventSource
from sources.predefined_programs import tcp_connect


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream eBPF events to a file")
    parser.add_argument("--port", type=int, default=443, help="TCP port to trace")
    parser.add_argument("--output", default="events.ndjson", help="Output file path")
    args = parser.parse_args()

    sink = RecordEventSink(args.output)
    source = EBPFEventSource(BPF(text=tcp_connect(args.port)))

    def _shutdown(sig: int, _: object) -> None:
        sink.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"Tracing TCP connects to port {args.port} -> {args.output}")
    for event in source.events():
        sink.write(event)


if __name__ == "__main__":
    main()
