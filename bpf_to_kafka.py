"""Read eBPF events and publish them to a Kafka topic."""

import argparse
import signal
import sys

from bcc import BPF  # type: ignore[import-not-found]

from sinks.kafka import KafkaEventSink
from sources.ebpf import EBPFEventSource
from sources.predefined_programs import tcp_connect


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream eBPF events to Kafka")
    parser.add_argument("--port", type=int, default=443, help="TCP port to trace")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="ebpf-events")
    args = parser.parse_args()

    sink = KafkaEventSink(args.bootstrap_servers, args.topic)
    source = EBPFEventSource(BPF(text=tcp_connect(args.port)))

    def _shutdown(sig: int, _: object) -> None:
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"Tracing TCP connects to port {args.port} -> {args.topic}@{args.bootstrap_servers}")
    for event in source.events():
        sink.write(event)


if __name__ == "__main__":
    main()
