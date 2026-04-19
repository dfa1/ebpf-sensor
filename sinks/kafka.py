import json
from dataclasses import asdict

from kafka import KafkaProducer  # type: ignore[import-untyped]

from event import Event


class KafkaEventSink:
    def __init__(self, bootstrap_servers: str, topic: str) -> None:
        self._topic = topic
        self._producer: KafkaProducer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode(),
        )

    def write(self, event: Event) -> None:
        self._producer.send(self._topic, value=asdict(event))
