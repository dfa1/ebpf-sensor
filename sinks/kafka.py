import json
import socket
from dataclasses import asdict

from kafka import KafkaProducer  # type: ignore[import-untyped]

from event import Event
from policy import Policy


class KafkaEventSink:
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        policy: Policy | None = None,
        host: str | None = None,
    ) -> None:
        self._topic = topic
        self._policy = policy
        self._host = host if host is not None else socket.gethostname()
        self._producer: KafkaProducer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode(),
        )

    def write(self, event: Event) -> None:
        msg = asdict(event)
        if self._policy is not None:
            msg["priority"] = self._policy.evaluate(event.check).value
            msg["host"] = self._host
        self._producer.send(self._topic, value=msg)

    def close(self) -> None:
        self._producer.flush()
        self._producer.close()
