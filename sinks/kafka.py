class KafkaEventSink(EventSink):
    def __init__(self, bootstrap_servers, topic):
        self.topic = topic
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode()
        )

    def send(self, event: dict) -> None:
        self.producer.send(self.topic, value=event)
