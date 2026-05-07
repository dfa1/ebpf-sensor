from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    timestamp: int  # nanoseconds since boot (bpf_ktime_get_ns); local machine clock only — not wall time, meaningless across machines or in Kafka
    pid: int
    process: str
    payload: str
    check: str = ""  # name of the BPF check that produced this event
