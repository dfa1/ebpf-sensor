from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    timestamp: int  # nanoseconds since boot
    pid: int
    process: str
    payload: str
    check: str = ""  # name of the BPF check that produced this event
