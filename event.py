from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    timestamp: int  # nanoseconds since boot
    pid: int
    process: str
    payload: str
