from dataclasses import dataclass

@dataclass(frozen=True)
class Event:
    timestamp: float
    pid: int
    process: str
    payload: str
