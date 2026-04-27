from enum import Enum
from typing import Any


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Policy:
    def __init__(
        self,
        rules: dict[str, Priority],
        default: Priority = Priority.INFO,
    ) -> None:
        self._rules = rules
        self._default = default

    def evaluate(self, check: str) -> Priority:
        return self._rules.get(check, self._default)

    @staticmethod
    def from_dict(cfg: dict[str, Any]) -> "Policy":
        default = Priority(cfg.get("default", Priority.INFO.value))
        rules = {k: Priority(v) for k, v in cfg.get("rules", {}).items()}
        return Policy(rules, default)
