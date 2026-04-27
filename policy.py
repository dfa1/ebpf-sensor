from dataclasses import dataclass
from enum import Enum
from typing import Any


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class MitreTag:
    tactic_id: str    # e.g. "TA0004"
    technique_id: str  # e.g. "T1548.001"


class Policy:
    def __init__(
        self,
        rules: dict[str, Priority],
        default: Priority = Priority.INFO,
        mitre: dict[str, MitreTag] | None = None,
    ) -> None:
        self._rules = rules
        self._default = default
        self._mitre: dict[str, MitreTag] = mitre if mitre is not None else {}

    def evaluate(self, check: str) -> Priority:
        return self._rules.get(check, self._default)

    def mitre_tag(self, check: str) -> MitreTag | None:
        return self._mitre.get(check)

    @staticmethod
    def from_dict(cfg: dict[str, Any]) -> "Policy":
        default = Priority(cfg.get("default", Priority.INFO.value))
        rules: dict[str, Priority] = {}
        mitre: dict[str, MitreTag] = {}
        for check, rule in cfg.get("rules", {}).items():
            rules[check] = Priority(rule["priority"])
            if "mitre_tactic" in rule and "mitre_technique" in rule:
                mitre[check] = MitreTag(
                    tactic_id=rule["mitre_tactic"],
                    technique_id=rule["mitre_technique"],
                )
        return Policy(rules, default, mitre)
