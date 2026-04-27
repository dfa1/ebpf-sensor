import pytest

from policy import Policy, Priority


# --- Priority ---


def test_priority_values_are_strings() -> None:
    assert Priority.CRITICAL.value == "critical"
    assert Priority.HIGH.value == "high"
    assert Priority.MEDIUM.value == "medium"
    assert Priority.LOW.value == "low"
    assert Priority.INFO.value == "info"


# --- Policy.evaluate ---


def test_evaluate_returns_mapped_priority() -> None:
    p = Policy({"suid_exec": Priority.CRITICAL})
    assert p.evaluate("suid_exec") == Priority.CRITICAL


def test_evaluate_returns_default_for_unknown_check() -> None:
    p = Policy({}, default=Priority.INFO)
    assert p.evaluate("unknown_check") == Priority.INFO


def test_evaluate_custom_default() -> None:
    p = Policy({}, default=Priority.LOW)
    assert p.evaluate("anything") == Priority.LOW


def test_evaluate_multiple_rules() -> None:
    p = Policy(
        {
            "commit_creds": Priority.CRITICAL,
            "raw_socket": Priority.HIGH,
            "tcp_connect": Priority.MEDIUM,
        }
    )
    assert p.evaluate("commit_creds") == Priority.CRITICAL
    assert p.evaluate("raw_socket") == Priority.HIGH
    assert p.evaluate("tcp_connect") == Priority.MEDIUM


def test_evaluate_empty_check_name_uses_default() -> None:
    p = Policy({"": Priority.HIGH}, default=Priority.INFO)
    assert p.evaluate("") == Priority.HIGH


# --- Policy.from_dict ---


def test_from_dict_parses_rules() -> None:
    cfg = {
        "default": "info",
        "rules": {
            "suid_exec": "critical",
            "raw_socket": "high",
        },
    }
    p = Policy.from_dict(cfg)
    assert p.evaluate("suid_exec") == Priority.CRITICAL
    assert p.evaluate("raw_socket") == Priority.HIGH


def test_from_dict_uses_default_priority() -> None:
    cfg = {"default": "medium", "rules": {}}
    p = Policy.from_dict(cfg)
    assert p.evaluate("anything") == Priority.MEDIUM


def test_from_dict_missing_default_falls_back_to_info() -> None:
    p = Policy.from_dict({"rules": {}})
    assert p.evaluate("x") == Priority.INFO


def test_from_dict_missing_rules_key() -> None:
    p = Policy.from_dict({"default": "low"})
    assert p.evaluate("x") == Priority.LOW


def test_from_dict_empty_dict() -> None:
    p = Policy.from_dict({})
    assert p.evaluate("x") == Priority.INFO


def test_from_dict_invalid_priority_raises() -> None:
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": {"suid_exec": "urgent"}})


def test_from_dict_invalid_default_raises() -> None:
    with pytest.raises(ValueError):
        Policy.from_dict({"default": "unknown"})
