import pytest

from policy import MitreTag, Policy, Priority


# --- Priority ---


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


# --- Policy.mitre_tag ---


def test_mitre_tag_returns_tag_when_present() -> None:
    tag = MitreTag(tactic_id="TA0004", technique_id="T1548.001")
    p = Policy({"suid_exec": Priority.CRITICAL}, mitre={"suid_exec": tag})
    assert p.mitre_tag("suid_exec") == tag


def test_mitre_tag_returns_none_for_unknown_check() -> None:
    p = Policy({"suid_exec": Priority.CRITICAL})
    assert p.mitre_tag("suid_exec") is None


def test_mitre_tag_returns_none_when_no_mitre_configured() -> None:
    p = Policy({})
    assert p.mitre_tag("anything") is None


# --- Policy.from_dict ---


def test_from_dict_parses_rules() -> None:
    cfg = {
        "default": "info",
        "rules": {
            "suid_exec": {"priority": "critical"},
            "raw_socket": {"priority": "high"},
        },
    }
    p = Policy.from_dict(cfg)
    assert p.evaluate("suid_exec") == Priority.CRITICAL
    assert p.evaluate("raw_socket") == Priority.HIGH


def test_from_dict_parses_mitre_tags() -> None:
    cfg = {
        "default": "info",
        "rules": {
            "suid_exec": {
                "priority": "critical",
                "mitre_tactic": "TA0004",
                "mitre_technique": "T1548.001",
            },
        },
    }
    p = Policy.from_dict(cfg)
    tag = p.mitre_tag("suid_exec")
    assert tag == MitreTag(tactic_id="TA0004", technique_id="T1548.001")


def test_from_dict_mitre_optional_per_rule() -> None:
    cfg = {
        "rules": {
            "suid_exec": {
                "priority": "critical",
                "mitre_tactic": "TA0004",
                "mitre_technique": "T1548.001",
            },
            "tcp_connect": {"priority": "low"},
        }
    }
    p = Policy.from_dict(cfg)
    assert p.mitre_tag("suid_exec") is not None
    assert p.mitre_tag("tcp_connect") is None


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
    with pytest.raises((ValueError, KeyError)):
        Policy.from_dict({"rules": {"suid_exec": {"priority": "urgent"}}})


def test_from_dict_invalid_default_raises() -> None:
    with pytest.raises(ValueError):
        Policy.from_dict({"default": "unknown"})
