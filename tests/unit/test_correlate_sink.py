from event import Event
from sinks.correlate import (
    CorrelatingEventSink,
    CorrelationRule,
    copy_fail_rule,
)

SEC = 1_000_000_000


class _CapturingSink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def write(self, event: Event) -> None:
        self.events.append(event)


def _evt(ts: int, pid: int, check: str, process: str = "x") -> Event:
    return Event(timestamp=ts, pid=pid, process=process, payload="", check=check)


def test_forwards_single_event_unchanged() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule()])
    e = _evt(0, 1, "af_alg_socket")
    sink.write(e)
    assert inner.events == [e]


def test_no_synthesis_when_only_one_required_check_fires() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule()])
    sink.write(_evt(0, 1, "af_alg_socket"))
    sink.write(_evt(SEC, 1, "af_alg_socket"))
    assert [e.check for e in inner.events] == ["af_alg_socket", "af_alg_socket"]


def test_chain_fires_when_both_checks_same_pid_within_window() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule(window_seconds=5.0)])
    sink.write(_evt(0, 42, "af_alg_socket"))
    sink.write(_evt(2 * SEC, 42, "splice_nonroot"))
    assert [e.check for e in inner.events] == [
        "af_alg_socket",
        "splice_nonroot",
        "copy_fail_chain",
    ]
    synthetic = inner.events[-1]
    assert synthetic.pid == 42
    assert synthetic.timestamp == 2 * SEC


def test_chain_does_not_fire_across_different_pids() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule()])
    sink.write(_evt(0, 1, "af_alg_socket"))
    sink.write(_evt(SEC, 2, "splice_nonroot"))
    assert all(e.check != "copy_fail_chain" for e in inner.events)


def test_chain_does_not_fire_outside_window() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule(window_seconds=5.0)])
    sink.write(_evt(0, 7, "af_alg_socket"))
    sink.write(_evt(10 * SEC, 7, "splice_nonroot"))
    assert all(e.check != "copy_fail_chain" for e in inner.events)


def test_chain_does_not_refire_within_window() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule(window_seconds=5.0)])
    sink.write(_evt(0, 9, "af_alg_socket"))
    sink.write(_evt(SEC, 9, "splice_nonroot"))
    sink.write(_evt(2 * SEC, 9, "splice_nonroot"))
    fires = [e for e in inner.events if e.check == "copy_fail_chain"]
    assert len(fires) == 1


def test_chain_refires_after_window_elapsed() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule(window_seconds=5.0)])
    sink.write(_evt(0, 9, "af_alg_socket"))
    sink.write(_evt(SEC, 9, "splice_nonroot"))
    sink.write(_evt(20 * SEC, 9, "af_alg_socket"))
    sink.write(_evt(21 * SEC, 9, "splice_nonroot"))
    fires = [e for e in inner.events if e.check == "copy_fail_chain"]
    assert len(fires) == 2


def test_unrelated_check_is_passthrough() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule()])
    sink.write(_evt(0, 1, "execve"))
    assert inner.events == [_evt(0, 1, "execve")]
    assert all(e.check != "copy_fail_chain" for e in inner.events)


def test_orphan_first_check_evicted_so_late_partner_does_not_fire() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule(window_seconds=5.0)])
    sink.write(_evt(0, 9, "af_alg_socket"))
    sink.write(_evt(10 * SEC, 9, "splice_nonroot"))
    assert all(e.check != "copy_fail_chain" for e in inner.events)


def test_multiple_rules_independent() -> None:
    inner = _CapturingSink()
    rule_a = CorrelationRule(
        name="a",
        required=frozenset({"x", "y"}),
        window_ns=SEC,
        emit_check="chain_a",
    )
    rule_b = CorrelationRule(
        name="b",
        required=frozenset({"p", "q"}),
        window_ns=SEC,
        emit_check="chain_b",
    )
    sink = CorrelatingEventSink(inner, [rule_a, rule_b])
    sink.write(_evt(0, 1, "x"))
    sink.write(_evt(0, 1, "y"))
    sink.write(_evt(0, 2, "p"))
    sink.write(_evt(0, 2, "q"))
    fires = {e.check for e in inner.events if e.check.startswith("chain_")}
    assert fires == {"chain_a", "chain_b"}


def test_synthetic_event_inherits_pid_and_process() -> None:
    inner = _CapturingSink()
    sink = CorrelatingEventSink(inner, [copy_fail_rule()])
    sink.write(_evt(0, 99, "af_alg_socket", process="evil"))
    sink.write(_evt(SEC, 99, "splice_nonroot", process="evil"))
    synthetic = next(e for e in inner.events if e.check == "copy_fail_chain")
    assert synthetic.pid == 99
    assert synthetic.process == "evil"


def test_copy_fail_rule_window_conversion() -> None:
    rule = copy_fail_rule(window_seconds=2.5)
    assert rule.window_ns == 2_500_000_000
    assert rule.emit_check == "copy_fail_chain"
    assert rule.required == frozenset({"af_alg_socket", "splice_nonroot"})
