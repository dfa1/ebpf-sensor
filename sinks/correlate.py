from collections.abc import Iterable
from dataclasses import dataclass

from event import Event
from sinks.sink import EventSink


@dataclass(frozen=True)
class CorrelationRule:
    """Emit a synthetic Event when every check in `required` has been observed
    for the same pid within `window_ns` of each other.

    Used to express attack-chain detection. The Copy Fail / DirtyFrag class
    is the motivating case: af_alg_socket (init) and splice_nonroot (trigger)
    are each individually low-signal (cryptsetup uses AF_ALG; nginx uses
    splice), but together on the same non-root pid within a few seconds
    they are the canonical Copy Fail exploit signature documented by
    Elastic, Sysdig, and Stream.Security.

    name        identifier for the rule (logs/debugging only)
    required    set of `Event.check` names that must all fire for one pid
    window_ns   max gap between first and last observation (nanoseconds,
                matching Event.timestamp units = bpf_ktime_get_ns)
    emit_check  `check` field on the synthetic Event
    emit_payload optional payload string on the synthetic Event
    """

    name: str
    required: frozenset[str]
    window_ns: int
    emit_check: str
    emit_payload: str = ""


class CorrelatingEventSink:
    """EventSink decorator: forwards every event to `inner`, and when a
    CorrelationRule's `required` set is satisfied for one pid inside its
    time window, emits an additional synthetic Event to `inner` tagged
    with the rule's `emit_check`.

    State is bounded: only the most recent timestamp of each required
    check is kept per (rule, pid). Stale entries (older than window_ns
    behind the current event's timestamp) are evicted on every write,
    so memory is O(rules * active_pids_in_window).

    Re-fire suppression: once a rule fires for a pid, it will not fire
    again for that pid until window_ns has elapsed. Without this an
    attacker looping the chain would generate one synthetic event per
    inner event.
    """

    def __init__(self, inner: EventSink, rules: Iterable[CorrelationRule]) -> None:
        self._inner = inner
        self._rules: list[CorrelationRule] = list(rules)
        self._seen: list[dict[int, dict[str, int]]] = [{} for _ in self._rules]
        self._fired: list[dict[int, int]] = [{} for _ in self._rules]

    def write(self, event: Event) -> None:
        self._inner.write(event)
        for idx, rule in enumerate(self._rules):
            if event.check not in rule.required:
                continue
            per_pid = self._seen[idx].setdefault(event.pid, {})
            per_pid[event.check] = event.timestamp
            self._evict_stale(idx, rule, event.timestamp)
            if not rule.required.issubset(per_pid.keys()):
                continue
            last_fire = self._fired[idx].get(event.pid)
            if last_fire is not None and event.timestamp - last_fire < rule.window_ns:
                continue
            self._fired[idx][event.pid] = event.timestamp
            self._inner.write(
                Event(
                    timestamp=event.timestamp,
                    pid=event.pid,
                    process=event.process,
                    payload=rule.emit_payload or rule.name,
                    check=rule.emit_check,
                )
            )

    def _evict_stale(self, idx: int, rule: CorrelationRule, now_ns: int) -> None:
        cutoff = now_ns - rule.window_ns
        per_pid = self._seen[idx]
        for pid in list(per_pid.keys()):
            checks = per_pid[pid]
            for cname in list(checks.keys()):
                if checks[cname] < cutoff:
                    del checks[cname]
            if not checks:
                del per_pid[pid]
        fired = self._fired[idx]
        for pid in list(fired.keys()):
            if fired[pid] < cutoff:
                del fired[pid]


def copy_fail_rule(window_seconds: float = 5.0) -> CorrelationRule:
    """Predefined CorrelationRule for the Copy Fail / DirtyFrag class.

    Fires when both af_alg_socket and splice_nonroot are observed for the
    same pid within `window_seconds`. af_alg_bind_aead is intentionally
    not required — the AEAD bind is itself high-signal (authencesn is
    never used legitimately) and should be alerted on directly, not
    gated on chain completion.

    Sources:
      https://www.elastic.co/security-labs/copy-fail-dirtyfrag-linux-page-bugs-in-the-wild
      https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds
      https://www.stream.security/post/cve-2026-31431-how-copy-fail-behaves-in-kubernetes
    """
    return CorrelationRule(
        name="copy_fail",
        required=frozenset({"af_alg_socket", "splice_nonroot"}),
        window_ns=int(window_seconds * 1_000_000_000),
        emit_check="copy_fail_chain",
        emit_payload="af_alg_socket + splice_nonroot on same pid",
    )
