import pytest

from sources.predefined_programs import (
    icmp,
    ip_host,
    suid_exec,
    tcp_connect,
    tcp_port,
    udp_port,
)


# --- suid_exec ---


def test_suid_exec_returns_string() -> None:
    assert isinstance(suid_exec(), str)


def test_suid_exec_hooks_security_bprm_check() -> None:
    prog = suid_exec()
    assert "kprobe__security_bprm_check" in prog


def test_suid_exec_checks_suid_bit() -> None:
    prog = suid_exec()
    assert "S_ISUID" in prog


def test_suid_exec_checks_sgid_bit() -> None:
    prog = suid_exec()
    assert "S_ISGID" in prog


def test_suid_exec_uses_perf_output() -> None:
    prog = suid_exec()
    assert "BPF_PERF_OUTPUT" in prog


def test_suid_exec_reads_filename_from_bprm() -> None:
    prog = suid_exec()
    assert "bprm->filename" in prog


def test_suid_exec_includes_mode_in_event() -> None:
    prog = suid_exec()
    assert "ev.mode" in prog


def test_suid_exec_filters_non_suid() -> None:
    prog = suid_exec()
    # early-return when neither SUID nor SGID set
    assert "return 0" in prog


# --- tcp_port ---


def test_tcp_port_embeds_port_number() -> None:
    prog = tcp_port(8080)
    assert "8080" in prog


def test_tcp_port_different_ports_differ() -> None:
    assert tcp_port(80) != tcp_port(443)


# --- tcp_connect ---


def test_tcp_connect_embeds_port_number() -> None:
    prog = tcp_connect(443)
    assert "443" in prog


# --- udp_port ---


def test_udp_port_embeds_port_number() -> None:
    prog = udp_port(53)
    assert "53" in prog


# --- icmp ---


def test_icmp_returns_string() -> None:
    assert isinstance(icmp(), str)


def test_icmp_is_deterministic() -> None:
    assert icmp() == icmp()


# --- ip_host ---


def test_ip_host_valid_address() -> None:
    prog = ip_host("10.0.0.1")
    assert isinstance(prog, str)
    assert "10.0.0.1" in prog


def test_ip_host_rejects_invalid_address() -> None:
    with pytest.raises(ValueError):
        ip_host("not-an-ip")


def test_ip_host_rejects_partial_address() -> None:
    with pytest.raises(ValueError):
        ip_host("192.168.1")


def test_ip_host_rejects_out_of_range_octet() -> None:
    with pytest.raises(ValueError):
        ip_host("256.0.0.1")
