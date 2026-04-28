import pytest

from sources.predefined_programs import (
    commit_creds,
    icmp,
    ip_host,
    module_load,
    suid_exec,
    tcp_port,
    udp_port,
)


# --- suid_exec ---


def test_suid_exec_returns_string() -> None:
    assert isinstance(suid_exec(), str)


# --- tcp_port ---


def test_tcp_port_different_ports_differ() -> None:
    assert tcp_port(80) != tcp_port(443)


# --- icmp ---


def test_icmp_returns_string() -> None:
    assert isinstance(icmp(), str)


def test_icmp_is_deterministic() -> None:
    assert icmp() == icmp()


# --- ip_host ---


def test_ip_host_valid_address() -> None:
    prog = ip_host("10.0.0.1")
    assert isinstance(prog, str)


def test_ip_host_rejects_invalid_address() -> None:
    with pytest.raises(ValueError):
        ip_host("not-an-ip")


def test_ip_host_rejects_partial_address() -> None:
    with pytest.raises(ValueError):
        ip_host("192.168.1")


def test_ip_host_rejects_out_of_range_octet() -> None:
    with pytest.raises(ValueError):
        ip_host("256.0.0.1")


# --- commit_creds ---


def test_commit_creds_returns_string() -> None:
    assert isinstance(commit_creds(), str)


# --- module_load ---


def test_module_load_returns_string() -> None:
    assert isinstance(module_load(), str)


def test_module_load_is_deterministic() -> None:
    assert module_load() == module_load()
