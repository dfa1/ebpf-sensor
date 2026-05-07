import pytest

from sources.predefined_programs import (
    af_alg_socket,
    commit_creds,
    dirtyfrag_esp,
    dirtyfrag_rxrpc,
    execve,
    icmp,
    ip_host,
    module_load,
    ptrace,
    sensitive_file_open,
    suid_exec,
    tcp_port,
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


# --- execve ---


def test_execve_returns_string() -> None:
    assert isinstance(execve(), str)


def test_execve_is_deterministic() -> None:
    assert execve() == execve()


# --- ptrace ---


def test_ptrace_returns_string() -> None:
    assert isinstance(ptrace(), str)


def test_ptrace_is_deterministic() -> None:
    assert ptrace() == ptrace()


# --- sensitive_file_open ---


def test_sensitive_file_open_returns_string() -> None:
    assert isinstance(sensitive_file_open("/etc/shadow"), str)


def test_sensitive_file_open_different_paths_differ() -> None:
    assert sensitive_file_open("/etc/shadow") != sensitive_file_open("/etc/passwd")


def test_sensitive_file_open_is_deterministic() -> None:
    assert sensitive_file_open("/etc/shadow") == sensitive_file_open("/etc/shadow")


def test_sensitive_file_open_rejects_relative_path() -> None:
    with pytest.raises(ValueError):
        sensitive_file_open("etc/shadow")


def test_sensitive_file_open_rejects_too_long_path() -> None:
    with pytest.raises(ValueError):
        sensitive_file_open("/" + "a" * 255)


# --- af_alg_socket ---


def test_af_alg_socket_returns_string() -> None:
    assert isinstance(af_alg_socket(), str)


def test_af_alg_socket_is_deterministic() -> None:
    assert af_alg_socket() == af_alg_socket()


# --- dirtyfrag_rxrpc ---


def test_dirtyfrag_rxrpc_returns_string() -> None:
    assert isinstance(dirtyfrag_rxrpc(), str)


def test_dirtyfrag_rxrpc_is_deterministic() -> None:
    assert dirtyfrag_rxrpc() == dirtyfrag_rxrpc()


def test_dirtyfrag_rxrpc_differs_from_esp() -> None:
    assert dirtyfrag_rxrpc() != dirtyfrag_esp()


# --- dirtyfrag_esp ---


def test_dirtyfrag_esp_returns_string() -> None:
    assert isinstance(dirtyfrag_esp(), str)


def test_dirtyfrag_esp_is_deterministic() -> None:
    assert dirtyfrag_esp() == dirtyfrag_esp()
