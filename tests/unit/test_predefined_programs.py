import pytest

from sources.predefined_programs import (
    commit_creds,
    icmp,
    ip_host,
    module_load,
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


# --- commit_creds ---


def test_commit_creds_returns_string() -> None:
    assert isinstance(commit_creds(), str)


def test_commit_creds_hooks_commit_creds() -> None:
    assert "kprobe__commit_creds" in commit_creds()


def test_commit_creds_uses_perf_output() -> None:
    assert "BPF_PERF_OUTPUT" in commit_creds()


def test_commit_creds_skips_already_root() -> None:
    prog = commit_creds()
    assert "old_uid == 0" in prog


def test_commit_creds_filters_non_escalation() -> None:
    prog = commit_creds()
    assert "new_uid != 0" in prog


def test_commit_creds_reads_new_uid_from_cred() -> None:
    assert "new->uid" in commit_creds()


# --- module_load ---


def test_module_load_returns_string() -> None:
    assert isinstance(module_load(), str)


def test_module_load_hooks_do_init_module() -> None:
    assert "kprobe__do_init_module" in module_load()


def test_module_load_uses_perf_output() -> None:
    assert "BPF_PERF_OUTPUT" in module_load()


def test_module_load_reads_module_name() -> None:
    assert "mod->name" in module_load()


def test_module_load_is_deterministic() -> None:
    assert module_load() == module_load()
