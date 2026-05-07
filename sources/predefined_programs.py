# BPF programs for use with BCC's BPF(text=...).
# Filter concepts ported from classical BPF to eBPF:
# https://github.com/dfa1/pangolin/blob/master/src/filters.c


def tcp_port(port: int) -> str:
    """Trace inbound TCP connections accepted on the given port."""
    return f"""
#include <net/sock.h>
#include <net/inet_sock.h>

void kprobe__inet_csk_accept(struct pt_regs *ctx, struct sock *sk) {{
    struct inet_sock *inet = inet_sk(sk);
    u16 lport = inet->inet_sport;
    if (ntohs(lport) != {port}) return;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("tcp_accept port={port} pid=%d comm=%s\\n", pid, comm);
}}
"""


def tcp_connect(port: int) -> str:
    """Trace outbound TCP connections to the given destination port."""
    return f"""
#include <net/sock.h>

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {{
    u16 dport = sk->__sk_common.skc_dport;
    if (ntohs(dport) != {port}) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("tcp_connect port={port} pid=%d comm=%s\\n", pid, comm);
    return 0;
}}
"""


def udp_port(port: int) -> str:
    """Trace UDP datagrams sent to the given destination port."""
    return f"""
#include <net/sock.h>

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {{
    struct inet_sock *inet = inet_sk(sk);
    u16 dport = inet->inet_dport;
    if (ntohs(dport) != {port}) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("udp_send port={port} pid=%d comm=%s\\n", pid, comm);
    return 0;
}}
"""


def icmp() -> str:
    """Trace outbound ICMP packets (e.g. ping)."""
    return """
#include <net/sock.h>

int kprobe__icmp_push_reply(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("icmp pid=%d comm=%s\\n", pid, comm);
    return 0;
}
"""


def suid_exec() -> str:
    """Trace execve of SUID/SGID binaries by inspecting inode mode bits
    at bprm check time.
    """
    return """
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256
#define S_ISUID       0004000
#define S_ISGID       0002000

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__security_bprm_check(struct pt_regs *ctx, struct linux_binprm *bprm) {
    struct inode *inode = bprm->file->f_inode;
    umode_t mode = 0;
    bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    if (!(mode & (S_ISUID | S_ISGID))) return 0;

    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_kernel_str(ev.payload, sizeof(ev.payload), bprm->filename);

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


def commit_creds() -> str:
    """Trace privilege escalation: non-root process committing uid=0 credentials."""
    return """
#include <uapi/linux/ptrace.h>
#include <linux/cred.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__commit_creds(struct pt_regs *ctx, struct cred *new) {
    u32 old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (old_uid == 0) return 0;

    u32 new_uid = 0;
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid);
    if (new_uid != 0) return 0;

    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


def module_load() -> str:
    """Trace kernel module loading via do_init_module."""
    return """
#include <uapi/linux/ptrace.h>
#include <linux/module.h>
#include <linux/sched.h>

#define TASK_COMM_LEN    16
#define PAYLOAD_LEN      256
#define MODULE_NAME_LEN  56

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__do_init_module(struct pt_regs *ctx, struct module *mod) {
    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_kernel_str(ev.payload, sizeof(ev.payload), mod->name);

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


def execve() -> str:
    """Trace all execve syscalls (process execution)."""
    return """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(ev.payload, sizeof(ev.payload), args->filename);
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""


def ptrace() -> str:
    """Trace ptrace calls via security_ptrace_access_check
    (process injection / debugging).
    """
    return """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__security_ptrace_access_check(struct pt_regs *ctx,
    struct task_struct *child, unsigned int mode) {
    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_kernel_str(ev.payload, sizeof(ev.payload), child->comm);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""


def sensitive_file_open(path: str) -> str:
    """Trace opens of a specific absolute file path (e.g. /etc/shadow).

    Uses compile-time unrolled byte comparison — no BPF loops,
    works on all kernel versions.
    """
    if not path.startswith("/"):
        raise ValueError(f"path must be absolute: {path!r}")
    path_bytes = path.encode("utf-8")
    if len(path_bytes) > 255:
        raise ValueError(f"path too long (max 255 bytes): {path!r}")
    comparisons = (
        " ||\n        ".join(f"fname[{i}] != {b}" for i, b in enumerate(path_bytes))
        + f" ||\n        fname[{len(path_bytes)}] != 0"
    )
    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256

struct event_t {{
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
}};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {{
    char fname[PAYLOAD_LEN];
    bpf_probe_read_user_str(fname, sizeof(fname), args->filename);
    if ({comparisons}) return 0;

    struct event_t ev = {{}};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    __builtin_memcpy(ev.payload, fname, sizeof(ev.payload));
    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}}
"""


def af_alg_socket() -> str:
    """Detect copy.fail (CVE-2026-31431): non-root process creating AF_ALG sockets.

    The exploit creates ~40 sequential AF_ALG (family=38) sockets to perform
    controlled page-cache writes via splice(), overwriting setuid binaries to
    gain root. Any non-root AF_ALG socket creation is anomalous — legitimate
    AF_ALG users (cryptsetup, fscrypt) run as root.

    MITRE: TA0004 Privilege Escalation / T1068 Exploitation for Privilege Escalation
    """
    return """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256
#define AF_ALG        38

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (args->family != AF_ALG) return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) return 0;

    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""


def dirtyfrag_rxrpc() -> str:
    """Detect DirtyFrag (RxRPC variant): non-root add_key with 'rxrpc' keytype.

    The RxRPC exploit calls add_key("rxrpc", ...) three times to register
    brute-forced session keys for RXKAD authentication. These keys enable
    in-place pcbc(fcrypt) decryption on splice-planted page-cache pages,
    bypassing the missing skb_cloned() COW check in rxkad_verify_packet_1().
    The 'rxrpc' keytype is never legitimately used by non-root processes.

    MITRE: TA0004 Privilege Escalation / T1068 Exploitation for Privilege Escalation
    """
    return """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef int key_serial_t;

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   256

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_add_key) {
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) return 0;

    /* Check keytype == "rxrpc"; BCC renames the 'type' field to '_type' */
    char ktype[8] = {};
    bpf_probe_read_user_str(ktype, sizeof(ktype), args->_type);
    if (ktype[0] != 'r' || ktype[1] != 'x' || ktype[2] != 'r' ||
        ktype[3] != 'p' || ktype[4] != 'c' || ktype[5] != 0) return 0;

    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(ev.payload, sizeof(ev.payload), args->_description);

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""


def dirtyfrag_esp() -> str:
    """Detect DirtyFrag (ESP variant): non-root enabling UDP_ENCAP_ESPINUDP.

    The ESP exploit calls setsockopt(IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
    from a user-namespaced non-root process to enable ESP-in-UDP encapsulation.
    This allows crafted IPsec packets to reach esp_input(), where the missing
    skb_has_frag_list() guard lets splice-planted page-cache pages bypass
    skb_cow_data(), writing attacker-controlled values via scatterwalk_map_and_copy().
    Legitimate UDP_ENCAP_ESPINUDP users (VPN daemons, racoon, strongSwan) run as root.

    MITRE: TA0004 Privilege Escalation / T1068 Exploitation for Privilege Escalation
    """
    return """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN      16
#define PAYLOAD_LEN        256
#define IPPROTO_UDP        17
#define UDP_ENCAP          100
#define UDP_ENCAP_ESPINUDP 2

struct event_t {
    u64  ts;
    u32  pid;
    char comm[TASK_COMM_LEN];
    char payload[PAYLOAD_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_setsockopt) {
    if (args->level != IPPROTO_UDP) return 0;
    if (args->optname != UDP_ENCAP) return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) return 0;

    int encap_type = 0;
    bpf_probe_read_user(&encap_type, sizeof(encap_type), (void *)args->optval);
    if (encap_type != UDP_ENCAP_ESPINUDP) return 0;

    struct event_t ev = {};
    ev.ts  = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""


def ip_host(addr: str) -> str:
    """Trace TCP connections to or from the given IPv4 address (dotted decimal)."""
    octets = [int(o) for o in addr.split(".")]
    if len(octets) != 4 or not all(0 <= o <= 255 for o in octets):
        raise ValueError(f"invalid IPv4 address: {addr!r}")
    ip_be = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return f"""
#include <net/sock.h>

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {{
    u32 daddr = sk->__sk_common.skc_daddr;
    if (daddr != htonl({ip_be})) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("ip_host {addr} pid=%d comm=%s\\n", pid, comm);
    return 0;
}}
"""
