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
    """Trace execve of SUID/SGID binaries by inspecting inode mode bits at bprm check time."""
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
