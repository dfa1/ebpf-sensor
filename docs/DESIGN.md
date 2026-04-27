# ebpf-sensor: Kernel Security Monitoring Design

## Overview

ebpf-sensor is a fleet-wide kernel security monitoring system built on eBPF/BCC. It attaches kprobes and LSM hooks to detect threats across 8 categories, emits structured events through a perf buffer, and ships them to a central SIEM via Kafka.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Linux Kernel                                                   │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ kprobe:      │  │ kprobe:      │  │ kprobe:      │  ...    │
│  │ security_    │  │ commit_creds │  │ __x64_sys_   │         │
│  │ bprm_check   │  │              │  │ execve       │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                  │                  │                 │
│         └──────────────────┴──────────────────┘                 │
│                            │                                    │
│                  ┌─────────▼─────────┐                         │
│                  │ BPF_PERF_OUTPUT   │                         │
│                  │ ("events" table)  │                         │
│                  └─────────┬─────────┘                         │
└────────────────────────────┼────────────────────────────────────┘
                             │ perf_buffer_poll()
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Userspace (Python / BCC)                                       │
│                                                                 │
│  BpfEventSource                                                 │
│    - Casts perf buffer data to _BpfEvent ctypes struct          │
│    - Yields Event(timestamp, pid, process, payload)             │
│                                                                 │
│  Pipeline:                                                      │
│    for event in source.events():                                │
│        sink.write(event)                                        │
│                                                                 │
│  KafkaEventSink                                                 │
│    - Serializes Event as JSON                                   │
│    - Produces to Kafka topic (partitioned by host)              │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Fleet SIEM / Detection Layer                                   │
│                                                                 │
│  Kafka topic: "ebpf-events"                                     │
│    → Streaming consumers (Flink/ksqlDB/custom)                  │
│    → Correlation engine (cross-host pattern matching)           │
│    → Alert routing (PagerDuty, Slack, SOAR)                    │
│    → Long-term storage (S3/Elasticsearch)                       │
└─────────────────────────────────────────────────────────────────┘
```

**Per-host agent**: One Python process per machine loads all BPF programs, polls the shared `events` perf buffer, and writes to Kafka. The agent runs as root (required for BPF).

**Event schema**: Every BPF program emits a struct compatible with `_BpfEvent` (ts u64, pid u32, comm char[16], payload char[256]). The `payload` field carries program-specific context (filename, address, syscall args) as a formatted string.

---

## Prioritized Hook Table

Priority: P0 = high-confidence / low-noise, P1 = useful with allowlisting, P2 = noisy baseline required.

| Hook Point | Type | Threat Category | Signal/Noise | Priority |
|---|---|---|---|---|
| `security_bprm_check` | LSM/kprobe | Privilege Escalation (SUID/SGID exec) | High signal; filter on mode bits | P0 |
| `commit_creds` | kprobe | Privilege Escalation (uid 0 transition) | High signal; uid!=0 -> uid==0 only | P0 |
| `__x64_sys_init_module` / `__x64_sys_finit_module` | kprobe | Kernel Module Abuse | High signal; rare on production hosts | P0 |
| `__x64_sys_execve` | tracepoint/kprobe | Anomalous Exec Chains, Persistence, Memory Exploitation (memfd exec) | Noisy; requires parent-tree allowlist | P1 |
| `__x64_sys_ptrace` | kprobe | Credential Theft (PTRACE_POKEDATA) | Medium; filter on request type | P1 |
| `__x64_sys_mprotect` | kprobe | Memory Exploitation (PROT_EXEC on anon) | Medium; filter on PROT_EXEC + anon VMA | P1 |
| `__x64_sys_socket` | kprobe | Network/Exfil (SOCK_RAW) | High signal if filtered to SOCK_RAW + non-root | P0 |
| `__x64_sys_unshare` | kprobe | Container Escape (CLONE_NEWUSER) | Medium; containers legitimately use this | P1 |
| `__x64_sys_mount` | kprobe | Container Escape (mount from container) | Medium; filter by pid namespace | P1 |
| `__x64_sys_bpf` | kprobe | eBPF Abuse (BPF_PROG_LOAD) | High signal; few processes should call this | P0 |
| `security_file_open` / `vfs_read` | kprobe | Credential Theft (/etc/shadow, /proc/pid/mem) | Noisy; requires path + process allowlist | P2 |
| `__x64_sys_setuid` | kprobe | Privilege Escalation (setuid(0)) | High signal; filter on arg==0 | P0 |
| `cap_capable` | kprobe | Privilege Escalation (unexpected capabilities) | Noisy; baseline required per binary | P2 |
| `__x64_sys_mmap` | kprobe | Memory Exploitation (MAP_FIXED near NULL) | Low noise if filtered to addr < PAGE_SIZE | P1 |
| `__x64_sys_prctl` | kprobe | Memory Exploitation (PR_SET_DUMPABLE,0) | Low signal alone; useful as enrichment | P2 |
| `security_path_rename` / `vfs_write` | kprobe | Persistence (/etc/cron*, ld.so.preload) | Medium; path prefix filter | P1 |
| `udp_sendmsg` | kprobe | Network/Exfil (DNS on non-53 ports) | Medium; filter dport!=53 + payload heuristic | P1 |
| `__x64_sys_pivot_root` / `__x64_sys_chroot` | kprobe | Container Escape | High signal; extremely rare in production | P0 |

---

## MITRE ATT&CK Integration

Every detection check maps to one ATT&CK tactic and technique. Tags are stamped onto Kafka messages **at the sensor**, not in the SIEM.

**Why at the sensor**: tagging in the SIEM requires a lookup or enrichment join on every incoming event — CPU and I/O that scales with fleet size. Doing it at the source means the SIEM receives pre-enriched events it can index and route directly, with no per-event fan-out. The policy config is deployed once per host via config management; the mapping cost is paid at config load, not at event time.

Concretely: a fleet of 1000 hosts emitting 10k events/s each would require 10M enrichment lookups/s in the SIEM. With sensor-side tagging that cost is zero in the SIEM — each event arrives with `mitre_tactic` and `mitre_technique` already set.

### Check → ATT&CK Mapping

| Check | Tactic | Tactic ID | Technique | Technique ID |
|---|---|---|---|---|
| `suid_exec` | Privilege Escalation | TA0004 | Abuse Elevation Control Mechanism: Setuid and Setgid | T1548.001 |
| `commit_creds` | Privilege Escalation | TA0004 | Exploitation for Privilege Escalation | T1068 |
| `module_load` | Persistence / Defense Evasion | TA0003 / TA0005 | Boot or Logon Autostart Execution: Kernel Modules | T1547.006 |
| `raw_socket` | Exfiltration | TA0010 | Exfiltration Over Alternative Protocol | T1048 |
| `bpf_prog_load` | Defense Evasion | TA0005 | Indicator Removal: Disable or Modify Tools | T1562.001 |
| `container_escape_unshare` | Privilege Escalation | TA0004 | Escape to Host | T1611 |
| `memfd_exec` | Defense Evasion | TA0005 | Reflective Code Loading | T1620 |
| `shadow_read` | Credential Access | TA0006 | OS Credential Dumping | T1003 |

### Kafka Message Schema (with MITRE)

```json
{
  "timestamp": 1714214400000000000,
  "pid": 1234,
  "process": "bash",
  "payload": "/usr/bin/sudo",
  "check": "suid_exec",
  "priority": "critical",
  "host": "worker-gpu-01",
  "mitre_tactic": "TA0004",
  "mitre_technique": "T1548.001"
}
```

`mitre_tactic` and `mitre_technique` are present only when the check has a configured MITRE mapping. Checks without a mapping emit without those fields.

### SIEM Usage

- **Coverage dashboard**: group by `mitre_tactic` to see which ATT&CK tactics have active detections.
- **Alert rules**: trigger on `mitre_technique == "T1068"` (privilege escalation) regardless of which underlying check fired.
- **Detection-as-code**: policy YAML is the source of truth for check → technique mapping. Changes are version-controlled and auditable.

### Policy Config Format

```yaml
default: info
rules:
  suid_exec:
    priority: critical
    mitre_tactic: "TA0004"
    mitre_technique: "T1548.001"
  commit_creds:
    priority: critical
    mitre_tactic: "TA0004"
    mitre_technique: "T1068"
  module_load:
    priority: high
    mitre_tactic: "TA0003"
    mitre_technique: "T1547.006"
  tcp_connect:
    priority: low
```

`mitre_tactic` / `mitre_technique` are optional per rule. `priority` is required.

---

## Threat Categories: Hook Details

### 1. Privilege Escalation

| Signal | Hook | Filter Logic |
|---|---|---|
| SUID/SGID exec | `security_bprm_check` | `inode->i_mode & (S_ISUID\|S_ISGID)` -- already implemented |
| setuid(0) | `__x64_sys_setuid` | arg0 == 0 AND current_uid != 0 |
| uid 0 transition | `commit_creds` | `new->uid == 0 && old->uid != 0` |
| Unexpected caps | `cap_capable` | comm not in allowlist for given cap |

### 2. Credential/Token Theft

| Signal | Hook | Filter Logic |
|---|---|---|
| /proc/pid/mem write | `vfs_write` + path check | path matches `/proc/*/mem` |
| ptrace injection | `__x64_sys_ptrace` | request == PTRACE_POKEDATA, target pid in sensitive set |
| /etc/shadow read | `security_file_open` | path == `/etc/shadow`, comm not in {login, passwd, sshd} |

### 3. Container Escape

| Signal | Hook | Filter Logic |
|---|---|---|
| User namespace creation | `__x64_sys_unshare` | flags & CLONE_NEWUSER, from within container pidns |
| Mount from container | `__x64_sys_mount` | caller in non-init pid namespace |
| /proc/sysrq-trigger | `security_file_open` | path match |
| pivot_root/chroot | `__x64_sys_pivot_root`, `__x64_sys_chroot` | any invocation outside init |

### 4. Kernel Module / eBPF Abuse

| Signal | Hook | Filter Logic |
|---|---|---|
| Module load | `__x64_sys_init_module` / `__x64_sys_finit_module` | any invocation (alert always) |
| BPF program load | `__x64_sys_bpf` | cmd == BPF_PROG_LOAD, comm not in allowlist |

### 5. Memory Exploitation

| Signal | Hook | Filter Logic |
|---|---|---|
| W^X on anon mapping | `__x64_sys_mprotect` | PROT_EXEC on VMA with no file backing |
| NULL-page map | `__x64_sys_mmap` | MAP_FIXED with addr < 4096 |
| memfd/shm exec | `__x64_sys_execve` | filename starts with `/dev/shm/`, `/tmp/`, `/proc/self/fd/` |
| Anti-dump | `__x64_sys_prctl` | PR_SET_DUMPABLE with arg2==0 (enrichment signal) |

### 6. Persistence

| Signal | Hook | Filter Logic |
|---|---|---|
| Cron writes | `vfs_write` / `security_path_rename` | path prefix `/etc/cron` |
| ld.so.preload | `vfs_write` | path == `/etc/ld.so.preload` |
| LD_PRELOAD in execve | `__x64_sys_execve` | scan envp for `LD_PRELOAD=` (limited by BPF stack/complexity) |

### 7. Network/Exfil

| Signal | Hook | Filter Logic |
|---|---|---|
| Raw socket | `__x64_sys_socket` | type == SOCK_RAW AND uid != 0 |
| DNS on non-standard port | `udp_sendmsg` | dport != 53, payload starts with DNS header pattern |

### 8. Anomalous Exec Chains

| Signal | Hook | Filter Logic |
|---|---|---|
| Shell from daemon | `__x64_sys_execve` | filename in {/bin/sh, /bin/bash, ...}, parent comm in {nginx, apache, java, ...} |
| Interpreter from svc acct | `__x64_sys_execve` | filename is interpreter, uid maps to service account |

Detection here relies on correlating `execve` events with parent process info (read from `task_struct->real_parent`).

---

## Extension Points: Adding a New BPF Program

Follow the pattern established in `sources/predefined_programs.py`:

1. **Define the BPF C program** as a Python function returning a string:
   ```python
   def setuid_zero() -> str:
       """Trace setuid(0) calls from non-root processes."""
       return """
   #include <uapi/linux/ptrace.h>
   ...
   BPF_PERF_OUTPUT(events);
   int kprobe____x64_sys_setuid(struct pt_regs *ctx) {
       // filter + emit to events table
   }
   """
   ```

2. **Use the standard event struct** for perf output (ts u64, pid u32, comm char[16], payload char[256]) so `BpfEventSource` can decode it without changes.

3. **Register in the sensor agent** by passing `BPF(text=setuid_zero())` and wrapping with `BpfEventSource(bpf, table="events")`.

4. **For parameterized programs** (like `tcp_port(port)`), accept arguments and use f-string interpolation into the C source. Validate inputs before interpolation to prevent BPF compilation errors.

5. **Testing**: Use `ReplayEventSource` with recorded NDJSON for integration tests. Unit test the program-generation function for correct C output.

---

## Limitations

### What eBPF/BCC Cannot Detect

| Limitation | Explanation |
|---|---|
| Kernel exploits that bypass LSM entirely | If an attacker gains arbitrary kernel write (e.g., via use-after-free), they can disable BPF programs or detach probes. eBPF is not a security boundary against kernel-level compromise. |
| Encrypted exfiltration over allowed ports | Data exfil over HTTPS/443 to an attacker-controlled domain is invisible at the syscall layer. Requires network-layer inspection or DNS/SNI monitoring. |
| Return-oriented attacks within BPF verifier limits | BPF programs cannot inspect arbitrary user-space memory deeply; stack/heap content analysis is limited by BPF instruction count and stack size (512 bytes). |
| TOCTOU on file paths | Path-based checks in BPF are racy. An attacker can rename paths between check and use. FD-based checks (via `struct file`) are more reliable but harder to implement. |
| Userspace-only attacks | Pure userspace exploitation (e.g., ROP chains, JIT spray within a process) does not trigger kernel hooks unless it results in a syscall. |
| BCC overhead on older kernels | BCC compiles C to BPF at runtime via LLVM. On kernels < 5.x, some features (BTF, CO-RE) are unavailable, increasing maintenance burden and startup latency. |
| Anti-forensics | Attacker with root can `bpftool prog detach` or unload the sensor's programs. Requires integrity monitoring of the sensor process itself (watchdog, signed binaries). |
| Container-aware filtering gaps | Determining whether a process is "in a container" requires reading cgroup/pidns info from `task_struct`, which adds complexity and may miss non-standard container runtimes. |

### Mitigations for Sensor Tampering

- Run the sensor under a dedicated cgroup with `BPF_F_PREALLOC` maps.
- Use `bpf_prog_pin` to persist programs in `/sys/fs/bpf/` (survives agent restart).
- Monitor agent liveness via a separate watchdog that alerts on process death or BPF program detachment.
- On kernels 5.7+, use `BPF_LSM` programs (non-detachable without CAP_SYS_ADMIN) instead of kprobes.

---

## Deployment Considerations

- **Kernel version matrix**: Target 5.4+ (LTS). BPF LSM requires 5.7+. CO-RE/BTF requires 5.2+.
- **Performance budget**: Each kprobe adds ~100-500ns per invocation. High-frequency hooks (`vfs_read`, `mprotect`) need aggressive in-kernel filtering to avoid saturating the perf buffer.
- **Perf buffer sizing**: Default 64 pages per CPU. For high-event hosts (build servers), increase to 256 pages or use BPF ring buffer (kernel 5.8+).
- **Kafka partitioning**: Partition by hostname to preserve per-host event ordering. Use a separate topic per severity tier if consumer lag becomes an issue.
- **Allowlist management**: Ship per-host allowlists (expected SUID binaries, authorized BPF users) as JSON config. Update via config management (Ansible/Puppet) or a central allowlist service.
