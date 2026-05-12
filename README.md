# ebpf-sensor

eBPF event pipeline with pluggable sources and sinks.
Companion for [this article about BPF](https://dfa1.github.io/articles/from-bpf-to-ebpf-twenty-years-later).


## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync
```

## Usage

```python
from sources.ebpf import EBPFEventSource
from sinks.kafka import KafkaEventSink

source = EBPFEventSource(bpf_prog=open("prog.c").read())
sink = KafkaEventSink(bootstrap_servers="localhost:9092", topic="events")
for event in source.events():
    sink.write(event)
```

## Development

```bash
uv run python -m pytest  # tests
uv run python -m .       # type check
uv run ruff format .     # format
uv run ruff check .      # lint
```

## TODO

- Detect [Copy Fail 2: Electric Boogaloo](https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo) — unprivileged LPE via xfrm ESP-in-UDP `MSG_SPLICE_PAGES` no-COW fast path (same class as CVE-2026-31431). Sensor ideas:
  - kprobe `esp4_input` / `esp6_input` correlated with unprivileged UID
  - xfrm_user netlink socket activity from non-root userns
  - auto-load of `esp4` / `xfrm_user` / `xfrm_algo` from unprivileged context
  - page-cache writes to `/etc/passwd` (and other sensitive files) following ESP traffic on loopback
- Detect the **Copy Fail class** generically — `MSG_SPLICE_PAGES` / `splice()` / `sendfile()` fast paths that bypass copy-on-write and let unprivileged writers reach page cache of read-only-mapped files. Sensor ideas:
  - kprobe `splice_to_pipe`, `iov_iter_extract_pages`, `skb_splice_from_iter`, `__splice_from_pipe` — flag when source skb/iter originates from unprivileged socket and target inode is world-readable + root-owned
  - tracepoint on `MSG_SPLICE_PAGES` flag in `sendmsg` (`sock_sendmsg` kprobe, inspect `msg_flags`)
  - correlate `mark_page_accessed` / `set_page_dirty` on `address_space` of sensitive inodes (`/etc/passwd`, `/etc/shadow`, suid binaries) with non-root `current_uid()`
  - LSM `file_permission` deny-bypass: write-effect on inode without preceding `vfs_write` / `vfs_writev` from same task
- Detect tampering and privilege abuse around setuid binaries and credential files. Avoid alerting on bare `open` (world-readable files = huge noise; open ≠ modify; misses page-cache writes that bypass VFS). Layered approach:
  - **Credential-file tamper**: kprobe `vfs_write` / `notify_change` / LSM `security_inode_setattr` on inode set `{/etc/passwd, /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/*}` with `current_uid() != 0` → high-signal alert. Match by `(dev, ino)` captured at boot, not path string (survives bind-mounts, distro variance).
  - **Setuid exec**: LSM `bprm_check_security` (or kprobe `exec_binprm`) where `binprm->file->f_inode->i_mode & (S_ISUID|S_ISGID)`. Log caller uid, target inode, argv[0]. Cheap inode-mode check, distro-independent.
  - **Privilege transition**: kretprobe `commit_creds`, compare `old->euid` vs `new->euid`. Flag non-root → root transitions; correlate with recent setuid-exec event for context.
  - **Page-cache tamper (covers Copy Fail class)**: kprobe `set_page_dirty` / `mark_buffer_dirty` where `page->mapping->host` ∈ sensitive inode set and no `vfs_write` from `current` task in last N ms. Catches `MSG_SPLICE_PAGES` no-COW writes that never hit `file_open` / `vfs_write`.
  - **Skip**: open-only hooks, static path lists, parent-comm allowlists (rot under `systemd-run`, `tmux`, container runtimes), `(inode, pid)` rate-limits (useless for one-shot exploits).

## License

MIT
