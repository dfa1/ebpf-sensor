# tests/triggers

Manual trigger programs for validating sensor detections on a live Linux host.
These are Linux-only; they will not compile on macOS.

---

## rxrpc_trigger — DirtyFrag RxRPC variant

Exercises the `dirtyfrag_rxrpc` sensor by calling `add_key("rxrpc", ...)` as a
non-root user, then driving an AF_RXRPC handshake toward `rxkad_verify_packet_1`.

### Requirements

- Linux kernel with `CONFIG_AF_RXRPC=y` (most distro kernels have it)
- gcc
- Run as **non-root** (the sensor filters out uid=0)
- The ebpf-sensor loaded with the `dirtyfrag_rxrpc` program

### Steps

**1. On the Linux host — start the sensor (as root)**

```bash
sudo python bpf_to_file.py   # or however you load the sensor
```

**2. Compile the trigger (as any user)**

```bash
gcc -O0 -o rxrpc_trigger tests/triggers/rxrpc_trigger.c
```

**3. Run as non-root**

```bash
./rxrpc_trigger
```

Expected output:

```
[+] rxrpc key id=12345
[+] sendmsg sent — rxkad_verify_packet_1 should have been reached
[+] done — check your sensor output
```

**4. Verify the sensor fired**

The sensor should emit an event with:
- `check`: `dirtyfrag_rxrpc`
- `comm`: `rxrpc_trigger`
- `pid`: PID of the trigger process

### What it does

1. Calls `add_key("rxrpc", "sensor_test", ...)` — this is the detection point.
   The sensor fires here; the rest of the program is not needed for detection
   but exercises the deeper handshake path.
2. Opens a fake UDP server on 127.0.0.1:7779.
3. Creates an AF_RXRPC client socket with RXKAD security level 1.
4. Sends a call via `sendmsg`, driving the RxRPC state machine toward
   `rxkad_verify_packet_1`.

### Kernel requirement note

If `socket(AF_RXRPC, ...)` returns `EAFNOSUPPORT`, the kernel lacks AF_RXRPC
support. The `add_key` detection (step 1) still fires regardless.
