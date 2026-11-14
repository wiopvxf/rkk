# rkk — immunize, monitor and auto-remove a Linux rootkit family

A single static Go binary for hosts infected by (or targeted by) the
**child.malware / ninel / pam_master / processhider** rootkit family.

## Why static?

This malware writes a malicious library into `/etc/ld.so.preload`, so **every dynamically
linked program** on the box (`ls`, `ps`, `find`, `rm`, `kill`, `ss`, `last`) is hijacked:
processes, files, sockets and login records are all filtered or faked. A shell script
cannot even see the truth. `rkk` is built with `CGO_ENABLED=0`, never touches `ld.so` or
libc, and unlinks/kills through raw syscalls.

## Four capabilities

1. **Immunize** — pre-create immutable (`.rkk-vaccine`-marked, `chattr +i`) placeholder
   directories at all 76 known drop locations, and lock `/etc/ld.so.preload` as an
   immutable empty file. The malware's `open(O_CREAT)` returns `EISDIR`; removing the
   placeholder needs `chattr -i`, which even root cannot do silently.
2. **Instant rollback** — a 2-second patrol that removes only the malicious line/block,
   preserving legitimate admin edits.
3. **Auto-clean** — kill persistence (cron / systemd / initramfs) first, then kill the
   processes, then remove the files (backup + SHA-256 for oversized payloads).
4. **Self-heal** — `Restart=always`, dual binary copies, unit/binary recreated if deleted.

## Usage

```sh
./rkk-linux-amd64                 # read-only scan
./rkk-linux-amd64 clean -yes      # one-shot clean
./rkk-linux-amd64 install         # scan + immunize + systemd service
./rkk-linux-amd64 status
./rkk-linux-amd64 uninstall
```

## Tested

A 30-artifact simulated infection (real sample files, isolated mount): immunization
detects its own placeholders, first patrol cleans 37 changes with 0 failures, second
patrol is a no-op, and a simulated re-infection (fake `ninel` account, malicious cron,
40 MB payload) is reverted on the next patrol.

## Limitations

Single-host hardening only. An attacker with root can strip `chattr +i` within the
2-second window. If root, PAM master-password and initramfs were compromised, the trust
chain is broken — rebuild the host.

## Samples

Real malware samples are **not** part of the repository. Only hashes and IOCs are
published (`docs/IOC清单.txt`, `samples/SHA256SUMS.txt`). The encrypted sample archive
is distributed privately.

MIT licensed. Authorized hosts only.
