# Mirage

**Mirage** is a zero-compromise **OpenSSH Frontline Reverse Proxy & Pre-Auth CVE Shield** written in Rust.

Mirage sits in front of your real OpenSSH `sshd` (e.g. Mirage on `0.0.0.0:22` -> real `sshd` on `127.0.0.1:22022`) so legitimate administrators experience 100% native OpenSSH authentication, keys, PAM, and SFTP, while pre-auth OpenSSH CVE exploits, malformed packets, slowloris/regreSSHion abuse, and scanners are intercepted **before ever touching `sshd`**.

---

## Quick Start

### One-Click Install & Auto-Configure OpenSSH

```bash
curl -fsSLO https://raw.githubusercontent.com/ProjectRalyn/Mirage/main/mirage.sh
chmod +x mirage.sh
sudo ./mirage.sh deploy
```

`mirage.sh deploy` will interactively:
1. Download `mirage-daemon` and create `/etc/mirage/config.toml`.
2. Configure per-category actions (`fail2ban`, `ssh_honeypot`, `endlessh_tarpit`, or `drop`) for brute-force bursts, pre-auth CVE probes, and scanner banners.
3. Optionally move local OpenSSH `sshd` to `127.0.0.1:22022` (handles `ssh.socket` and SELinux, validates with `sshd -t` + live banner probe, and **auto-rolls back** on any failure) so Mirage safely takes port `22`.

> Keep your current SSH session open and verify logging in from a new terminal before closing.  
> Common management commands: `sudo ./mirage.sh status`, `sudo ./mirage.sh logs`, `sudo ./mirage.sh sshd-restore`, `sudo ./mirage.sh uninstall`.

### Build from Source (Optional)

```bash
cargo build --release --workspace
sudo install -m 0755 target/release/mirage-daemon /usr/local/bin/mirage-daemon
sudo ./mirage.sh deploy
```

---

## Core Architecture

1. **Strict RFC 4253 Banner & Pre-Auth Timeout Gate**
   - Validates `SSH-2.0-` / `SSH-1.99-` prefix, max banner length (`255` bytes), and printable US-ASCII before opening an upstream connection to `sshd`.
   - Enforces a strict `preauth_timeout_secs` deadline across banner + key-exchange (`SSH_MSG_NEWKEYS`), mitigating pre-auth `LoginGraceTime` / race exploits (e.g. CVE-2024-6387 regreSSHion).

2. **Full-Duplex Pre-`NEWKEYS` Binary Packet & `sigil-filter` Inspection**
   - Parses unencrypted pre-`NEWKEYS` SSH binary packets (`packet_length`, `padding_length`, block alignment, allowed pre-KEX opcodes) and blocks out-of-state packets such as pre-KEX `SSH_MSG_USERAUTH_SUCCESS` (CVE-2018-10933), `SSH2_MSG_PING` (CVE-2025-26466), or Strict-KEX violations (Terrapin CVE-2023-48795).
   - Inspects every `SSH_MSG_KEXINIT` algorithm name-list and `SSH_MSG_DEBUG` string with [`sigil-filter`](https://crates.io/crates/sigil-filter) (~85 ns benign fast-path) to stop crafted buffer-overflow, command-injection, or control-byte payloads before forwarding untouched raw bytes to real `sshd`.

3. **Per-Category Configurable Defense Policies (`bruteforce_action` / `cve_exploit_action` / `scanner_action`)**
   - Independently choose `"fail2ban"`, `"ssh_honeypot"`, `"endlessh_tarpit"`, or `"drop"` for brute-force bursts, pre-auth CVE/sigil violations, and scanner banners.
   - `fail2ban`: Bans the source IP in Mirage's fixed-capacity O(1) memory table for `quarantine_secs` (0-CPU instant drop on reconnect) and emits `MIRAGE_BAN` lines (plus optional `ban_log_file` for host Fail2Ban/nftables integration).
   - `ssh_honeypot`: Seamlessly diverts into Mirage's pure-Rust SSH-2 honeypot (using the cached real upstream banner, stable Ed25519 host key, Strict-KEX, `aes128-ctr`/`aes256-ctr`, `hmac-sha2-256`/`hmac-sha2-512`, `EXT_INFO`, and bounded in-memory shell) with strict anti-CC session caps.
   - `endlessh_tarpit`: Traps scanners in a slow pre-banner Endlessh drip loop.
   - `drop`: Closes the offending connection immediately.

---

## Workspace Structure

```text
Mirage/
├── crates/
│   ├── mirage-core   # Configuration, O(1) anti-CC/ban guard, sigil-filter integration, persona & fake-shell sink
│   ├── mirage-ssh    # Frontline SSH reverse proxy, RFC 4253 & KEXINIT inspector, Endlessh tarpit, SSH-2 honeypot
│   └── mirage-bin    # `mirage-daemon` CLI & systemd entrypoint
├── config.example.toml
└── mirage.sh
```
