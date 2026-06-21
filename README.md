# Network Diagnostics & Port Auditing Tool

A small Python command-line tool that checks which common network ports are
open on a target host, and resolves hostnames to IP addresses. Built using
only Python's standard library — no external dependencies.

## Overview

This tool automates a basic but genuinely useful security check: scanning a
small set of well-known ports (FTP, SSH, Telnet, DNS, HTTP, HTTPS) to see
which ones are open and responding. It's the kind of check a sysadmin or
security-conscious developer runs to catch services running on a machine
that shouldn't be exposed, or simply forgotten about.

This is a learning/auditing project, not a penetration testing tool. It is
designed to be run against `localhost` or hosts you own or have permission
to scan.

## How It Works

The core mechanism is the **TCP three-way handshake**:

1. The client sends a **SYN** packet to the target port, requesting a connection.
2. If a service is listening on that port, the target replies with **SYN-ACK**.
3. The client completes the handshake with an **ACK**, and the connection is established.

Python's `socket.connect_ex()` performs this handshake under the hood. If it
returns `0`, the handshake succeeded and the port is open. If it returns a
non-zero error code, the connection was refused (port closed) or the
attempt timed out (likely blocked by a firewall).

This script uses a **full TCP connect scan** (not a raw SYN scan) — meaning
it lets the OS complete the full handshake rather than crafting raw packets.
This is slower than a raw SYN scan but doesn't require elevated/root
permissions, which is why standard library sockets are enough.

## Why Open Ports Matter

An open port means *something* is listening for connections. That's not
inherently bad — a web server needs port 80/443 open. The risk shows up when:

- **A port is open that nobody intended to expose** (e.g. a forgotten test
  server, a misconfigured service) — that's an unmonitored attack surface.
- **An outdated or insecure service is reachable** (e.g. Telnet on port 23,
  which transmits everything, including passwords, unencrypted).
- **An open port reveals information via "banner grabbing"** — many services
  announce their name and version when you connect, which an attacker can
  use to look up known vulnerabilities for that exact version.

Routine, automated port auditing is one of the simplest ways to catch these
issues before someone else finds them first.

## How to Run

Requires Python 3.6 or later. No installation needed.

**Linux / macOS:**
```bash
python3 network_utility.py
```

**Windows (Command Prompt or PowerShell):**
```bash
python network_utility.py
```

You'll be prompted for a target hostname or IP. Press Enter to default to
`127.0.0.1` (your own machine).

## Example Output

```
[16:37:57] Starting port scan on 127.0.0.1
[16:37:57] Checking 6 common ports...

  Port 21    (FTP (File Transfer)           ) -> closed
  Port 22    (SSH (Remote Login)            ) -> closed
  Port 80    (HTTP (Web Server)             ) -> closed
  ...
[16:37:57] Scan complete. No common ports were open.
```

## Banner Grabbing

After a port is confirmed open, the tool can optionally attempt to read the
**banner** the service sends back — the short message many services use to
announce themselves. For example, a web server typically replies with a
`Server:` header revealing its exact software and version
(e.g. `SimpleHTTP/0.6 Python/3.12.3`).

This matters because that version string is exactly what an attacker would
use to look up known vulnerabilities for that specific software version —
so seeing it exposed is itself a small security signal worth knowing about.

This is enabled with a y/N prompt at runtime and is entirely passive: for
most ports we simply read whatever the service sends on connection; for
HTTP/HTTPS ports (which wait silently for a request) we send a single
minimal `HEAD / HTTP/1.0` request to prompt a reply — the same kind of
request any browser sends, not an exploit payload.

## Limitations (Honestly)

- Only checks 6 common ports, not the full range.
- Uses sequential (one-at-a-time) scanning, so it's slow on larger port
  ranges or remote hosts with high latency.
- Banner grabbing only sends an HTTP nudge for ports 80/443 — other
  services that wait for a specific protocol handshake (e.g. some
  database ports) won't return a banner without a more tailored request.
- TCP connect scan is easily logged by the target — it's not stealthy,
  and isn't meant to be.

## Possible Future Improvements

These are things I understand conceptually but haven't implemented yet:

- **`asyncio` instead of sequential scanning**: scanning ports one at a time
  is slow because each `connect_ex()` call waits for its own timeout.
  `asyncio` would let many port checks run concurrently instead.
- **Expanded port range**: scanning a configurable range (e.g. 1-1024)
  instead of a fixed list.
- **Protocol-specific banner probes**: sending tailored handshake bytes
  for services beyond HTTP (e.g. a minimal SMTP EHLO) to grab banners
  from more service types.

## Disclaimer

This tool only performs TCP connect attempts, the same kind any browser or
client app makes when connecting to a server. It does not exploit, attack,
or gain unauthorized access to anything. Only run it against systems you
own or have explicit permission to test.
