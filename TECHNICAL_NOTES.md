# Technical Notes

This document explains the networking and security concepts underlying
this tool, including the design rationale and trade-offs behind each
implementation decision.

---

## 1. Background: Ports and Why They Matter

A single machine has one IP address but can run many network services at
once (a web server, an SSH daemon, a mail server). Ports are how the
operating system distinguishes between these services — the IP address
identifies the machine, and the port number identifies which service on
that machine a connection is intended for.

Ports range from 0 to 65535. Ports 0–1023 are reserved "well-known ports"
for standard services (e.g. 80 for HTTP, 22 for SSH), which is why this
tool checks them specifically.

## 2. What Port Scanning Does

Port scanning works by attempting a normal TCP connection to a port and
observing the result. This is the same underlying action a browser
performs when loading a website — no exploitation is involved.

Three possible outcomes:
- **Open** — a service is listening and the connection succeeds.
- **Closed** — nothing is listening; the OS immediately refuses the connection.
- **Filtered** — a firewall silently drops the packet, producing no response (observed as a timeout).

## 3. The TCP Three-Way Handshake

TCP — the protocol underlying HTTP, HTTPS, SSH, and FTP — establishes
connections using a three-step handshake:

```
   Client                          Server
     |                                |
     |---------- SYN -------------->  |   Connection request
     |                                |
     |<------- SYN-ACK -------------  |   Acknowledged, ready
     |                                |
     |---------- ACK -------------->  |   Connection established
     |                                |
     |======= Connection Open ======  |
```

**Design choice — connect scan vs. SYN scan:** This tool performs a
**full TCP connect scan**, completing all three handshake steps via the
operating system's standard socket interface. Tools such as `nmap` can
alternatively perform a **raw SYN scan** — sending only the initial SYN
and inspecting the response without completing the handshake. A SYN scan
is faster and leaves a smaller log footprint, but requires raw socket
access and elevated (root/admin) privileges. This tool intentionally uses
a connect scan to remain dependency-free and runnable without elevated
permissions.

## 4. Connection Handling — `socket.connect_ex()`

```python
result = sock.connect_ex((target_ip, port))
```

This single call performs the handshake and returns `0` on success or a
platform-specific error code (e.g. `ECONNREFUSED`) otherwise. The `_ex`
variant is used in place of plain `.connect()` because it returns an
error code rather than raising an exception, simplifying control flow.

## 5. Hostname Resolution

```python
ip_address = socket.gethostbyname(target)
```

DNS (Domain Name System) translates human-readable hostnames into IP
addresses, which are what's actually required for routing. This call
queries the system's configured DNS resolver to perform that translation.

## 6. Timeout Handling

```python
sock.settimeout(1.0)
```

Without an explicit timeout, a connection attempt to a filtered port
(one silently dropped by a firewall) would block indefinitely. Setting a
timeout ensures the scan can always proceed to the next port within a
bounded time.

## 7. Banner Grabbing and Its Security Relevance

Once a port is confirmed open, many services announce themselves
immediately — for example, an SSH server typically responds with a string
such as `SSH-2.0-OpenSSH_8.2`. This tool implements banner grabbing as a
read-only, passive operation: for most services it simply reads whatever
is sent on connection, and for HTTP/HTTPS ports (which wait for a request
before responding) it sends a minimal `HEAD / HTTP/1.0` request to prompt
a reply.

**Security relevance:** exposing exact service/version information lowers
the effort required for an attacker to identify known vulnerabilities
(CVEs) associated with that specific version. Automated banner auditing
helps surface this exposure proactively.

## 8. Performance Considerations — Sequential Scanning vs. `asyncio`

The current implementation scans ports sequentially, with each check
bounded by its own timeout. This is sufficient for a small, fixed set of
common ports but scales poorly to larger port ranges, since total scan
time grows linearly with the number of ports checked.

A natural enhancement is to use Python's `asyncio` to run multiple port
checks concurrently. This is *concurrency through cooperative waiting*,
not *parallelism* across CPU cores — well suited to I/O-bound tasks like
network scanning, and the standard approach used internally by most
modern scanning tools.

## 9. Design Philosophy: Why Not Just Use `nmap`?

`nmap` is the industry-standard tool for this purpose and is far more
capable. This project was built from first principles, using raw sockets
rather than a pre-built scanning library, specifically to demonstrate
understanding of what a tool like `nmap` is doing underneath its
interface — this is a fundamentals-focused learning project, not a
production replacement for established tooling.

---

## Summary of Trade-offs

| Decision | Choice Made | Reason |
|---|---|---|
| Scan type | Full TCP connect scan | No elevated privileges required |
| Concurrency | Sequential | Simplicity for a small, fixed port set |
| Dependencies | Standard library only | Zero-install portability |
| Banner grabbing | Passive, read-only | No risk of triggering unintended service behavior |
