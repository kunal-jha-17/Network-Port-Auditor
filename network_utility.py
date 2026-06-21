#!/usr/bin/env python3
"""
Network Diagnostics & Port Auditing Tool
------------------------------------------
A small command-line tool to check which common ports are open on a target
host, and to resolve a hostname to an IP address.

Why this exists:
Open network ports are how services talk to the outside world. A port being
"open" means some program on that machine is listening for connections on it.
If a port is open and you didn't expect it to be, that's worth investigating —
it might be an attack surface (an unauthorized service, an old forgotten
server, a misconfiguration). This tool automates the boring part of checking
that, the same way a security audit script would.

Only uses Python's built-in standard library — no pip installs needed.
"""

import socket
import sys
import time
from datetime import datetime

# A short list of well-known ports and what they're normally used for.
# Checking "common" ports first is standard practice — scanning all 65535
# ports takes a long time and most useful information comes from these.
COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Remote Login)",
    23: "Telnet (Insecure Remote Login)",
    53: "DNS (Domain Name Lookup)",
    80: "HTTP (Web Server)",
    443: "HTTPS (Secure Web Server)",
}


def log(message):
    """Print a message with a timestamp, so output reads like a real audit log."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")


def resolve_hostname(target):
    """
    Convert a hostname (like 'example.com') into an IP address.

    socket.gethostbyname() does a DNS lookup under the hood — the same
    process your browser does before it can connect to a website.
    """
    try:
        ip_address = socket.gethostbyname(target)
        log(f"Resolved '{target}' -> {ip_address}")
        return ip_address
    except socket.gaierror:
        # gaierror = "getaddrinfo error" — raised when the hostname is invalid
        # or doesn't exist (e.g. you typed it wrong, or there's no internet).
        log(f"ERROR: Could not resolve hostname '{target}'. Check spelling or network connection.")
        return None


def check_port(target_ip, port, timeout=1.0):
    """
    Try to open a TCP connection to a single port on the target.

    How this actually works (the TCP 3-way handshake):
    1. We send a SYN packet (a connection request).
    2. If a service is listening on that port, it replies with SYN-ACK.
    3. We complete the handshake with an ACK, and the connection succeeds.
    If nothing is listening, the OS replies with a "connection refused"
    (RST packet), or the connection just times out if a firewall is silently
    dropping the packet.

    socket.connect_ex() does steps 1-3 for us and returns 0 on success,
    or a non-zero error code if the connection failed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            return True  # Port is open
        else:
            return False  # Port is closed or filtered
    except socket.error as e:
        log(f"Socket error while checking port {port}: {e}")
        return False
    finally:
        sock.close()  # Always release the socket, even if something went wrong


def banner_grab(target_ip, port, timeout=1.5):
    """
    Connect to an open port and try to read whatever the service sends back.

    Many services announce themselves immediately on connection (a "banner") -
    e.g. an SSH server typically sends a string like "SSH-2.0-OpenSSH_8.2".
    Some services (like HTTP) wait for a request before responding, so for
    those we send a minimal request first to prompt a reply.

    This is read-only and passive: we are not sending exploit payloads or
    authentication attempts, only the same kind of request a normal client
    would send to start a conversation with the service.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target_ip, port))

        # HTTP/HTTPS-style services usually wait silently for a request,
        # so we nudge them with a minimal valid HTTP request line.
        if port in (80, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else None
    except socket.timeout:
        return None  # Service didn't send anything within the timeout - that's fine
    except socket.error:
        return None
    finally:
        sock.close()


def scan_common_ports(target_ip, grab_banners=False):
    """Run check_port() against every port in COMMON_PORTS and report results."""
    log(f"Starting port scan on {target_ip}")
    log(f"Checking {len(COMMON_PORTS)} common ports...\n")

    open_ports = []

    for port, description in COMMON_PORTS.items():
        is_open = check_port(target_ip, port)
        status = "OPEN" if is_open else "closed"
        if is_open:
            open_ports.append(port)
        print(f"  Port {port:<5} ({description:<30}) -> {status}")

        # Only attempt banner grabbing on ports we just confirmed are open -
        # there's no point trying to read from a connection that doesn't exist.
        if is_open and grab_banners:
            banner = banner_grab(target_ip, port)
            if banner:
                # Show only the first line - banners can sometimes be multi-line
                first_line = banner.splitlines()[0]
                print(f"           -> Banner: {first_line}")
            else:
                print(f"           -> Banner: (no response / service didn't announce itself)")

        time.sleep(0.05)  # Small delay so output doesn't flood the terminal instantly

    print()
    if open_ports:
        log(f"Scan complete. Open ports found: {open_ports}")
    else:
        log("Scan complete. No common ports were open.")


def main():
    print("=" * 55)
    print("   Network Diagnostics & Port Auditing Tool")
    print("=" * 55)
    print()

    # Default to localhost if the user doesn't specify a target.
    # Scanning localhost is always safe — you're only checking your own machine.
    target = input("Enter target hostname or IP (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    # Ask whether to attempt banner grabbing on any open ports found.
    # This is optional because it adds time and isn't always useful
    # (closed/filtered ports have nothing to grab a banner from).
    grab_choice = input("Attempt banner grabbing on open ports? (y/N): ").strip().lower()
    grab_banners = grab_choice == "y"

    try:
        # If the input looks like a hostname rather than an IP, resolve it first.
        # A quick way to check: try to parse it as an IP; if that fails, resolve it.
        try:
            socket.inet_aton(target)
            target_ip = target  # It was already a valid IP
        except socket.error:
            target_ip = resolve_hostname(target)
            if target_ip is None:
                sys.exit(1)  # Stop here if resolution failed

        scan_common_ports(target_ip, grab_banners=grab_banners)

    except KeyboardInterrupt:
        # Lets the user cleanly cancel with Ctrl+C instead of a messy crash/traceback
        print("\n")
        log("Scan interrupted by user (Ctrl+C). Exiting cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
