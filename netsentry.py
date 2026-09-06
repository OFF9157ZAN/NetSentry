#!/usr/bin/env python3
"""
netsentry.py — A simple, dependency-free network scanner for YOUR OWN network.

Features:
  1. Host discovery: find live devices on a local subnet (ping sweep)
  2. Port scanning: check common (or custom) TCP ports on a target
  3. Banner grabbing: best-effort service identification on open ports

IMPORTANT / LEGAL NOTE:
  Only run this against networks and devices you own or have explicit
  written authorization to test. Scanning networks/hosts you don't own
  or don't have permission to test may be illegal in your jurisdiction
  (e.g., under the U.S. Computer Fraud and Abuse Act or similar laws
  elsewhere).

Usage examples:
  # Discover live hosts on your subnet
  python3 netsentry.py discover 192.168.1.0/24

  # Scan common ports on a single host
  python3 netsentry.py scan 192.168.1.10

  # Scan a custom port range
  python3 netsentry.py scan 192.168.1.10 --ports 1-1024

  # Scan and grab banners
  python3 netsentry.py scan 192.168.1.10 --banners
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# A reasonably useful default port list (not exhaustive)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}


def ping(host: str, timeout_s: float = 1.0) -> bool:
    """Cross-platform single ping. Returns True if host responds."""
    system = platform.system().lower()
    count_flag = "-n" if system == "windows" else "-c"
    timeout_flag = "-w" if system == "windows" else "-W"
    timeout_val = str(int(timeout_s * 1000)) if system == "windows" else str(int(timeout_s))

    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, host]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def discover_hosts(subnet: str, max_workers: int = 100):
    """Ping-sweep a subnet (CIDR notation) and return list of live IPs."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        print(f"[!] Invalid subnet '{subnet}': {e}")
        sys.exit(1)

    hosts = list(network.hosts())
    if len(hosts) > 1024:
        print(f"[!] Subnet has {len(hosts)} hosts — that's a lot. Consider a smaller range (e.g. /24).")
        confirm = input("Continue anyway? [y/N]: ").strip().lower()
        if confirm != "y":
            sys.exit(0)

    print(f"[*] Scanning {len(hosts)} addresses in {subnet} ...")
    live_hosts = []
    start = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping, str(ip)): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    hostname = resolve_hostname(str(ip))
                    live_hosts.append((str(ip), hostname))
                    label = f" ({hostname})" if hostname else ""
                    print(f"    [+] {ip}{label} is up")
            except Exception:
                pass

    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n[*] Discovery complete in {elapsed:.1f}s — {len(live_hosts)} host(s) up.\n")
    return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x[0]))


def resolve_hostname(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def grab_banner(ip: str, port: int, timeout_s: float = 1.5) -> str:
    """Best-effort banner grab on an open TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            s.connect((ip, port))
            # Some services send a banner immediately
            try:
                s.settimeout(1.0)
                data = s.recv(256)
                if data:
                    return data.decode(errors="replace").strip().replace("\r", " ").replace("\n", " ")
            except socket.timeout:
                pass
            # HTTP-like ports: send a basic request to elicit a response
            if port in (80, 8080, 8000, 443, 8443):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256)
                    if data:
                        return data.decode(errors="replace").splitlines()[0].strip()
                except Exception:
                    pass
    except Exception:
        pass
    return ""


def scan_port(ip: str, port: int, timeout_s: float = 0.5, grab: bool = False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port) if grab else ""
                return port, True, banner
    except Exception:
        pass
    return port, False, ""


def parse_port_range(port_str: str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def scan_host(ip: str, ports=None, max_workers: int = 200, grab: bool = False):
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"[*] Scanning {ip} — {len(ports)} port(s)...")
    start = datetime.now()
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, ip, p, 0.5, grab) for p in ports]
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))

    elapsed = (datetime.now() - start).total_seconds()
    open_ports.sort()

    print(f"\n[*] Scan complete in {elapsed:.1f}s\n")
    if not open_ports:
        print("    No open ports found (in the scanned range).")
    else:
        print(f"    {'PORT':<8}{'SERVICE':<15}{'BANNER'}")
        print(f"    {'-'*8}{'-'*15}{'-'*30}")
        for port, banner in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            print(f"    {port:<8}{service:<15}{banner}")
    print()
    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description="Simple network scanner for authorized use on your own network.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_p = subparsers.add_parser("discover", help="Find live hosts on a subnet")
    discover_p.add_argument("subnet", help="Subnet in CIDR notation, e.g. 192.168.1.0/24")
    discover_p.add_argument("--workers", type=int, default=100, help="Concurrent ping workers")

    scan_p = subparsers.add_parser("scan", help="Scan ports on a target host")
    scan_p.add_argument("target", help="IP address or hostname")
    scan_p.add_argument("--ports", default=None, help="Port range, e.g. 1-1024 or 22,80,443")
    scan_p.add_argument("--banners", action="store_true", help="Attempt banner grabbing on open ports")
    scan_p.add_argument("--workers", type=int, default=200, help="Concurrent scan workers")

    args = parser.parse_args()

    print("=" * 60)
    print(" netsentry.py — for use only on networks you own/are authorized to test")
    print("=" * 60)

    if args.command == "discover":
        discover_hosts(args.subnet, max_workers=args.workers)
    elif args.command == "scan":
        ports = parse_port_range(args.ports) if args.ports else None
        scan_host(args.target, ports=ports, max_workers=args.workers, grab=args.banners)


if __name__ == "__main__":
    main()
