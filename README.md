# NetSentry

A lightweight, **zero-dependency** network discovery and port-scanning tool, built with the Python standard library. NetSentry helps you find live devices on your local network and check them for open ports and exposed services — ideal for home labs, sysadmins, and anyone learning network security fundamentals.

> ⚠️ **Use responsibly:** Only run NetSentry against networks and devices you **own** or have **explicit written authorization** to test. Scanning networks or systems without permission may be illegal in your jurisdiction (e.g., under the U.S. Computer Fraud and Abuse Act or equivalent laws elsewhere).

---

## Features

- **Host discovery** — ping-sweeps a subnet (CIDR notation) to find live devices, with hostname resolution where available
- **Port scanning** — checks common ports (or a custom range) on a target host using concurrent TCP connections
- **Banner grabbing** — optionally attempts to identify service versions on open ports
- **No external dependencies** — runs anywhere Python 3.7+ is installed, no `pip install` required
- **Cross-platform** — works on Linux, macOS, and Windows

---

## Requirements

- Python 3.7 or later
- No third-party packages required (see [`requirements.txt`](./requirements.txt))
- Standard user permissions are sufficient (no root/admin needed for the core features)

---

## Installation

### 1. Clone or download the files

```bash
git clone https://github.com/OFF9157ZAN/NetSentry.git
cd Netsentry
```

*(Or simply download `netsentry.py`, `requirements.txt`, `LICENSE`, and this `README.md` into a folder.)*

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> This installs nothing extra since NetSentry only uses the Python standard library — the command is included for convention and safe to run.

### 4. Verify it runs

```bash
python3 netsentry.py --help
```

---

## Usage

### Find your local subnet first

```bash
# Linux / macOS
ip addr

# Windows
ipconfig
```

Look for your local IP and subnet mask (e.g., `192.168.1.42/24` means your subnet is `192.168.1.0/24`).

### Discover live hosts on your network

```bash
python3 netsentry.py discover 192.168.1.0/24
```

Optional: control concurrency with `--workers` (default: 100)

```bash
python3 netsentry.py discover 192.168.1.0/24 --workers 200
```

### Scan a host for open ports

```bash
# Scan ~20 common ports (SSH, HTTP, RDP, SMB, etc.)
python3 netsentry.py scan 192.168.1.10

# Scan a custom port range
python3 netsentry.py scan 192.168.1.10 --ports 1-1024

# Scan specific ports
python3 netsentry.py scan 192.168.1.10 --ports 22,80,443,3389

# Attempt to identify service banners on open ports
python3 netsentry.py scan 192.168.1.10 --banners
```

---

## Example Output

```
============================================================
 netsentry.py — for use only on networks you own/are authorized to test
============================================================
[*] Scanning 192.168.1.10 — 20 port(s)...

[*] Scan complete in 1.2s

    PORT    SERVICE        BANNER
    ------------------------------
    22      SSH            SSH-2.0-OpenSSH_9.6
    80      HTTP           HTTP/1.1 200 OK
    443     HTTPS
```

---

## Roadmap / Ideas for Extension

- UDP port scanning
- Export results to JSON/CSV
- Simple web dashboard for scan history
- OS fingerprinting
- Scheduled/recurring scans with change alerts

Contributions and forks welcome — see [`LICENSE`](./LICENSE) for terms.

---

## Disclaimer

NetSentry is provided for educational and authorized administrative use only. The authors are not responsible for any misuse of this tool. Always obtain proper authorization before scanning any network or system you do not own.

## License

Licensed under the MIT License — see [`LICENSE`](./LICENSE) for details.
