
#!/usr/bin/env python3
"""
simple_scanner.py
A safe, timestamped TCP connect scanner restricted to 127.0.0.1/localhost/scanme.nmap.org.
Features:
- Port/range validation (1..65535)
- Graceful errors for invalid host/ports and DNS failures (unreachable host)
- Optional delay between attempts to respect rate limits
- Clear, timestamped output for screenshots
"""

import socket
import sys
import time
import datetime

ALLOWED = {"127.0.0.1", "localhost", "scanme.nmap.org"}

def ts() -> str:
    return datetime.datetime.now().isoformat(sep=' ', timespec='seconds')

def log(msg: str):
    print(f"{ts()}  {msg}", flush=True)

def validate_port(p: int):
    if not (1 <= p <= 65535):
        raise ValueError(f"Port {p} is out of valid range 1..65535")

def parse_args(argv):
    if len(argv) < 3:
        print("Usage: python simple_scanner.py <host> <start_port> [end_port] [delay_ms]")
        sys.exit(1)

    host = argv[1].strip()
    if host not in ALLOWED:
        print(f"ERROR: Host '{host}' not authorized. Allowed: {sorted(ALLOWED)}")
        sys.exit(2)

    try:
        start = int(argv[2])
        end = int(argv[3]) if len(argv) > 3 else start
        validate_port(start)
        validate_port(end)
        if end < start:
            raise ValueError("end_port must be >= start_port")
    except ValueError as ve:
        print(f"ERROR: {ve}")
        sys.exit(3)

    try:
        delay_ms = int(argv[4]) if len(argv) > 4 else 50  # avoid fast/aggressive scans
        if delay_ms < 0:
            raise ValueError("delay_ms must be >= 0")
    except ValueError as ve:
        print(f"ERROR: {ve}")
        sys.exit(4)

    return host, start, end, delay_ms

def scan_port(sockaddr, timeout=0.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sockaddr)
            return True
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        return False

def main():
    host, start, end, delay_ms = parse_args(sys.argv)

    try:
        addr = socket.gethostbyname(host)
    except socket.gaierror as e:
        log(f"[ERROR] DNS resolution failed for host '{host}': {e}")
        sys.exit(5)

    log(f"Starting scan {host} ({addr}) ports {start}-{end} with delay {delay_ms}ms")
    
    for port in range(start, end + 1):
        status = "OPEN" if scan_port((addr, port)) else "closed"
        log(f"{host}:{port} -> {status}")
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
    log("Scan complete.")

if __name__ == "__main__":
    main()
