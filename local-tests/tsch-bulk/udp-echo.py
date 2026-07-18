#!/usr/bin/env python3
"""
UDP echo sink for the tsch-bulk probe. Binds :::<port> (so it catches datagrams
to the tun's fd00::1), echoes every datagram back to its sender unchanged, and
logs the RECEIVED size with a timestamp. Cross-reference this log with the DK's
[BULK] lines: if the host logs "recv N" for a size but the DK reports ok=0 at
that size, the UPLINK (DK->host) worked and the DOWNLINK (host->DK echo) is the
one dropping; if the host never logs it, the uplink is the bottleneck.

Run on the tun-capable host (behind the Firefly gateway), same place as setest:
    python3 udp-echo.py            # port 7777
    python3 udp-echo.py 7777

SECURITY NOTICE: Test credentials only. Never use in production.
"""
import socket
import sys
import datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7777

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", PORT))
print(f"# udp-echo bound on [::]:{PORT}  (Ctrl-C to stop)", flush=True)

while True:
    data, addr = s.recvfrom(4096)
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ts}  recv {len(data):4d} B <- {addr[0]}  -> echo", flush=True)
    s.sendto(data, addr)
