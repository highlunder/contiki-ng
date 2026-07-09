#!/usr/bin/env python3
"""Minimal timestamping serial reader — progress tracking for the HW benchmarks.

No pyserial needed: it `stty`s the port to raw 115200 then reads lines and prefixes
a host wall-clock timestamp. Use it INSTEAD of picocom while a looping benchmark
runs, so you can see the pace (and the ~60-70 s TSCH join) in wall-clock. The
authoritative handshake timing is the on-device RTIMER value in each [BENCH] line;
this host timestamp is only for progress and never feeds the measurement.

    python3 ts-serial.py [/dev/ttyACM0] [115200]
"""
import sys, time, subprocess

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
baud = sys.argv[2] if len(sys.argv) > 2 else "115200"
subprocess.run(["stty", "-F", port, baud, "raw", "-echo", "-echoe", "-echok"], check=True)

with open(port, "rb", buffering=0) as f:
    buf = bytearray()
    while True:
        chunk = f.read(256)
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            line, _, buf = buf.partition(b"\n")
            ts = time.strftime("[%H:%M:%S]")
            print(ts, line.decode("ascii", "replace").rstrip("\r"), flush=True)
