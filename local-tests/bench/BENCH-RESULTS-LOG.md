# Benchmark results log (real-hardware, over-the-air)

Paste the **`… FINAL …`** line from each run here (that line is self-contained:
n / fail / mean / median / p95 / sd / min / max / hops / retx_tot / dbg). For
right-skewed handshake latency, **median + p95** are the headline numbers.

Setup: nRF52840-DK client ↔ Firefly (RPL root / gateway) over 2.4 GHz 802.15.4;
EDHOC → bridged native responder (`fd01::…`), DTLS → setest (`fd00::1`).
BENCH_ITERS=100, BENCH_SETTLE_S=5, dbg=0 (quiet build) unless noted.

| date | config | n | fail | median | p95 | mean | sd | min | max | hops | notes |
|------|--------|---|------|--------|-----|------|----|-----|-----|------|-------|
| 2026-07-03 | edhoc-c5t-cc310-csma | 100 | 0 | 327.7 | 404.3 | 332.5 | 43.6 | 228.4 | 444.5 | 1 | first clean run; settle=5 removed the slow tails |

## Raw FINAL lines
```
[BENCH edhoc-c5t-cc310-csma FINAL] n=100 fail=0 mean=332.472 median=327.704 p95=404.304 sd=43.616 min=228.416 max=444.464 hops=1 retx_tot=0 dbg=0 (ms)
```

## Still to collect (same setup)
- edhoc-c5t-**sw**-csma  (software baseline -> sw-vs-CC310 speedup)
- edhoc-**c5c**-{sw,cc310}-csma  (inline cert vs cert-hash)
- dtls-{psk,x509,c509}-csma  (setest at fd00::1)
- all of the above on **TSCH** once the TSCH join test passes (`../tsch-test/`)
- optional: multi-hop (add a relay node -> `hops` rises; same firmwares)
