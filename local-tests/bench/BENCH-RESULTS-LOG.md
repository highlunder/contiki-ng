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
| 2026-07-03 | edhoc-c5t-**sw**-csma | 100 | 0 | 689.2 | 760.4 | 692.4 | 42.7 | 616.8 | 823.1 | 1 | software (uECC) baseline |
| 2026-07-03 | edhoc-**c5c**-sw-csma | 100 | 0 | 822.8 | 923.9 | 832.3 | 52.6 | 721.5 | 947.8 | 1 | c5c = full cert inline (vs c5t cert-hash) |

### c5t vs c5c (software, CSMA, real RF) — the C509 wire-size effect
c5t (cert **hash** in MSG_2/3) median 689 ms vs c5c (full cert **inline**) median
823 ms → **c5c is ~134 ms slower**. Crypto is identical (same P-256 ops), so the
delta is pure RF/protocol: c5c's inline ~164 B cert enlarges MSG_2/MSG_3, adding
6LoWPAN fragmentation + air time. This is the on-wire cost of inlining the cert
vs referencing it by hash — a clean measured data point for the C509 story.

### CC310 vs software (c5t, CSMA, real RF)
Whole-handshake **speedup = 689.2 / 327.7 ≈ 2.1×** (median). It is *not* the ~8×
per-op CC310 speedup because most of the handshake is RF/protocol time (message
transmission, 6LoWPAN fragmentation, CoAP round-trips), which hardware crypto
doesn't touch. Decomposition (assuming CC310 ECC ~8× faster, consistent with the
per-op benches):
- ECC saved by CC310 = 689.2 − 327.7 ≈ **361 ms**.
- => sw ECC ≈ 413 ms, CC310 ECC ≈ 52 ms, and the **RF/protocol floor ≈ 276 ms**
  (the same in both: 689−413 = 328−52 = 276). Both fit, so the model is
  self-consistent. Confirm the split directly with `EDHOC_PROFILE=1` (per-op DWT
  cycles + wall-clock).

Takeaway for the paper: hardware ECC roughly halves the *whole* EDHOC handshake
over a real radio (2.1×), even though the crypto itself is ~8× — the ~276 ms
RF/protocol floor dilutes it.

## Raw FINAL lines
```
[BENCH edhoc-c5t-cc310-csma FINAL] n=100 fail=0 mean=332.472 median=327.704 p95=404.304 sd=43.616 min=228.416 max=444.464 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH edhoc-c5t-sw-csma FINAL] n=100 fail=0 mean=692.445 median=689.216 p95=760.352 sd=42.660 min=616.768 max=823.056 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH edhoc-c5c-sw-csma FINAL] n=100 fail=0 mean=832.324 median=822.784 p95=923.936 sd=52.648 min=721.520 max=947.760 hops=1 retx_tot=0 dbg=0 (ms)
```

## Hardware vs emulator (cooja-ng, same sw firmware)
Running the *exact same* `edhoc-c5t-sw` nRF52840 firmware on a real DK and on an
emulated nRF52840 in cooja-ng (`emul/emul-edhoc-c5t.json`, 2 nodes, UDGM lossless):

| env | n | median | p95 | sd | notes |
|-----|---|--------|-----|----|-------|
| hardware  | 100 | 689.2 | 760.4 | 42.7 | real DK ↔ Firefly |
| emulator  | 30  | 955.9 | 1009.8 | 42.3 | emulated DK ↔ emulated responder; 7.1× real-time |

**Emulator ≈ 1.4× the hardware time** (956 vs 689 ms), same tight sd — a
consistent, *calibratable* offset, not noise. Likely the emulated nRF
cycle/instruction timing + UDGM radio model vs real silicon; useful as a fixed
correction factor. Emulator lets us then scale node count (hardware can't).
```
[BENCH edhoc-c5t-sw-emul FINAL] n=30 fail=0 mean=954.113 median=955.928 p95=1009.776 sd=42.294 min=876.976 max=1048.848 hops=1 retx_tot=0 dbg=0 (ms)
```

## Still to collect (same setup)
- edhoc-c5t-**sw**-csma  (software baseline -> sw-vs-CC310 speedup)
- edhoc-**c5c**-{sw,cc310}-csma  (inline cert vs cert-hash)
- dtls-{psk,x509,c509}-csma  (setest at fd00::1)
- all of the above on **TSCH** once the TSCH join test passes (`../tsch-test/`)
- optional: multi-hop (add a relay node -> `hops` rises; same firmwares)
