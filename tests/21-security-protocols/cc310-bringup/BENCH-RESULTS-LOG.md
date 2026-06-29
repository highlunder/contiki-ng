# nRF52840-DK ECC bench — results log (firmware-version tracked)

Every bench firmware now prints a build stamp so any pasted result is
self-identifying:

```
fw-build: <FW_BUILD_ID>  (compiled <__DATE__> <__TIME__>)
...
=== SUMMARY (<curve>, <backend>, <n> iters, fw <FW_BUILD_ID>) ===
```

- `FW_BUILD_ID` is a short date id the Makefile injects (`-DFW_BUILD_ID`,
  default `$(date -u +%Y%m%d)`; override per build with `FW_ID=20260626b`).
- `__DATE__`/`__TIME__` are the compiler's own timestamps — insurance against a
  stale object that didn't get the new id. Always clean-build (`rm -rf build`).

When pasting a run here, keep the `fw-build:` line — it ties the numbers to a
firmware register row below.

---

## Firmware register

| fw id | hex | source rev | I-cache | notes |
|---|---|---|---|---|
| `20260626` | `ecc-bench-secp256r1-sw.hex` | ecc-bench.c (uECC) | ON | stamp + cache-on rebuild; supersedes pre-stamp |
| `20260626` | `ecc-bench-secp256r1-p256m.hex` | p256m-bench.c (p256-m) | ON | stamp + cache-on; variance-overflow fix |
| `20260626` | `ecc-bench-secp256r1-cc310.hex` | ecc-bench.c `ECC_HW_BACKEND=cc310` | ON (insensitive) | stamp + cache-on rebuild |

---

## Results

### fw `20260626` — 3-way P-256, I-cache ON, 100 iters
Flash each hex, paste the `fw-build:` + `SUMMARY` block under the matching row.

- [x] `ecc-bench-secp256r1-sw.hex`     (uECC)    — captured below, RESULT PASS
- [x] `ecc-bench-secp256r1-p256m.hex`  (p256-m)  — captured below
- [x] `ecc-bench-secp256r1-cc310.hex`  (CC310)   — captured below, RESULT PASS

**uECC** (compiled Jun 26 13:58:26, I-cache ENABLED, DWT sanity 64029 cyc, RESULT PASS):

| op | mean_us | mean_ms | vs cache-off baseline |
|---|---|---|---|
| keygen | 150631 | 150.6 | 171.9 → 1.14× faster |
| sign   | 161189 | 161.2 | 186.1 → 1.15× faster |
| verify | 180042 | 180.0 | 208.7 → 1.16× faster |
| ecdh   | 150459 | 150.5 | 171.7 → 1.14× faster |

**p256-m** (compiled Jun 26 14:02:02, I-cache ENABLED, DWT sanity 64028 cyc):

| op | mean_us | mean_ms | vs cache-off baseline |
|---|---|---|---|
| keygen | 341574 | 341.6 | 554.1 → 1.62× faster |
| sign   | 367399 | 367.4 | 597.0 → 1.62× faster |
| verify | 732324 | 732.3 | 1190.4 → 1.63× faster |
| ecdh   | 341054 | 341.1 | 553.8 → 1.62× faster |

sd now sane (uECC 97–120 except verify's 3574 spread; p256-m 51–137; the old
1.16M verify-sd overflow is gone). The cache gain differs by lib — uECC ~1.15×,
p256-m ~1.62× — because p256-m's larger constant-time inner loop is more
flash-fetch-bound, so it was hurt more by the disabled cache. With the cache ON
(the as-deployed config), the fair P-256 software comparison is:

| op | uECC ms | p256-m ms | p256-m / uECC |
|---|---|---|---|
| keygen | 150.6 | 341.6 | 2.27× slower |
| sign   | 161.2 | 367.4 | 2.28× slower |
| verify | 180.0 | 732.3 | **4.07× slower** |
| ecdh   | 150.5 | 341.1 | 2.27× slower |

p256-m is slower across the board by design (constant-time + ~2.9 KB code over
speed); verify is the worst case (~4×). Unlike Monocypher-vs-CC310 for Ed25519,
a modern compact P-256 sw lib does **not** beat uECC here.

**CC310** (compiled Jun 26 13:58:57, I-cache ENABLED, DWT sanity 64025 cyc, RESULT PASS):

| op | mean_us | mean_ms | vs cache-off baseline |
|---|---|---|---|
| keygen | 18589 | 18.6 | 19.1 → ~same (cache-insensitive ✓) |
| sign   | 20388 | 20.4 | 21.2 → ~same |
| verify | 21537 | 21.5 | 22.2 → ~same |
| ecdh   | 18796 | 18.8 | 19.4 → ~same |

CC310 is unaffected by the I-cache (the EC math runs in the CryptoCell engine,
not flash), confirming the hw-vs-sw gap below is measured under one memory system.

### Final 3-way, fw `20260626`, I-cache ON, mean ms

| op | uECC (sw) | p256-m (sw) | CC310 (hw) | CC310 speedup vs uECC |
|---|---|---|---|---|
| keygen | 150.6 | 341.6 | 18.6 | 8.1× |
| sign   | 161.2 | 367.4 | 20.4 | 7.9× |
| verify | 180.0 | 732.3 | 21.5 | 8.4× |
| ecdh   | 150.5 | 341.1 | 18.8 | 8.0× |

A full secp256r1 handshake's worth (keygen+sign+verify+ecdh):
**uECC 642 ms · p256-m 1782 ms · CC310 79 ms.** CC310 is ~8× faster than the
best software (uECC); p256-m is the slowest. ~79 ms for CC310's 4 ops is
consistent with the earlier full-netstack figure (~6 ops × ~19 ms ≈ 114 ms,
cf. Fedrecheski 2024 ~135 ms CC310 EDHOC).

---

## Pre-stamp baseline (untracked, **I-cache OFF** — superseded by fw `20260626`)

Captured before the build stamp + the NVMC I-cache enable existed. Kept for
reference only; the cache-on `20260626` runs replace these for the paper.

| op | uECC (µs) | p256-m (µs) | CC310 (µs) |
|---|---|---|---|
| keygen | 171912 | 554112 | 19056 |
| sign   | 186116 | 596950 | 21154 |
| verify | 208717 | 1190370 | 22212 |
| ecdh   | 171695 | 553840 | 19407 |

(p256-m `verify` sd column read 1162359 — the uint64 variance overflow, since
fixed. CC310 is largely cache-insensitive, so its numbers should hold ~19 ms.)
