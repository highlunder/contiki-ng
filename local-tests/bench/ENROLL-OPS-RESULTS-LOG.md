# Enrollment per-op microbenchmark — results log (Exp H1)

Per-operation CPU cost of the C509 enrollment crypto path on real silicon —
the RW-6 remainder ("full ECDSA per-op timing on hardware"), the primary
hardware-gated gap of the LICE follow-up (`PLAN-c509-lice-followup.md` §10.1).

Firmware: `local-tests/bench/enroll-ops-bench/` (staged hex
`enroll-ops-bench-sw-dk.hex`). Pure compute, no radio. Self-contained
(uECC + SHA-256, no mbedTLS — the EDHOC/OSCORE crypto path).

Log blocks **verbatim**, with the DK serial + date. The `fw:` + `test:` ids are
the join key back to the exact source + config.

**SECURITY NOTICE: Test credentials only. Never use in production.**

---

## Run 2 — 2026-07-17, I-cache ON — **THE CURRENT NUMBERS** (supersedes Run 1)

Same board/firmware source, rebuilt after the platform I-cache fix
(`fw:20260717-icache`, hex `enroll-ops-bench-sw-dk-icache.hex`). This is the
as-deployed cost from 2026-07-17 onward; **quote these, not Run 1.**

```
[ENROLL-OPS fw:20260717-icache compiled:Jul 17 2026 12:06:40 backend:software (uECC) curve:secp256r1 iters:50 test:enroll-ops-p256-sw]
[EOP csr-build  ] n=50 fail=0 mean_us=27 sd_us=7 min_us=16 max_us=32
[EOP csr-sign   ] n=50 fail=0 mean_us=105032 sd_us=8 min_us=105024 max_us=105040
[EOP ca-issue   ] n=50 fail=0 mean_us=104796 sd_us=6 min_us=104784 max_us=104800
[EOP chain-valid] n=50 fail=0 mean_us=114554 sd_us=7 min_us=114544 max_us=114560
[EOP cert-verify] n=50 fail=0 mean_us=113172 sd_us=7 min_us=113168 max_us=113184
[ENROLL-OPS-END fw:20260717-icache backend:software (uECC) test:enroll-ops-p256-sw]
```

| op | mean | cache-OFF (Run 1) | I-cache factor |
|---|---:|---:|---:|
| `csr-build` | **≲27 µs** (resolution-limited) | ≲32 µs | — |
| `csr-sign` | **105.03 ms** | 116.97 | 1.114x |
| `ca-issue` | **104.80 ms** | 116.67 | 1.113x |
| `chain-valid` | **114.55 ms** | 127.57 | 1.114x |
| `cert-verify` | **113.17 ms** | 126.05 | 1.114x |

Roll-up (CPU per enrollment): **client ≈ 105.1 ms** (`csr-build+csr-sign`),
**CA ≈ 104.8 ms** (`ca-issue`), **relying party ≈ 227.7 ms**
(`chain-valid+cert-verify`); total across parties ≈ **437.6 ms** (was 487.3).

**Consistency:** the I-cache factor is 1.113-1.114x on all four ops, matching
`ecc-bench`'s independently measured 1.10-1.12x. Residues against `ecc-bench`'s
tuned primitives (sign 102.60, verify 113.19) are now **+2.4 ms** (`csr-sign`) and
**+1.4 ms** (`chain-valid`) — the SHA-256 + CBOR assembly, i.e. the composite op is
correctly *slower* than the primitive it contains. Finding 1 below is unchanged and
in fact sharper: assembly is ≲27 µs against a ~105 ms sign, **~3 900x**.

**CC310 substitute** (per §10.1; valid because assembly is negligible): client
enrollment CPU ≈ **20.4 ms** vs **105.1 ms** tuned software = **~5.2x**.

### Caveat on `csr-build` and on verify's precision

`csr-build` now reads `min=16 max=32 sd=7` — flickering between **1 and 2 ticks** of
the 62.5 kHz RTIMER (16 µs). That confirms Run 1's `sd=0, min=max=32` was a
quantisation artifact, not precision. Quote as "sub-millisecond".

Also note the verify ops here show `sd≈7 µs` while `ecc-bench`'s verify shows
`sd≈1900 µs`. Not a contradiction: this bench verifies **one fixed signature** every
iteration, `ecc-bench` verifies a **fresh random** one, and ECDSA verify is
input-dependent (Shamir's trick). So these verify figures are a single point in a
distribution that really spans ~109.7-118.4 ms; the tiny sd overstates their
generality. `cert-verify` (113.17) landing on `ecc-bench`'s mean (113.19) is a
coincidence of that particular signature.

## Run 1 — 2026-07-17, nRF52840-DK, software (uECC), secp256r1 — SUPERSEDED (I-cache OFF)

- **Board:** nRF52840-DK (PCA10056), J-Link SN **683609980** (confirmed by the
  operator; this is the original bench DK, not the second one now on the bench)
- **Firmware:** `enroll-ops-bench-sw-dk.hex`, `fw:20260716` (compiled Jul 16 2026 17:17:01)
- **Backend:** software (uECC), `uECC_OPTIMIZATION_LEVEL=4`, `uECC_SQUARE_FUNC=1`
- **Iterations:** 50/op. **Serial:** 115200 8N1, J-Link CDC.

```
[ENROLL-OPS fw:20260716 compiled:Jul 16 2026 17:17:01 backend:software (uECC) curve:secp256r1 iters:50 test:enroll-ops-p256-sw]
[EOP csr-build  ] n=50 fail=0 mean_us=32 sd_us=0 min_us=32 max_us=32
[EOP csr-sign   ] n=50 fail=0 mean_us=116974 sd_us=6 min_us=116960 max_us=116992
[EOP ca-issue   ] n=50 fail=0 mean_us=116671 sd_us=6 min_us=116656 max_us=116688
[EOP chain-valid] n=50 fail=0 mean_us=127572 sd_us=7 min_us=127568 max_us=127584
[EOP cert-verify] n=50 fail=0 mean_us=126052 sd_us=6 min_us=126048 max_us=126064
[ENROLL-OPS-END fw:20260716 backend:software (uECC) test:enroll-ops-p256-sw]
```

### Reading

| op | mean | what it is |
|---|---:|---|
| `csr-build` | **≲32 µs** (resolution-limited, see below) | CBOR assembly, no asymmetric crypto |
| `csr-sign` | **116.97 ms** | SHA-256 + 1 ECDSA-P256 **sign** (PoP) |
| `ca-issue` | **116.67 ms** | assembly + 1 **sign** |
| `chain-valid` | **127.57 ms** | SHA-256 + 1 **verify** |
| `cert-verify` | **126.05 ms** | SHA-256 + 1 **verify** |

Derived primitives: **sign ≈ 116.8 ms**, **verify ≈ 126.8 ms** (verify/sign ≈ 1.09),
non-crypto assembly ≈ 0.03–1.5 ms.

Roll-up (CPU only, per enrollment):
- **client** = `csr-build + csr-sign` ≈ **117.0 ms**
- **CA** = `ca-issue` ≈ **116.7 ms**
- **relying party** = `chain-valid + cert-verify` ≈ **253.6 ms**
- total across all parties ≈ **487 ms**

### Findings

1. **Enrollment CPU cost is entirely the asymmetric crypto; the C509/CBOR encoding
   is free.** `csr-build` (≲32 µs) is **~3 700× cheaper** than the single P-256 sign
   it accompanies (117 ms), i.e. ~0.03 % of the client's enrollment CPU. Every op is
   "one sign or one verify, plus noise". This is the enrollment analogue of the LRev
   E4 result (revocation codec = tens of µs vs a ~110 ms verify): in both papers the
   compact-encoding work is metrologically invisible next to one EC operation, so the
   C509 case rests on **bytes on the wire**, not CPU.

2. **Cross-validates the independent EDHOC decomposition.** `TSCH-HW-RESULTS.md`
   derived sw crypto ≈ 858 ms for 8 EC ops ≈ **107 ms/op** from whole-handshake 2×2
   timings. Measuring the primitives directly here gives **117 ms sign / 127 ms
   verify** — same figure from a completely different route (whole-handshake
   subtraction vs. isolated per-op loop). The two agree.

3. **The plan's expected values were stale and are now superseded.** §10.1 predicted
   ~186 ms sign / ~209 ms verify; silicon says **117 / 127 ms** — ~1.6× faster. The
   expectations should be corrected in the plan rather than the measurement doubted:
   they disagree with both the direct measurement *and* the independent handshake
   decomposition (107 ms/op), which agree with each other.

4. **`csr-build` is at the RTIMER resolution floor.** `mean = min = max = 32 µs`,
   `sd = 0` — exactly 2 ticks of the DK's 62.5 kHz RTIMER (16 µs/tick). So the true
   value lies in ~(16, 48) µs and is **resolution-limited, not measured to ±0 µs**.
   Quote it as "≲32 µs / sub-millisecond", never as a precise 32 µs. (The native x86
   run reports 0 for the same reason.) A DWT-cycle read would resolve it if a precise
   figure is ever needed — it is not, given finding 1.

5. **Determinism**: sd = 6–7 µs on ~120 ms ops (0.005 %) — fixed inputs, no radio, no
   allocation. Nothing here needs more seeds/iterations.

### RESOLVED 2026-07-17 — this block is a cache-OFF measurement

Finding 3 below ("the plan's expected values were stale") was right but shallow.
Chasing it exposed two build accidents, both now fixed; see
`tests/21-security-protocols/cc310-bringup/BENCH-RESULTS-LOG.md` (2026-07-17):

1. `ecc-bench` — the source of the plan's ~186/209 expectation and of the paper's
   "software" column — was the only uECC build in the tree left at the library
   defaults (`OPTIMIZATION_LEVEL=2`, `SQUARE_FUNC=0`). Every deployed app, this
   bench included, uses level 4 + `SQUARE_FUNC=1`.
2. The **NVMC I-cache** was enabled by `ecc-bench` alone; the nrf platform left it
   off, so all shipped firmware — including **this run** — paid flash wait-states.
   Now enabled platform-wide (`NRF_CONF_ENABLE_ICACHE`, default on).

A cache-OFF `ecc-bench` (`fw:sw-opt4-nocache`) reproduces this block to within
1-2 ms (bare `sign` 115.34 vs `csr-sign` 116.97; bare `verify` 127.06 vs
`chain-valid` 127.57), the residue being exactly the SHA-256 + CBOR assembly —
confirming both the numbers here and the I-cache as the sole cause of the apparent
contradiction. **Consequence:** the figures above are the *pre-fix as-deployed*
cost. With the I-cache on, expect ~10-12% lower (sign ~103 ms, verify ~113 ms).
Re-run this firmware before quoting per-op absolutes in the paper.

### Emulator comparison (fair-warning note)

`rev-ops-bench` (LRev E4, cooja-ng-ge) measured a uECC P-256 **verify at 109.9 ms**
vs **126.8 ms** on silicon here — the cycle-accurate emulator is **~13 % optimistic**
for the same primitive class. Plausible cause: the emulator's flat 64 MHz core with no
flash wait-states / I-cache effects (the CC310 3-way bench was explicitly run with
I-cache **ON**; this enroll-ops build does not enable it). Different call paths and
message lengths also contribute. **Consequence:** emulator per-op figures are good to
~±15 % of silicon — fine for the "codec ≪ crypto" argument (a 3 700× ratio), but
per-op absolutes quoted in a paper should come from this log, not the emulator.

### Open

- **CC310 / p256-m per-op**: these ops call uECC directly, so a genuine CC310
  enrollment-op figure needs c509 signing routed through `os/services/ecc` (not done).
  Substitute per §10.1: take sign/verify from **H3** (`ecc-bench`) for CC310/p256-m and
  add the ≲32 µs assembly — valid precisely because of finding 1. H3 (2026-07-17)
  gives CC310 sign 20.4 ms, so the client's enrollment CPU is ≈**20.4 ms** vs the
  tuned-software ≈**102.6 ms** — a **~5.0×**, not ~5.8×, reduction. (The ~5.8×
  written here earlier used the pre-I-cache software figure.)
- **Re-run this firmware with the I-cache on** to supersede the block above, now
  that the platform enables it; that makes H1 and H3 share one memory system.
