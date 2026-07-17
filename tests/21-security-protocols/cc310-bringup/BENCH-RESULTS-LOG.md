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

## PR-branch backend verified on silicon — `examples/libs/ecc` ecdsa (2026-06-29)

Ran the PR's own in-tree test (`examples/libs/ecc/ecdsa`, CC310 build) on a real
nRF52840-DK — verifies the **extracted `nrf52840-cc310-ecc-backend` branch**
(off upstream `develop`, blob referenced not vendored), not the eval-phase5 tree.
Build banner `v5.1-192-gc74bff480` = exactly the PR branch HEAD. PASS:

```
ECC backend: CC310 hardware
key generation took 18ms
validation took 0ms
signature generation took 20ms
signature verification took 22ms
```

Backend line correct, no `failed`, timings match the P-256 CC310 column (18.6/
20.4/21.5 ms). ms granularity (not µs) is expected — this is a correctness test
using `clock_time`, not the DWT-µs bench harness. Substantiates the
`CC310-BACKEND-PR.md` "Validated on real nRF52840-DK" claim on the actual branch.

ECDH program (`examples/libs/ecc/ecdh`, same branch `gc74bff480`) also PASS:
both parties' `ECDH took 19ms` + `OK` (shared secrets agreed) — matches the
P-256 CC310 ECDH column (18.8 ms).

compress program (same branch) PASS too: `decompression took 13ms` + `OK`. The
13 ms is the **software** `uECC_decompress` helper (CC310 has no point-decompress
primitive — micro-ecc kept linked to fill it), confirming the backend's decompress
delegation works (not a CC310 op).

**All three `examples/libs/ecc` programs (ecdsa / ecdh / compress) now PASS on
real silicon from the PR branch — backend hardware-validation complete.**

---

## Tier A — 25519 family on CC310, real HW (X25519 + Ed25519)

`ec25519-bench` (EDHOC suite 0/1 primitives), 100 iters, RESULT PASS, CC310
hardware. **This is a reproduction of the 2026-06-22 measurement** (same
pre-stamp firmware `g1e9d6f0a0-dirty`) — numbers match within noise, confirming
stability across a reflash/board cycle. Mean ms:

| op | mean_us | mean_ms |
|---|---|---|
| x25519-keygen  | 11819 | 11.8 |
| x25519-ecdh    | 11682 | 11.7 |
| ed25519-keygen | 14802 | 14.8 |
| ed25519-sign   | 16732 | 16.7 |
| ed25519-verify | 17922 | 17.9 |

**Curve25519 is faster than secp256r1 on CC310** (cf. the fw `20260626` P-256
CC310 column): X25519 ECDH 11.7 ms vs P-256 ECDH 18.8 ms (~1.6×); Ed25519
sign 16.7 vs ECDSA sign 20.4; Ed25519 verify 17.9 vs ECDSA verify 21.5. So the
EDHOC suite 0/1 (X25519/Ed25519) primitives cost less on CC310 than suite 2
(P-256/ES256).

⚠️ **Traceability caveat — this hex is NOT fw-stamped.** `ec25519-bench.c` has
neither the `FW_BUILD_ID` stamp nor the in-bench NVMC I-cache enable (only
`ecc-bench`/`p256m-bench` got those). The only version marker is the Contiki
build banner **`v5.1-164-g1e9d6f0a0-dirty`** (predates the stamp/I-cache commits).
I-cache was therefore **OFF** for this run — but CC310 numbers are cache-
insensitive (engine, not flash), so these stand as valid CC310 figures. TODO to
make this self-identifying like the P-256 benches: add `FW_BUILD_ID` + the
I-cache enable to `ec25519-bench.c` (and `mlkem-bench.c`) and rebuild.

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

---

# 2026-07-17 — the software column was misconfigured; corrected 3-way + platform I-cache fix

**DK J-Link SN 683609980, 100 iters/op, secp256r1.** Triggered by a contradiction:
the new enrollment per-op bench (`local-tests/bench/ENROLL-OPS-RESULTS-LOG.md`,
Exp H1) measured `csr-sign` = **117.0 ms**, i.e. SHA-256 + one ECDSA sign coming
out *faster* than this log's bare `sign` = 161.2 ms. A composite op cannot beat the
primitive it contains, so one of the builds was wrong. Both were — for two
independent reasons.

## Cause 1 — `ecc-bench` was the only uECC build in the tree at the library defaults

uECC.h defaults to `uECC_OPTIMIZATION_LEVEL=2` / `uECC_SQUARE_FUNC=0`. Neither this
app's Makefile nor `os/services/ecc/Makefile.ecc` overrode them. But **every
deployed app** (`edhoc-*`, `enroll-*`, `enroll-ops-bench`) sets `LEVEL=4` +
`SQUARE_FUNC=1`. So the benchmark measured a configuration nothing ships, and the
published "software" column understated software by ~1.4x.
**Fixed:** `ecc-bench/Makefile` now defaults `UECC_OPT=4 UECC_SQUARE=1` (the
as-deployed config); reproduce the old column with `UECC_OPT=2 UECC_SQUARE=0`.

## Cause 2 — the I-cache was on in the bench and off in every shipped build

`ecc-bench.c` enabled the NVMC instruction cache itself; the nrf platform did not,
and no other app did either. So benchmark numbers were cache-ON while all deployed
firmware ran cache-OFF, paying flash wait-states on every uECC inner loop.
**Fixed platform-wide:** `arch/platform/nrf/platform.c` now enables the I-cache in
`platform_init_stage_one()` (guarded on `NVMC_FEATURE_CACHE_PRESENT`; opt out with
`NRF_CONF_ENABLE_ICACHE=0`). `ecc-bench` gained `ECC_BENCH_ICACHE=0`, which also
passes `-DNRF_CONF_ENABLE_ICACHE=0` so a cache-off measurement is really cache-off.

## Results (mean ms; all rows level 4 + SQUARE_FUNC=1 unless noted)

| config | keygen | sign | verify | ecdh | 4-op total |
|---|---:|---:|---:|---:|---:|
| level **2**, cache ON — *the old published column* (fw 20260626) | 150.6 | 161.2 | 180.0 | 150.5 | **642.3** |
| level 4, cache **OFF** — as-deployed BEFORE today's fix (`fw:sw-opt4-nocache`) | 101.29 | 115.34 | 127.06 | 101.08 | **444.8** |
| level 4, cache **ON** — as-deployed AFTER the fix (`fw:20260717-opt4`) | 92.08 | **102.60** | **113.19** | 91.93 | **399.8** |
| level 4, cache ON, **-O3** (`fw:sw-opt4-o3`) | 92.81 | 103.70 | 114.21 | 92.66 | 403.4 |
| **CC310** (fw 20260626, cache-insensitive) | 18.6 | 20.4 | 21.5 | 18.8 | **79.3** |

### The corrected CC310 claim

| software baseline | sign | 4-op | CC310 speedup |
|---|---:|---:|---:|
| level 2, cache ON *(what the paper currently claims)* | 161.2 | 642.3 | **8.1x** |
| level 4, cache OFF (deployed until today) | 115.3 | 444.8 | **5.6x** |
| level 4, cache ON (deployed from today) | **102.6** | **399.8** | **5.0x** |

**CC310 is ~5x faster than properly-configured software, not ~8x.** The ~8x figure
was measured against software crippled by two build accidents. Configuration alone
— two `-D`s and one register write, no new code — makes software **1.61x faster**
(642.3 -> 399.8 ms) and halves the CryptoCell's apparent advantage. This is the
P-256 counterpart of the Ed25519 lesson in [[project-alt-kex-benches]] ("CC310 ~9x
is vs uECC, not intrinsic"): the honest claim is that CC310 beats *tuned* software
by ~5x.

### Cross-validation (why the cache-OFF row is trustworthy)

The cache-OFF row reproduces H1's independent `enroll-ops-bench` to within 1-2 ms —
`sign` 115.34 vs `csr-sign` 116.97 (+1.6 ms) and `verify` 127.06 vs `chain-valid`
127.57 (+0.5 ms) — and that residue is exactly the SHA-256 + CBOR assembly the
composite ops add. Different firmware, different curve set (this app compiles
secp192r1+secp256r1 via `os/services/ecc`; `enroll-ops-bench` compiles uECC's five
defaults), same answer => the I-cache was the whole discrepancy, and curve count
does not affect speed.

### -O3: rejected on data

`-O3` is **~1% SLOWER** than `-O2` on every op and costs **+16.6 KB flash**
(`.text` 67 936 -> 84 516, +24%). Expected: uECC's hot path is hand-written UMAAL
assembly the compiler cannot improve, so -O3 only adds inlining bloat and I-cache
pressure. Keep `-O2`. (`EXTRA_OPT=-O3` is retained in the Makefile, appended after
`Makefile.include` so the later -O wins; verified `-O2 -O3` on the uECC.c command
line.)

### uECC tuning: there is nothing left to turn on

Verified against uECC.h/types.h and the actual compile line — every speed knob is
already at maximum on this target:

| knob | value | how established |
|---|---|---|
| `uECC_OPTIMIZATION_LEVEL` | 4 (max) | compile line |
| `uECC_SQUARE_FUNC` | 1 | compile line |
| ARM thumb2 asm (`asm_arm.inc`) | active | `__thumb2__` => `uECC_PLATFORM=uECC_arm_thumb2` |
| `uECC_ARM_USE_UMAAL` (fastest multiply) | 1 | `__ARM_ARCH=7` + `__ARM_ARCH_7EM__` (not `7M`) => auto-on |
| `uECC_WORD_SIZE` | 4 (forced for ARM) | types.h |
| compiler | -O2 (-O3 rejected above) | compile line |

Considered and ruled out:
- **Single-curve build** (secp256r1 only): **not possible** via `os/services/ecc` —
  `ecc.c` calls `uECC_secp192r1()` unconditionally, so disabling it fails to
  compile (module-macros.h's "mandatory" comment is accurate; do not add #ifndef
  guards there without guarding those call sites first). Note it would be a
  code-size lever at best and could REGRESS speed: uECC.h says level 4 "only has an
  effect on ARM platforms where more than one curve is enabled", and the two curves
  this module enables are what make level 4 effective at all.
- **`uECC_VLI_NATIVE_LITTLE_ENDIAN=1`**: cuts byte-swapping and stack, but changes
  the endianness of every key/signature crossing the API — incompatible with
  X.509/C509/EDHOC interop unless all parties swap. Bench-only curiosity.
- **`uECC_SUPPORT_COMPRESSED_POINT=0`**: code size only, and we need decompression
  for C509 point reconstruction.

### Side note — variance structure

`sign` sd ~100 us (0.1%) but `verify` sd ~1.9-2.3 ms (~2%, spread 121-132 ms).
Verify's scalar multiplication is input-dependent (Shamir's trick over the random
signature values); sign's is not. That asymmetry is the expected side-channel
posture: the secret-scalar op is near-constant-time, the variable-time op runs only
on public data.

## Consequence for previously-logged numbers

**Every nRF sw-crypto figure recorded before 2026-07-17 was cache-OFF**, including
today's H1 block and the TSCH-HW-RESULTS EDHOC 2x2 (sw 1122 ms CSMA / 1298 ms TSCH,
CC310 424/532). With the platform fix they should improve by ~10-12% on the
software side only (CC310 is cache-insensitive), which will further compress the
CC310 speedup on whole handshakes. Re-run before quoting; do not scale the old
numbers analytically.

---

# 2026-07-17 — Exp H5: CC310-linked memory footprint (LICE PLAN §10.5)

Build-time only (`arm-none-eabi-size`, no board). Closes the §5.3.9 flag: the
paper's `Table:memory-footprint` is software-only, so the accelerator's ROM/RAM
cost — the other half of the "is CC310 worth it?" question — was never quantified.
Same app built twice, only `ECC_HW_BACKEND=cc310` differing.

| config | text | data | bss | dec |
|---|---:|---:|---:|---:|
| `ecc-bench` sw | 67 956 | 1 128 | 14 520 | 83 604 |
| `ecc-bench` **cc310** | 100 100 | 1 080 | 20 908 | 122 088 |
| `edhoc-c5t-bench` sw, CSMA | 113 860 | 1 368 | 16 276 | 131 504 |
| `edhoc-c5t-bench` **cc310**, CSMA | 149 712 | 1 320 | 22 664 | 173 696 |
| `edhoc-oscore-c5t-server` sw, CSMA | 108 628 | 1 376 | 16 156 | 126 160 |
| `edhoc-oscore-c5t-server` **cc310**, CSMA | 144 480 | 1 328 | 22 544 | 168 352 |
| `enroll-ops-bench` sw (no cc310 path) | 74 264 | 1 032 | 11 160 | 86 456 |

**Cost of enabling CC310** (cc310 − sw):

| app | flash (.text) | RAM (.bss) |
|---|---:|---:|
| `ecc-bench` | **+32 144 B** (+47.3%) | **+6 388 B** (+44.0%) |
| `edhoc-c5t-bench` | **+35 852 B** (+31.5%) | **+6 388 B** (+39.2%) |
| `c5t-server` | **+35 852 B** (+33.0%) | **+6 388 B** (+39.5%) |

`.data` *falls* by 48 B in every cc310 build (noise). The RAM delta is identical
(+6 388 B) across all three apps and the flash delta is identical (+35 852 B) for the
two real apps, so this is the fixed cost of linking Nordic's `nrf_crypto` + CC310
runtime, not something that scales with the application. `ecc-bench`'s smaller flash
delta (+32 144) reflects the EDHOC apps pulling a few more `nrf_crypto` modules.

Note uECC is linked in **both** builds — the CC310 backend reuses `uECC_decompress`
for EC point decompression (`os/services/ecc/Makefile.ecc`), so the +35.9 KB is
purely additive; enabling hardware does not let you drop the software library.

## The trade-off, stated honestly

Pairing this with the 2026-07-17 speed results above:

| option | flash cost | RAM cost | speed gain (per-op P-256) |
|---|---:|---:|---:|
| tune uECC (LEVEL 2→4 + SQUARE_FUNC) | **+1 292 B** | 0 | **1.57x** |
| enable NVMC I-cache | **0 B** | 0 | **1.12x** |
| *both (config only, no new code)* | **+1 292 B** | **0** | **1.61x** |
| enable CC310 on top | **+35 852 B** | **+6 388 B** | further **~3.1x** (5.0x total) |

**The first 1.6x is essentially free; the remaining ~3x costs ~36 KB of flash and
~6.4 KB of RAM.** Per unit of flash the software tuning is ~28x more efficient. On
the nRF52840 (1 MB flash / 256 KB RAM) CC310's ~3.6% flash and ~2.5% RAM are easily
affordable and the accelerator remains the right choice where latency or energy
matters — but the correct comparison is against *tuned* software (~5x, and only
2.05-2.60x on a whole handshake), not the ~8-9x this log previously reported against
a misconfigured build. On a smaller part (256 KB flash), ~36 KB for ~3x is a real
decision rather than a free win.

**Caveat:** the CC310 silicon exists on the die regardless — this is the cost of the
*driver library*, not of hardware. And these are `-O2` figures; see the -O3 note
above (rejected: +24% flash for ~1% slower).

---

# 2026-07-17 — ec25519 (Monocypher) SW re-measured cache-ON (micro-arm table)

DK SN 683609980, 100 iters, `ec25519-bench-sw-icache.hex`. Re-run so the paper's
`Table:micro-arm` X25519/Ed25519 SW rows share the cache-ON memory system with the
P-256 rows, retiring the "measured cache-disabled" caption caveat.

Stamped block (`ec25519-bench-sw` had no fw-stamp before today -- Makefile now
passes `FW_ID` as `-DFW_BUILD_ID` and the SUMMARY line prints it; a header line
`NVMC I-cache: ENABLED` was also added):

```
=== SUMMARY (X25519 + Ed25519, software (Monocypher), 100 iters, fw 20260717-icache) ===
op              n  nfail   min_us   mean_us    max_us    sd_us
x25519-keygen  200      0     25655     25658     25664         2
x25519-ecdh    200      0     25655     25658     25664         2
ed25519-keygen 100      0     13087     13092     13095         2
ed25519-sign   100      0     13873     13878     13881         2
ed25519-verify 100      0     33879     34811     35406       322
```

| op | cache-OFF (prior) | cache-ON (mean ms) | factor |
|---|---:|---:|---:|
| x25519-keygen | 28.1 | 25.66 | 1.10x |
| x25519-ecdh | 28.1 | 25.66 | 1.10x |
| ed25519-keygen | 14.5 | 13.09 | 1.11x |
| ed25519-sign | 15.4 | 13.88 | 1.11x |
| ed25519-verify | 38.8 | 34.81 | 1.11x |

**Finding — the ~1.10x I-cache gain is universal for well-written EC libs.**
Monocypher gains 1.08-1.11x, matching uECC's 1.10-1.12x. **p256-m's 1.62x was the
outlier**, not the rule: its large constant-time inner loop was uniquely
flash-fetch-bound. So the instruction cache buys a fairly constant ~1.10x across
uECC (P-256) and Monocypher (25519), and only more for a pathologically
flash-bound implementation.

**Precision note — cache-ON carries a ~1-2% build-layout sensitivity.** Two builds
of this bench that differ ONLY in the added fw-stamp code (a define + one printf
arg + `-DFW_BUILD_ID`, none touching the crypto) gave x25519 keygen/ecdh 26.044 ms
vs 25.658 ms (-1.5%), while all three Ed25519 ops moved <=0.4%. Each run is
deterministic to +-2 us (sd 2-3 us); the shift is BETWEEN builds and selective to
x25519. Cause: with the I-cache ON, absolute timing depends on where a hot loop
sits relative to cache-line boundaries, and unrelated code shifts the binary
layout -- the x25519 ladder loop crossed a line boundary in one layout, Ed25519's
did not. This is inherent to cache-ON measurement (cache-OFF has uniform
wait-states, no alignment effect, hence its cleaner run-to-run stability but slower,
unrepresentative numbers). **Read the cache-ON figures as ~+-2%**; the qualitative
comparisons (5x / 2x / 0.8x) are unaffected (X25519 HWx = 2.2 for either x25519
value). The paper quotes the stamped run (25.7 ms) as the traceable central value.

**Consequence for the Ed25519 hw-vs-sw story (strengthened):** cache-ON software
Ed25519 keygen 13.05 ms and sign 13.84 ms now clearly BEAT CC310 (14.8 / 16.7 ms) --
0.88x / 0.83x -- so "the accelerator offers no advantage for Ed25519 keygen/sign"
is now unambiguous, not marginal. CC310 keeps only the double-scalar verify
(34.96 / 17.9 = 1.95x). X25519 ECDH speedup eases to 26.04 / 11.7 = 2.22x (was
~2.4x). CC310 columns are cache-insensitive (EC math runs in the CryptoCell), so
they are unchanged.

---

# 2026-07-17 — ML-KEM (Kyber ref, SW) re-measured cache-ON

DK SN 683609980, 100 iters, `fw:20260717-icache` (`mlkem-{512,768,1024}-sw-icache.hex`;
now stamped + prints `NVMC I-cache: ENABLED`, hooks it previously lacked). All PASS
(encaps/decaps shared secret matched every iteration).

| level | keygen (ms) | encaps (ms) | decaps (ms) |
|---|---:|---:|---:|
| ML-KEM-512 | 16.46 | 17.75 | 20.66 |
| ML-KEM-768 | 27.72 | 29.96 | 34.07 |
| ML-KEM-1024 | 42.15 | 45.23 | 50.23 |

sd ~150 us (~0.4%), larger than the EC benches' ~2 us -- Kyber's rejection sampling
in keygen/encaps is data-dependent, so run-to-run variance is inherent (not the
cache-layout effect). These supersede the cache-OFF alt-kex Tier-D numbers
(2026-06-22) for the software ML-KEM column; the ~1.1x cache gain and ~±2% layout
sensitivity noted for the EC benches apply here too.
