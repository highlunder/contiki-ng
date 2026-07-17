# rev-ops-bench — on-device C509 revocation consume-path microbench (LRev E4/E6)

The revocation-paper analogue of `enroll-ops-bench`: a pure-compute, no-radio
per-operation microbenchmark for the self-contained C509 **revocation** consume
path in `os/services/c509/` (`c509-crl`, `c509-ocsp`, `c509-ocsp-req`,
`c509-rev-verify[-ecdsa]`, `c509-cbor-lite`). It fills the LRev evaluation's
Tier-1 gaps E4 (per-op cycles/latency) and E6 (ROM/RAM footprint) — the
constrained-target numbers the host-only `c509rev` Rust impl cannot give.

Five operations, each timed and printed in one traceable `[ROP …]` block with a
firmware build id + per-op test id:

| op | function | what it costs |
|---|---|---|
| `crl-parse`     | `c509_crl_parse()`             | CBOR walk of the 11-element CRL, locate the revoked-cert group |
| `crl-lookup`    | `c509_crl_is_revoked()`        | binary search of the fixed-width entries, worst-case (last) serial |
| `ocsp-lookup`   | `c509_ocsp_lookup()`           | status lookup by (issuerCertHash, serialNumberHash) in a Basic response |
| `ocspreq-build` | `c509_ocsp_build_simple_request()` | assemble a `C509SimpleOCSPRequest` (CBOR, no crypto) |
| `ecdsa-verify`  | `c509_rev_verify_ecdsa_p256()` | locate TBS → SHA-256 → 1 ECDSA-secp256r1 `uECC_verify` |

The `crl-parse`/`crl-lookup`/`ocsp-lookup`/`ocspreq-build` ops are the
**C509-specific codec cost** — the revocation analogue of the LICE paper's
"C509→DER overhead" measurement — and are cycle-accurate on the emulator. The
`ecdsa-verify` op is the ms-scale software signature-verify baseline (the same
P-256 verify done for any certificate; ~10× faster on CC310, cf. the CC310
hw-crypto results). The signed CRL it verifies is **synthesised at startup**
(sign `CRL_NO_REVOKED`'s TBS with a test key, patch the sigValue), so no external
vector is needed and the measured path is exactly locate→SHA-256→verify.

The Ed25519 rev-sig path is deliberately not linked (it pulls in mbedTLS
SHA-512); a never-called local `ed25519_verify` stub satisfies the linker for the
shared `c509-rev-verify.o`. The Ed25519 verify cost is the same primitive already
characterised by the alt-kex benches.

## Emulator (cooja-ng-ge) — E4

The emulated nRF52840 has no DWT cycle counter and a ~16 µs-granular rtimer, so
the fast codec ops are timed in **batches** of `ROP_BATCH` (default 128) and the
per-op figure is the batch total ÷ `ROP_BATCH`; the mean uses an integer running
sum (robust against the emulator's soft-double).

```
ARM=/home/joel/toolchains/arm-gcc/bin
make TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= FW_ID=20260717 \
  CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
  AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm
cp build/nrf/nrf52840/dk/rev-ops-bench.nrf ../emul/rev-ops-bench-emul.nrf52840
/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner test ../emul/emul-rev-ops.json
```

### Result (emulated nRF52840, 64 MHz Cortex-M4, software/uECC, 2026-07-17)

`rev-ops-emul-20260717.log`, fw:20260717, iters=50, batch=128:

| op | per-op mean | ~cycles @64 MHz |
|---|---:|---:|
| crl-parse     | 26.56 µs   | ~1 700 |
| crl-lookup    | 3.07 µs    | ~196 |
| ocsp-lookup   | 33.15 µs   | ~2 122 |
| ocspreq-build | 8.58 µs    | ~549 |
| ecdsa-verify  | 109.9 ms   | ~7.03 M |

**Headline:** the whole C509 revocation *codec* (parse a CRL/OCSP object + one
lookup, or build a request) is tens of µs — negligible against the single
~110 ms signature verify, which is the same P-256 verify done to validate any
certificate (and ~10× faster on CC310). A relying party's marginal compute to
*consume* revocation state is therefore in the noise of the handshake it already
performs.

## Footprint — E6 (`arm-none-eabi-size` on the object files)

Flash (`.text`, bytes) of the revocation consume path; `.data`/`.bss` are **0**
for every module — no static RAM (working buffers are caller-provided stack), and
SHA-256/uECC are already linked by the DTLS/EDHOC stack:

| module | text (B) | role |
|---|---:|---|
| c509-crl.o            | 1 016 | CRL parse + binary-search lookup |
| c509-ocsp.o           | 1 232 | OCSP response status codec |
| c509-ocsp-req.o       | 1 708 | OCSP request builders (simple/unsigned/signed) |
| c509-rev-verify.o     |   400 | TBS locator + Ed25519 verify |
| c509-rev-verify-ecdsa.o | 108 | ECDSA-P256 verify |
| c509-cbor-lite.o      |   400 | shared read-only CBOR walker |
| **total**             | **4 864** | ≈ 4.8 KB flash, **0 B static RAM** |

CRL-only consume (crl + cbor-lite + rev-verify[-ecdsa]) is ~1.9 KB; OCSP-only
(ocsp + cbor-lite) is ~1.6 KB.

## Hardware (DK) — deferred to the PPK2/energy tier

The same firmware flashes on the nRF52840-DK; read the `[ROP …]` block over
USB-CDC for the on-silicon figures and the CC310 sign/verify comparison. That is
the E5 energy tier (task #28/#40), out of the emulator's scope (cooja-ng does not
model the CC310 CryptoCell).

SECURITY NOTICE: Test credentials only. Never use in production.
