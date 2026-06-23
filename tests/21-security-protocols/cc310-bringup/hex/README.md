# nRF52840-DK micro-benchmark firmware set

Pre-built Intel-hex images for the CC310 bring-up / paper ECC-timing
experiments. Build in WSL (arm-gcc 13.2.1), flash from Windows with
`nrfjprog` via `flash.bat`. Read serial with plink at `115200,8,n,1,N` or
JLinkRTTViewer (when a firmware is built with `DBG_CONF_RTT=1`).

J-Link SN for this DK: **683609980** (hard-coded in `flash.bat`).

## How to flash + read

From a Windows shell, in this folder (works over the `\\wsl$` share — the
`%~dp0%~nx1` pattern in flash.bat copies the file locally so cmd.exe does not
trip over the UNC cwd):

```
flash.bat ecc-bench-secp256r1-cc310.hex
```

Then open the serial console (COM port varies; was COM5 with the SEGGER
driver installed):

```
plink -serial COM5 -sercfg 115200,8,n,1,N
```

A green LED + a `RESULT: PASS (...)` line = the run is healthy.

## Paper-experiment firmwares

These three are THE images for the paper's ARM ECC-timing numbers. All run
the identical `ecc-bench` logic (keygen / sign / verify / ECDH, 100 iterations,
DWT cycle counter), so software vs hardware and curve vs curve are directly
comparable. All timing is buffered and printed only after the timed run
finishes, so no UART traffic ever falls inside a measured window.

| Hex file | Curve | Backend | Feeds |
|---|---|---|---|
| `ecc-bench-secp256r1-cc310.hex` | secp256r1 (P-256) | **CC310 hardware** | Table `bp256-arm-timing` — CC310 column; `sec:eval-algo` HW-accel claim |
| `ecc-bench-secp256r1-sw.hex`    | secp256r1 (P-256) | software (uECC)    | Table `bp256-arm-timing` — SW P-256 column (the ~8x-slower baseline) |
| `ecc-bench-bp256-sw.hex`        | brainpoolP256r1   | software (uECC)    | `sec:eval-algo` brainpool row (CC310 cannot do brainpool — SW only) |

Measured (real HW, full RPL/CSMA/IPv6 + radio, 2026-06-19), CC310 P-256:
keygen 18.86 ms, sign 20.80 ms, verify 21.92 ms, ECDH 19.15 ms — ~6 ops ×
~19 ms ≈ 114 ms, consistent with Fedrecheski 2024's ~135 ms CC310 EDHOC
handshake. Re-run the SW images for the matching software column.

Note: there is no `ecc-bench-bp256-cc310.hex` on purpose — the CC310 backend's
`map_curve()` returns NULL for brainpool, so that combination does not exist.

### How each was built (from `cc310-bringup/ecc-bench/`)

```
make TARGET=nrf52840 BOARD=dk ECC_HW_BACKEND=cc310   # -> secp256r1-cc310
make TARGET=nrf52840 BOARD=dk                         # -> secp256r1-sw
make TARGET=nrf52840 BOARD=dk BP256=1                 # -> bp256-sw
```

then `arm-none-eabi-objcopy -O ihex build/nrf52840/dk/ecc-bench.nrf52840 <name>.hex`.
Do a clean build between curve/backend switches (`make ... clean`) so the
right `ecc.c` / CC310 backend objects are linked.

## Other key-establishment algorithms (Tier A + Tier D)

Companion benchmarks for the "what else makes sense on this class of device"
study. Same DWT + SUMMARY harness as `ecc-bench`, so all rows are comparable.
**Built and (for ML-KEM) host-validated 2026-06-22; on-device cycle counts
pending the board's return.**

| Hex file | Algorithm | Backend | Notes |
|---|---|---|---|
| `ec25519-bench-cc310.hex` | X25519 ECDH + Ed25519 EdDSA | **CC310 hardware** | EDHOC suite 0/1/4 primitives; the standards-default alternative to P-256/ES256 (suite 2/3) |
| `ec25519-bench-sw.hex`    | X25519 ECDH + Ed25519 EdDSA | software (Monocypher) | sw counterpart to the row above → hardware-vs-software speedup for the 25519 family (mirrors P-256 hw/sw) |
| `mlkem-512-sw.hex`  | ML-KEM-512 (FIPS 203)  | software (pq-crystals ref) | PQC KEM; pk 800 / ct 768 |
| `mlkem-768-sw.hex`  | ML-KEM-768 (FIPS 203)  | software (pq-crystals ref) | PQC KEM; pk 1184 / ct 1088 |
| `mlkem-1024-sw.hex` | ML-KEM-1024 (FIPS 203) | software (pq-crystals ref) | PQC KEM; pk 1568 / ct 1568 |

Build:
```
# Tier A (from ec25519-bench/) — CC310 X25519 + Ed25519:
make TARGET=nrf52840 BOARD=dk            # ECC_HW_BACKEND=cc310 + CC310_ECC_25519=1 are set in the Makefile
# Tier A software counterpart (from ec25519-bench-sw/) — Monocypher X25519 + Ed25519:
make TARGET=nrf52840 BOARD=dk            # -> ec25519-bench-sw.hex

# Tier D (from mlkem-bench/) — software ML-KEM, level via MLKEM=512|768|1024:
make TARGET=nrf52840 BOARD=dk MLKEM=512
make TARGET=nrf52840 BOARD=dk MLKEM=768
make TARGET=nrf52840 BOARD=dk MLKEM=1024  # clean between levels
```

Notes:
- **No CC310 column for ML-KEM**: CryptoCell-310 has no lattice/Keccak
  acceleration, so PQC is software-only. The reference C is also not
  Cortex-M-optimized — the optimized path is pqm4 / mlkem-native (ARM asm);
  these numbers are the portable-ref baseline.
- The CC310 X25519/Ed25519 wiring is opt-in (`CC310_ECC_25519=1` in
  `Makefile.cc310-crypto`), so the validated secp256r1 production builds are
  byte-for-byte unchanged.
- ML-KEM's story is **bandwidth, not compute**: its pk+ct is ~1.6–3.1 KB vs
  32–64 B for ECC, which is what hits the 802.15.4 radio (6LoWPAN
  fragmentation / airtime / energy) — exactly where C509 + EDHOC sizing
  matter. The bench prints a `sizes:` line for this.

## Bring-up-ladder firmwares (diagnostics, not paper data)

Kept for re-verifying the board after a toolchain or SDK change.

| Hex file | Rung | Purpose |
|---|---|---|
| `hello-world.hex`               | 1 | board alive, console prints |
| `board-check.hex`               | 2 | LEDs/GPIO, clock, DWT counter sanity |
| `rnd_pca10056.hex`              | — | Nordic SDK reference CC310 RNG example (Nordic toolchain) — the known-good control that proved CC310 silicon works |
| `rnd_pca10056_ourtoolchain.hex` | — | same example rebuilt with **our** arm-gcc 13.2.1 — proved the toolchain is not the cause |

## Superseded / duplicate (safe to delete)

Older un-suffixed names from before the curve-selectable split; identical
logic to the `secp256r1-` images above, kept only until the paper tables are
locked:

- `ecc-bench-cc310.hex`  → use `ecc-bench-secp256r1-cc310.hex`
- `ecc-bench-sw.hex`     → use `ecc-bench-secp256r1-sw.hex`

## Why the CC310 image needs the RNG fix

The CC310 backend's one-time TRNG seeding is disrupted by the 128 Hz RTC
system tick and fails (`CRYS_RndInit` -> 0xf00c12) unless run inside a
BASEPRI critical section that masks every IRQ except CC310's own completion
interrupt. That fix lives in
`arch/cpu/nrf52840/dev/nrf52840-cc310-ecc.c::ecc_session_begin()`. Full
write-up: `paper_space/PLAN-c509-lice-followup.md` §9.11. Without it the
`-cc310` image prints `RESULT: FAIL`.
