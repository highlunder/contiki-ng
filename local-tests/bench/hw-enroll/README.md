# Enrollment wall-clock on silicon (Exp H2) — C509 vs X.509

The `/crts`+`/sen` enrollment flow (EDHOC Method0 c5t + OSCORE; fetch CA chain,
build+self-sign a CSR on-device, submit it, verify the issued cert) timed on real
hardware, C509 vs the fully-dynamic X.509 arm. Closes the "real hardware" side of
the enrollment experiment (tasks #19/#33 were native + cooja only).

The client (`edhoc-oscore-crts-client`) is instrumented (2026-07-17) to print one
self-identifying block splitting the EDHOC handshake from the post-handshake
enrollment:
```
[ENROLL-TIMING fw:<id> arm:c509|x509 ok:1] edhoc_ms=.. crts_sen_ms=.. total_ms=..
```
`clock_time()` based (multi-second flow, wrap-safe; ~8 ms resolution — ample where
the arms differ by ~0.1 s).

**SECURITY NOTICE: Test credentials only. Never use in production.**

## Emulator baselines (cooja-ng-ge, TSCH 1-hop, the comparison target)

| arm | edhoc_ms | crts_sen_ms | total_ms |
|---|---:|---:|---:|
| C509 | 1476 | 1515 | **2992** |
| X.509 | 1476 | 1617 | **3093** |

At 1-hop lossless the arms differ by only **+101 ms** (all in the enrollment leg;
the c5t handshake is identical). The enrollment size effect (C509 ~135/144 B vs
X.509 ~380 B downlinks) is decisive at *depth/loss* — X.509 enroll fails at 2 hops,
shown in `local-tests/multihop/` — not at 1 hop. So the HW run here is a wall-clock
**cross-check against the emulator**, on the same footing as the EDHOC 2x2.

## Firmware (staged, TSCH, I-cache ON, `fw:20260717-en`)

| hex | board | role |
|---|---|---|
| `enroll-c509-client-dk.hex` | client DK | DUT — reads `[ENROLL-TIMING]` (C509 arm) |
| `enroll-c509-server-dk.hex` | server DK | CA + RPL root + TSCH coordinator (C509) |
| `enroll-x509-client-dk.hex` | client DK | DUT (X.509 arm, `ENROLL_X509_DYN=1`) |
| `enroll-x509-server-dk.hex` | server DK | CA (X.509, returns runtime-reconstructed DER) |

TSCH to match the emulator baseline and the paper's enrollment experiment. Both
built for `nrf52840/dk`, so **2 DKs, both J-Link-flashed** (no dongle DFU).

## Run (2 DKs)

Roles: **client = DK1 (SN 683609980)** — we read its serial; **server = DK2** (find
its SN with `nrfutil device list`). Flash the matching arm to both, power both,
wait for TSCH association (~60–70 s real-RF scan) + RPL, then the client enrolls once
and prints the block.

C509 arm:
```
# server (DK2):
nrfutil device program --options chip_erase_mode=ERASE_RANGES_TOUCHED_BY_FIRMWARE,verify=VERIFY_READ,reset=RESET_SYSTEM --family nrf52 --serial-number <DK2_SN> --firmware enroll-c509-server-dk.hex
# client (DK1):
nrfutil device program --options chip_erase_mode=ERASE_RANGES_TOUCHED_BY_FIRMWARE,verify=VERIFY_READ,reset=RESET_SYSTEM --family nrf52 --serial-number 683609980 --firmware enroll-c509-client-dk.hex
# read the client (DK1 J-Link CDC):
timeout 300 python3 ../ts-serial.py /dev/ttyACM1 115200
```
Watch for `=== ... TEST PASSED ===` then the `[ENROLL-TIMING ... arm:c509 ...]` line.
Then swap both boards to the `x509` hexes and repeat.

A single enrollment per flash. For a few samples, tap the client's RESET between
runs (the server stays up). Record each block in `ENROLL-HW-RESULTS.md`.

## Expectation

The EDHOC 2x2 showed HW handshake latency close to (slightly below) the emulator, so
expect HW `total_ms` in the ~2.5–3 s band, both arms within ~0.1 s of each other and
of the emulator's 2992/3093. A large HW-vs-emulator divergence would point at the
real-RF TSCH schedule, not the crypto.
