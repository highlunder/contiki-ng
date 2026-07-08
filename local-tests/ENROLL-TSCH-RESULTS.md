# Full C509 CSR-based enrollment over TSCH (Tier-2) — in-emulator result

**Purpose.** Extend the handshake-over-TSCH study (`TSCH-C509-VS-X509-LATENCY.md`) to the
*full enrollment workload*: EDHOC (Method 0, c5t) + `/crts` (fetch CA chain) + `/sen`
(submit C509 Type-3 CSR, receive issued C509 Type-2 cert), all over a duty-cycled
TSCH/Orchestra MAC. This is Tier-2 of `paper_space/PLAN-c509-enroll-experiment.md`.

**SECURITY NOTICE: Test credentials only. Never use in production.**

## Setup
Apps `tests/21-security-protocols/edhoc-oscore-crts-{client,server}`, shared nrf platform
(`TARGET=nrf BOARD=nrf52840/dk`, **nrfx v3.12.1**), `MAKE_MAC=MAKE_MAC_TSCH
MAKE_WITH_ORCHESTRA=1`, sw uECC P-256. 2-node cooja-ng-ge, UDGM lossless. Server = node 2
= RPL root + TSCH coordinator + CA/EDHOC-responder; client = node 1 = enrolling device.
Config `bench/emul/emul-enroll-c5t-tsch.json`. **Same two enabling fixes as the handshake
apps**: `tsch_set_coordinator(1)` on the server, `EDHOC_CONF_SERVER_FROM_ROOT` on the
client (also applied to the `/crts`+`/sen` endpoint, not just the EDHOC leg).

## Result — PASS (issued cert verified against the CA key)

| Leg | Wire (UDP / payload) | Sim-time window | **Latency** |
|---|---|---|---|
| Network association (TSCH) | — | 0 → 25.611 s | (assoc + settle) |
| **EDHOC handshake (c5t)** | msg1/2/3 | 25.69 → 26.99 s | **1.30 s** |
| **`/crts`** GET → chain verified | 13 B → 135 B (CertificateChain) | 27.50 → 27.81 s | **0.32 s** |
| **`/sen`** POST(CSR) → issued cert verified | 164 B (CSR 150 B) → 144 B (Type-2 cert) | 27.92 → 28.51 s | **0.58 s** |
| **Full enrollment** (net-ready → cert verified) | — | 25.611 → 28.505 s | **2.89 s** |

The wire sizes reproduce the CSMA plan/paper numbers **to the byte** (`/crts` 13/135,
`/sen` 164 B with a 150 B C509 Type-3 CSR, 144 B issued C509 Type-2 cert), confirming the
enrollment objects are unchanged by the MAC — TSCH only reshapes *when* the fragments go
out, not the payloads.

## Reading

- The **full C509 enrollment completes over duty-cycled TSCH** in ~2.9 s from network
  association, decomposing into the ~1.3 s EDHOC handshake plus two short OSCORE round
  trips (`/crts` ~0.32 s, `/sen` ~0.58 s). Each OSCORE leg is only 1–2 6LoWPAN fragments
  per direction, so it costs a few slotframes, not seconds.
- **`/sen` > `/crts`** because the CSR POST (164 B ≈ 2 fragments) plus the CA's
  ECDSA-P256 issuance sign is heavier than the `/crts` GET (13 B) + 135 B chain response.
- **Robustness caveat (same as the handshake study).** These are single-seed absolute
  latencies on nrfx v3.12.1; the sub-second per-leg values carry slot-alignment jitter of
  ~1 slotframe (≈70–140 ms) and will shift with seed / slotframe length / driver version.
  What is deterministic and robust: the flow completes, the leg *structure* (handshake +
  two OSCORE round trips), and the wire sizes.

## The X.509 comparison arm (next step, not yet built)

To turn this into a C509-vs-X.509 enrollment-over-TSCH result, the missing arm is an
**X.509/PKCS#10 (or EDHOC-x5chain) enrollment**: its CSR is ~408 B (vs the 150 B C509
Type-3 here — see the §8 table in the plan, C509 CSRs are 25–49 % of PKCS#10) → ~5
fragments vs ~2 on the `/sen` POST, plus a larger issued DER cert and a larger EDHOC
credential flight. Expectation: the X.509 enrollment's `/sen` leg (and its EDHOC leg, cf.
the x5c handshake ~2.0 s vs C509 ~1.3 s) each cost extra slotframes, so the **C509
full-enrollment latency saving compounds** the handshake saving. Recommended build: an
`edhoc-oscore-crts` x5chain variant reusing the scenario-C credential path.

## Repro
```sh
R=/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner
$R test /home/joel/gemini_workspace/contiki-ng/local-tests/bench/emul/emul-enroll-c5t-tsch.json
```
Firmware: `make TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 <arm-toolchain>`.
