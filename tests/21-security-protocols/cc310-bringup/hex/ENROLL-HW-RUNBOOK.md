# C509 enrollment (`/crts` + `/sen`) — hardware test runbook

EDHOC Method0 + OSCORE enrollment: the device authenticates with EDHOC (native
C509 Type-2, `c5t`), fetches the CA chain (`GET /crts`), builds + self-signs a
C509 Type-3 CSR on-device (uECC/SHA-256, no mbedTLS), submits it
(`POST /sen`), and the CA issues a Type-2 cert which the device verifies.

## Status (2026-07-16)
- **Native (x86) both nodes:** PASS — `cooja-ng/configs/edhoc-oscore-enroll.json`
  (`TEST PASSED, 20.7 s sim`).
- **Native server + emulated nRF52840-DK client (Cortex-M4F):** PASS —
  `cooja-ng/configs/edhoc-oscore-enroll-nrf52840.json` (`TEST PASSED, 11.9 s
  sim`). This validates the full enroll + device-side CSR build/sign on the
  nRF52840 *architecture*.
- **X.509 comparison arm (PKCS#10 uplink + runtime X.509 DER downlinks):** PASS
  in cooja-ng-ge over 1-hop TSCH (`emul-enroll-x509-pkcs10-1hop-tsch.json`,
  `TEST PASSED @18.3 s`). This is the fully-faithful X.509 enrollment: all three
  flights X.509-sized, on-device, uECC-only (no mbedTLS). See
  `local-tests/multihop/X509-ENROLL-WRAPPING.md`.
- **Real silicon:** all four firmwares built + staged (below); not yet run on a
  physical radio link.

## Staged firmware (this folder)

**C509 enrollment (the primary arm):**
| Hex | Role | Build |
|---|---|---|
| `enroll-client-dk.hex` | DUT — enrolling device | `edhoc-oscore-crts-client`, `TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH` |
| `enroll-server-dk.hex` | CA + RPL DAG root | `edhoc-oscore-crts-server`, same flags |

**X.509 enrollment (the comparison arm, `ENROLL_X509_DYN=1`):**
| Hex | Role | Build |
|---|---|---|
| `enroll-x509-client-dk.hex` | DUT — submits a genuine PKCS#10 DER CSR | `edhoc-oscore-crts-client`, `… ENROLL_X509_DYN=1` |
| `enroll-x509-server-dk.hex` | CA — parses PKCS#10, returns X.509 DER (runtime-reconstructed) | `edhoc-oscore-crts-server`, `… ENROLL_X509_DYN=1` |

All four build warning-free (only the pre-existing nrfx UARTE + linker-RWX
platform warnings). Crypto is software P-256 (uECC) + SHA-256; **CC310 is not
required** for enrollment. Both arms share the CA identity, PoP path, and issuance
logic — the X.509 arm only changes the three flights' wire encoding (PKCS#10 CSR
up; full X.509 DER CA cert + issued cert down) so the on-device C509-vs-X.509
difference is purely the certificate wire size and the encode/parse cost.

## Topology
- **Server** calls `NETSTACK_ROUTING.root_start()` → it is the **RPL DAG root**
  and the CA. Its address is **`fd00::202:2:2:2`**.
- **Client** waits for `NETSTACK_ROUTING.node_is_reachable()`, then connects to
  `SERVER_EP = coap://[fd00::202:2:2:2]`
  (`edhoc-oscore-crts-client/project-conf.h`).

So the real-board test is a **two-node 802.15.4 network**: server(root/CA) ↔
client(DUT).

### Address resolution (now dynamic — no hard-coded IID)
The current firmware sets `EDHOC_CONF_SERVER_FROM_ROOT` in the client's
`project-conf.h`, so the client resolves the responder/CA as the **RPL DAG root**
for both the EDHOC handshake and the `/crts`+`/sen` OSCORE endpoints — it no
longer depends on the server owning the hard-coded `fd00::202:2:2:2` IID. On real
hardware the server's IID derives from its factory link-layer address, and the
client will still reach it via the root. (If you rebuild without
`EDHOC_CONF_SERVER_FROM_ROOT`, the old constraint returns: force the server node
to id 2, or edit `EDHOC_CONF_SERVER_EP` and rebuild.)

## Running on real hardware
With **one** DK you can only place one node on silicon; the second node needs a
radio. Options:

1. **Two physical radios (cleanest):** flash `enroll-server-dk.hex` to one
   DK/dongle and `enroll-client-dk.hex` to the second. Power both; the client
   joins the root's DAG and enrolls. (Requires a 2nd nRF52840 board/dongle.)
2. **Client on DK + native server via bridge:** run the server as a native
   process behind a `rpl-border-router` + `slip-radio` (the
   `secure-endpoint-test-server/run-cross-platform-test.sh` template), with the
   slip-radio on a USB 802.15.4 device. The DK runs `enroll-client-dk.hex`.
3. **Architecture-validated interim (done):** the emulated-nRF52840 cooja-ng
   run above already exercises the M4F client end-to-end; use it as the
   reproducible result until a 2nd radio is available for a pure-silicon run.

### Flash (Windows, from this folder)
```
flash.bat enroll-server-dk.hex     # onto the server/root DK (option 1)
flash.bat enroll-client-dk.hex     # onto the DUT DK
```
Read UART with plink at `115200,8,n,1,N`. Success markers (both arms):
- server: `=== EDHOC native C509 c5t + OSCORE /sen server exchange complete ===`
- client: `=== EDHOC OSCORE enroll end-to-end test: TEST PASSED ===`

X.509-arm-specific server lines (confirm the fully-faithful path ran):
- `/crts: reconstructed X.509 DER CA cert (289 bytes)`
- `/sen: parsed 213-byte PKCS#10 CSR (CN edhoc-client), PoP OK`
- `/sen: reconstructed X.509 DER cert (288 bytes)`
X.509-arm client line: `Built 150-byte C509 CSR -> 213-byte self-signed PKCS#10 DER CSR`

## On-hardware C509-vs-X.509 comparison (the measurement)
Run the same two-node topology **twice** — once with the C509 pair
(`enroll-{server,client}-dk.hex`), once with the X.509 pair
(`enroll-x509-{server,client}-dk.hex`) — and compare. Everything except the three
flights' wire encoding is identical, so the delta isolates the certificate-size
effect on a real radio.

**Latency (no extra instrumentation).** The client logs a timestamp per leg
(`EDHOC finished`, `/crts received`, `/sen received … TEST PASSED`). Capture the
UART and diff the C509 vs X.509 totals + per-leg splits. Expectation (from the
in-emulator TSCH runs and the multi-hop study): near-parity at 1 hop on a
loss-free bench link, with X.509 paying extra 6LoWPAN fragments per downlink
(289/288 B vs 133/145 B) and the 213 B PKCS#10 CSR vs 150 B C509 CSR on the
uplink — the gap widens on a lossy/multi-hop link, where the emulator shows X.509
enrollment failing at 2 hops (0/3) while C509 recovers (Table `multihop-mac` in
the paper).

**Absolute energy (PPK2 — task #28).** With a Nordic Power Profiler Kit II in
series on the DUT (source-meter mode, board cut for VDD measurement per the PPK2
guide), integrate current over each labelled leg to get mJ/enrollment. Trigger the
PPK2 capture on the client's first EDHOC TX and stop on `TEST PASSED`; segment by
the UART leg markers. Report: (a) mJ/enrollment C509 vs X.509, (b) the per-leg
breakdown (EDHOC handshake vs `/crts` vs CSR build/sign vs `/sen`), (c) idle
draw between legs. The device-side crypto (CSR build/sign PoP, cert verify) is
identical across arms; the measurable energy delta is radio-time on the larger
X.509 flights. Pair this with the per-op crypto benches (`ecc-bench` uECC/CC310 +
`p256m-bench`, staged in this folder) for the compute-vs-radio split.

## Tuning to consider on a real (lossy) radio
The cooja runs use a loss-free UDGM medium. On real 802.15.4, prior EDHOC-on-DK
work needed: longer client connect delay before first EDHOC message, CSMA
`MAX_FRAME_RETRIES` ≈ 7, RPL/ETX and parent-timeout tuning, and a generous
server session timeout (the enroll flow has two round-trips — `/crts` then
`/sen` — so allow extra settle time after the handshake). See memories
`project_cross_platform_test`, `project_3hop_dtls_test`, `project_phase_b_c5c`
for the exact parameters that made EDHOC pass on real silicon.

## Rebuild
C509 arm:
```
make -C tests/21-security-protocols/edhoc-oscore-crts-client TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH
make -C tests/21-security-protocols/edhoc-oscore-crts-server TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH
```
X.509 comparison arm (add `ENROLL_X509_DYN=1`):
```
make -C tests/21-security-protocols/edhoc-oscore-crts-client TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH ENROLL_X509_DYN=1
make -C tests/21-security-protocols/edhoc-oscore-crts-server TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH ENROLL_X509_DYN=1
```
Pass the workspace ARM toolchain (`CC=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc`
+ `AS=/LD=/AR=/OBJCOPY=/NM=` likewise; see `reference_arm_toolchain`). Then:
```
arm-none-eabi-objcopy -O ihex build/nrf/nrf52840/dk/<app>.nrf <name>.hex
```
Do a clean `rm -rf build` between the two arms — the `ENROLL_X509_DYN` define
change does not by itself retrigger a rebuild.
