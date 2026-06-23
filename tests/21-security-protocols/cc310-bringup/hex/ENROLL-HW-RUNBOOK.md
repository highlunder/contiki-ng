# C509 enrollment (`/crts` + `/sen`) — hardware test runbook

EDHOC Method0 + OSCORE enrollment: the device authenticates with EDHOC (native
C509 Type-2, `c5t`), fetches the CA chain (`GET /crts`), builds + self-signs a
C509 Type-3 CSR on-device (uECC/SHA-256, no mbedTLS), submits it
(`POST /sen`), and the CA issues a Type-2 cert which the device verifies.

## Status (2026-06-22)
- **Native (x86) both nodes:** PASS — `cooja-ng/configs/edhoc-oscore-enroll.json`
  (`TEST PASSED, 20.7 s sim`).
- **Native server + emulated nRF52840-DK client (Cortex-M4F):** PASS —
  `cooja-ng/configs/edhoc-oscore-enroll-nrf52840.json` (`TEST PASSED, 11.9 s
  sim`). This validates the full enroll + device-side CSR build/sign on the
  nRF52840 *architecture*.
- **Real silicon:** firmware built + staged (below); not yet run on a physical
  radio link.

## Staged firmware (this folder)
| Hex | Role | Build |
|---|---|---|
| `enroll-client-dk.hex` | DUT — enrolling device | `edhoc-oscore-crts-client`, `TARGET=nrf52840 BOARD=dk` |
| `enroll-server-dk.hex` | CA + RPL DAG root | `edhoc-oscore-crts-server`, `TARGET=nrf52840 BOARD=dk` |

Both build warning-free. Crypto is software P-256 (uECC) + SHA-256; CC310 is
**not** required for enrollment (it can be enabled separately via the ECC
service if a HW-accelerated handshake is also wanted).

## Topology
- **Server** calls `NETSTACK_ROUTING.root_start()` → it is the **RPL DAG root**
  and the CA. Its address is **`fd00::202:2:2:2`**.
- **Client** waits for `NETSTACK_ROUTING.node_is_reachable()`, then connects to
  `SERVER_EP = coap://[fd00::202:2:2:2]`
  (`edhoc-oscore-crts-client/project-conf.h`).

So the real-board test is a **two-node 802.15.4 network**: server(root/CA) ↔
client(DUT).

### Address constraint (important)
The client's `SERVER_EP` is hard-coded to `fd00::202:2:2:2`. In the simulator
that IID comes from node-id 2. On real hardware the server's IID derives from
its factory link-layer address, so **either**:
- force the server node's id to 2 (so it owns `…:202:2:2:2`), **or**
- edit `EDHOC_CONF_SERVER_EP` in the client's `project-conf.h` to the server
  DK's actual global address and rebuild.

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
Read UART with plink at `115200,8,n,1,N`. Success markers:
- server: `=== EDHOC native C509 c5t + OSCORE /sen server exchange complete ===`
- client: `=== EDHOC OSCORE enroll end-to-end test: TEST PASSED ===`

## Tuning to consider on a real (lossy) radio
The cooja runs use a loss-free UDGM medium. On real 802.15.4, prior EDHOC-on-DK
work needed: longer client connect delay before first EDHOC message, CSMA
`MAX_FRAME_RETRIES` ≈ 7, RPL/ETX and parent-timeout tuning, and a generous
server session timeout (the enroll flow has two round-trips — `/crts` then
`/sen` — so allow extra settle time after the handshake). See memories
`project_cross_platform_test`, `project_3hop_dtls_test`, `project_phase_b_c5c`
for the exact parameters that made EDHOC pass on real silicon.

## Rebuild
```
make -C tests/21-security-protocols/edhoc-oscore-crts-client TARGET=nrf52840 BOARD=dk
make -C tests/21-security-protocols/edhoc-oscore-crts-server TARGET=nrf52840 BOARD=dk
# then arm-none-eabi-objcopy -O ihex build/nrf52840/dk/<app>.nrf52840 <name>.hex
```
