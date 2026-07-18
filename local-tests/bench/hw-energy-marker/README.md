# Marker-on energy firmware (Exp H4) — staged for flashing

All built 2026-07-17 with `ENERGY_MARKER_PIN=10` (nRF **P1.10** → PPK2 D0) and the
platform I-cache ON. DUT = nRF52840-DK (SN 683609980), measured via its P22
current header. See `../ENERGY-PPK2-RUNBOOK.md` for wiring.

| hex | board | flash | role |
|---|---|---|---|
| `enroll-ops-marker-dk.hex` | DK | J-Link | **capture 3** — per-op enrollment energy (single board, no radio). The clean, do-first capture. |
| `dut-c5t-{sw,cc310}-{csma,tsch}-dk.hex` | DK | J-Link | **capture 4** — per-handshake energy DUT (EDHOC c5t **initiator**; marker spans run→finished). |
| `peer-c5t-server-{csma,tsch}-dongle.hex` | dongle | DFU | the handshake peer (responder + RPL root + TSCH coordinator). |

⚠️ **Topology note for the handshake set.** To make the DK the PPK2 DUT, the roles
are **swapped** vs the latency 2×2 in `TSCH-HW-RESULTS.md` (there the DK was the
responder/root). Here the **DK is the initiator/leaf** and the **dongle is the
responder/root/coordinator**. This arrangement has **not been run** — smoke-test that
the DK associates and completes a handshake (watch the DK serial for `[BENCH … FINAL]`)
before trusting any energy number. The dongle-as-coordinator path in particular is
new. `enroll-ops` has no such caveat.

The dongle peer backend is software for both DK backends: the DK's own current is
what varies with its sw/cc310 build; the peer only needs to complete the handshake.

Flash (DK, J-Link):
```
nrfutil device program --options chip_erase_mode=ERASE_RANGES_TOUCHED_BY_FIRMWARE,verify=VERIFY_READ,reset=RESET_SYSTEM \
  --family nrf52 --serial-number 683609980 --firmware <hex>
```
Flash (dongle, DFU — generate the zip first, see RUNBOOK / below):
```
nrfutil nrf5sdk-tools pkg generate --hw-version 52 --sd-req 0x00 \
  --application peer-c5t-server-<mac>-dongle.hex --application-version 1 dfu/peer-<mac>.zip
nrfutil nrf5sdk-tools dfu usb-serial -pkg dfu/peer-<mac>.zip -p /dev/ttyACM0
```

SECURITY NOTICE: Test credentials only. Never use in production.
