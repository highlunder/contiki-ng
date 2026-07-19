# LICE-followup Phase-2 — hardware session plan (H2 + H6)

The two staged real-silicon experiments for the paper's `sec:eval-hw` Phase-2
paragraph. Both feed the numbers the cycle-accurate emulator can only predict, and
together they reproduce the original LICE evaluation's two hardware headlines:
end-to-end operation *timing* (Fig 5) and delivery under a real multi-hop mesh.

- **H2** — enrollment / handshake wall-clock on a **2-node** link (the LICE Fig-5
  operation-timing analogue: EDHOC+C509 vs the X.509 baseline).
- **H6** — multi-hop delivery/latency vs hop count on a **3–4-node line** (c509
  completes at every hop; X.509 fails at 3).

Crypto is software P-256 (uECC) + SHA-256 throughout; **CC310 not required** (the
`bench-edhoc-*-cc310-*` handshake hexes add the accelerated column if wanted).

## Boards & flashing
| board | role | flash |
|---|---|---|
| nRF52840-**DK** | root/CA/server, leaf/DUT/client | `nrfjprog --program <hex> --chiperase -r` (J-Link) |
| nRF52840-**dongle** | H6 relays only | `nrfutil` DFU (see `reference_nrf_dongle_dfu` / H6 runbook) |

Read the **client/leaf DK serial** (115200) for the result block. Server/root and
relays need no serial.

---

## Experiment H2 — enrollment wall-clock (2 nodes) — *do this first, it is 2 boards*
Firmware in `hw-enroll/` (rebuild with `./hw-enroll/stage-h2-enroll.sh`):

| arm | server (root/CA) | client (DUT) |
|---|---|---|
| **C509** | `enroll-c509-server-dk.hex` | `enroll-c509-client-dk.hex` |
| **X.509** | `enroll-x509-server-dk.hex` | `enroll-x509-client-dk.hex` |

Procedure, per arm: flash server on DK-A, client on DK-B, power both, read DK-B.
The client prints **one** block when the full EDHOC → `/crts` → `/sen` completes:
```
[ENROLL-TIMING fw:<id> arm:c509 ok:1] edhoc_ms=.. crts_sen_ms=.. total_ms=..
```
Run the C509 arm, then re-flash both DKs with the X.509 arm and repeat.
**Expected:** both complete; `total_ms` similar at 1 hop (the wire-size gap is small
over one link), with the X.509 arm's `crts_sen_ms` larger (bigger CA-cert + issued-cert
downlinks). This is the on-silicon counterpart of the enrollment-size tables
(`table:enrollment-sizes`) and the LICE Fig-5 timing.

### H2 handshake-only sweep (optional, same 2 boards, existing hexes)
For the pure-handshake wall-clock (no enrollment), the staged
`bench-edhoc-{c5t,c5c}-{sw,cc310}-{csma,tsch}.hex` and `bench-dtls-{psk,x509}-*.hex`
each print `[BENCH <label> FINAL] … (ms)` (Welford, whole result in the last line).
Pair a `*-server`/root with the bench client; the `sw` vs `cc310` pair at one `FW_ID`
isolates the CC310 speedup. (Handshake benches already characterised — re-run only to
confirm on this board set.)

---

## Experiment H6 — multi-hop delivery vs hops (3–4 nodes)
Firmware in `../multihop/fw-hw/` (built by `../multihop/stage-h6-firmware.sh`);
full detail in `../multihop/H6-FIRMWARE-STAGING.md`. Line topology is forced by the
`TOPO_ROLE` source-role filter — boards may sit 10 cm apart.

| hops | root DK (role 1) | dongle relays | leaf DK |
|---|---|---|---|
| 1 | `*-server-r1-dk` | — | `*-leaf-r2-dk` |
| 2 | `*-server-r1-dk` | `relay-r2-dongle` | `*-leaf-r3-dk` |
| 3 | `*-server-r1-dk` | `relay-r2-dongle`, `relay-r3-dongle` | `*-leaf-r4-dk` |

Run the **c5t** arm (`c5t-server` + `c5t-leaf`, leaf prints `[BENCH … FINAL] (ms)`)
and the **x5c** arm (`x5c-server` + `x5c-leaf`) at each hop count. Relays identical.
**Expected (the headline):** c5t completes at 1/2/3 hops; **x5c fails to deliver at
3 hops** while c5t succeeds — the real-RF confirmation of `table:multihop`.

---

## Logging
Record each result block **verbatim** (the `fw:`/`test:`/`arm:` ids are the join key
back to source+config):
- H2 enrollment → a new `hw-enroll/ENROLL-TIMING-RESULTS-LOG.md`.
- H2 handshake + H6 → `BENCH-RESULTS-LOG.md`.
Note the DK serial number and date with each block.

## Not in this session
- **H4 energy (PPK2)** — parked pending the SB40 board cut (`ENERGY-PPK2-RUNBOOK.md`).
- **H1 per-op crypto** and **H3 primitives** — already measured (`ENROLL-OPS-…`,
  `cc310-bringup/BENCH-RESULTS-LOG.md`); no re-run needed.
