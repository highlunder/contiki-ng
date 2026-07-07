# rxdiag — on-hardware TSCH receive-path bisection ladder

**SECURITY NOTICE: Test credentials only. Never use in production.**

## The bug we are cornering
Cert-DTLS over **TSCH** fails on the real nRF52840-DK: an ~**848 B (9-fragment)** server
flight is 6LoWPAN-reassembled and handed to IP (HW trace: *"received IPv6 packet with len
848"*) but the client's **coap-secure receive path never picks it up** — no
`[DTLS] Received DTLS message of len=848`, handshake stalls. Meanwhile **everything else
works**: PSK-DTLS over TSCH (small flight), cert-DTLS over **CSMA** (any size), bulk
`simple_udp` over TSCH (13-frag round-trips 8/8), and the **cooja-ng emulator** picks up
848 B — up to 1000 B — flawlessly. So the fault is **real-RF / TSCH-timing specific** and
must be narrowed on hardware.

**What the code told us (and why theory alone can't settle it):** UDP delivery to an app is
`process_post_synch` (synchronous), and `simple_udp` *also* waits on `tcpip_event` in a
process — so the naive "uip_buf clobbered before coap runs" story is unproven. The theory is
inconclusive; the ladder decides it empirically.

## Topology (mirrors the failure direction: server→client, downstream)
```
  ROOT / SENDER  ──TSCH/6LoWPAN, real 2.4GHz RF──▶  LEAF / RECEIVER (node under test)
  = Firefly (cc2538)                                = nRF52840-DK
    RPL root + TSCH coordinator                       runs TWO listeners for the SAME
    on the leaf's trigger, sweeps datagram            datagrams:
    sizes {700,760,820,848,880,920,1000} B              [SU]  simple_udp sync callback  (control)
    x4 trials to BOTH leaf listener ports              [RAW] raw udp_conn + tcpip_event  (suspect,
                                                             byte-for-byte coap-uip's dispatch)
```
We have both boards already (the Firefly is the proven RPL-root gateway, see
`project_firefly_gateway` / `FIREFLY-GATEWAY-README.md`; the nRF-DK joins it OTA). No 2nd nRF,
no host/tunslip, no setest needed — a self-contained Contiki↔Contiki real-RF test.

## Firmwares (built by `./build-rxdiag.sh`, all warning-free)
| file | role | MAC |
|------|------|-----|
| `rxdiag-root-firefly-tsch.bin` | Firefly root/sender | TSCH |
| `rxdiag-root-firefly-csma.bin` | Firefly root/sender | CSMA |
| `rxdiag-leaf-tsch.hex` | nRF-DK node under test | TSCH |
| `rxdiag-leaf-csma.hex` | nRF-DK node under test | CSMA |
| `rxdiag-root-tsch.hex` / `rxdiag-root-csma.hex` | nRF root | for a 2-nRF pair or the emulator |

Leaf log lines (what you read):
- `[SU]  recv len=N claimed=M` — sync path got a datagram (N bytes; M = size the sender stamped).
- `[RAW] recv len=N claimed=M lport=5689` — raw/async path got one.
- A **missing** size on a path = that path dropped it. `len != claimed` = truncation/clobber.

## Emulator baseline (already run — the comparison reference)
Full per-size baseline + interpretation: **`RXDIAG-EMULATOR-BASELINE.md`**.
- `test_runner test emul-rxdiag-tsch.json` (nRF-nRF TSCH) → **PASS**; `emul-rxdiag-nrf-csma.json`
  (nRF-nRF CSMA, rung R4) → **PASS**. In both, `[SU]` and `[RAW]` receive **every size 700–1000
  B (incl. 848), ~12/12, zero truncation** — the raw async path is as reliable as sync. No
  `[RAW]`-drops-while-`[SU]`-succeeds pattern. That is exactly what "no bug" looks like; the HW
  fault is a **divergence** from this (see R2).
- **Emulator limitation:** the literal Firefly(CC2538)↔nRF pairing does **not** converge in
  cooja-ng (mixed cc2538/nRF TSCH desyncs — CC2538 root stops beaconing, leaf never RPL-reachable;
  same for `cc2538dk`). The all-nRF run is the faithful leaf reference (leaf = identical nRF
  firmware); the real Firefly is used only on hardware. Details in the baseline doc.

## Flashing (per project_cc310_hw_bringup workflow)
- Build in WSL (done). Flash from **Windows**.
- **nRF-DK leaf:** `nrfjprog -f NRF52 --program rxdiag-leaf-tsch.hex --sectorerase --verify --reset`
  (or the objcopy→ihex is already ihex). Serial on the nRF USB CDC.
- **Firefly root:** flash `rxdiag-root-firefly-tsch.bin` with the Zolertia/cc2538 flasher
  (BSL / `cc2538-bsl.py`) as in the Firefly gateway docs. Serial on the Firefly USB.
- Capture **both** serial ports (e.g. `watch-serial.ps1` + a second terminal). The leaf log is
  the verdict; the root log confirms what was actually sent.

---

## The ladder (each rung: purpose → run → read → decide)

### R0 — Reproduce the real fault (anchor)
**Purpose:** confirm the failure is live on today's boards before diagnosing.
**Run:** flash the real cert-DTLS-over-TSCH client (`local-tests/bench/bench-dtls-x509-tsch.hex`)
against its server as usual; watch it stall with the server cert flight unacknowledged.
**Decide:** fault reproduces → proceed. Fault gone → the environment changed; re-baseline.

### R1 — Transport sanity to a leaf (rule out reassembly)
**Purpose:** prove the big datagram *reaches and reassembles at* the leaf under TSCH, so any
later drop is above 6LoWPAN.
**Run:** Firefly `rxdiag-root-firefly-tsch.bin` + nRF `rxdiag-leaf-tsch.hex`. Watch leaf.
**Read:** the `[SU]` lines across the sweep.
**Decide:**
- All sizes appear as `[SU] recv len=N claimed=N` (incl. 848, 1000) → transport + reassembly
  are fine downstream to a leaf under TSCH → **go R2**.
- Some size missing on `[SU]` too → it *is* transport/reassembly after all → jump to the
  6LoWPAN-buffer/MAXAGE analysis (enable DBG as in R3) — but note bulk already passed, so this
  would be new information.

### R2 — THE bisection: sync vs raw-async (same run as R1)
**Purpose:** the crux. Does the generic **async `tcpip_event`** path (coap-uip's mechanism)
drop large datagrams under TSCH while the **sync** path doesn't?
**Read:** for each size, compare `[SU] recv len=N` vs `[RAW] recv len=N`.
**Decide:**
- **Both** paths get every size (incl. 848) → the generic async uIP delivery is **fine** on
  HW/TSCH → the real fault is **DTLS/coap-specific** (handshake state, `process_secure_data`,
  or mbedtls record parse), not the receive dispatch → **go R5**.
- **Sync gets 848, RAW drops/truncates 848** → reproduced! the fault is the **raw async
  tcpip_event delivery of large reassembled datagrams under TSCH** — independent of DTLS →
  **go R3** to characterize, then a receive-path fix (R6) unblocks setest *and* the 2-nRF path.
- Both drop 848 → contradicts R1; re-check addressing/ports.

### R3 — Characterize the async drop (only if R2 shows a RAW drop)
**Purpose:** locate the drop between "uIP has the packet" and "process consumes it", and find
any clobber source.
**Run:** rebuild the leaf with IPv6/6LoWPAN debug and reflash:
```
make -C . TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 \
  DEFINES=LOG_CONF_LEVEL_IPV6=LOG_LEVEL_DBG,LOG_CONF_LEVEL_6LOWPAN=LOG_LEVEL_DBG \
  CC=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc AS=... LD=... AR=...ar \
  OBJCOPY=...objcopy NM=...nm SIZE=...size
```
(then `objcopy -O ihex build/nrf52840/dk/rxdiag-leaf.nrf52840 rxdiag-leaf-tsch-dbg.hex`).
**Read:** for a size the app never logs on `[RAW]`, does the IPv6 layer still print
*"received IPv6 packet with len N"*?
**Decide:**
- IPv6 log present, no `[RAW]` → drop is in **UDP demux / synchronous delivery to the process**
  (the packet reached IP but never reached the conn's process). Prime fix target.
- No IPv6 log for that size → **reassembly** intermittently fails under TSCH (despite MAXAGE
  160) → 6LoWPAN reassembly timing. Vary background traffic to confirm.
Then re-run with the mesh idle (only these 2 nodes, DAG settled) vs. with extra RPL churn to
see whether other inbound traffic is clobbering the single uip_buf/reassembly context.

### R4 — CSMA control (confirm TSCH-timing dependence)
**Purpose:** show whatever R2/R3 found is TSCH-specific.
**Run:** Firefly `rxdiag-root-firefly-csma.bin` + nRF `rxdiag-leaf-csma.hex`.
**Decide:** both paths get every size on CSMA (matches cert-DTLS working on CSMA) → the drop is
TSCH-timing dependent. If CSMA *also* drops, the cause is size/fragmentation, not slot timing.

### R5 — Instrument the real DTLS path (only if R2 shows async is fine)
**Purpose:** if the generic async path is healthy, the loss is inside DTLS/coap — find where.
**Run:** on the real cert-DTLS client, add (temporarily, guarded) a print in
`coap-uip.c` at the secure dispatch (`COAP_UIP_RX_DEBUG`, previously prototyped), in
`process_secure_data()`, and in the mbedtls BIO recv callback; reflash; run one handshake.
**Read:** does `tcpip_event` fire for the secure conn with `uip_datalen()=848`? Does
`process_secure_data` run? Does mbedtls' BIO recv get 848 bytes, and does `ssl_read` reject it?
**Decide:** localizes to handshake-state (event arrives while coap is mid-state) vs mbedtls
record framing vs BIO — pick the fix accordingly.

### R6 — Fix + verify
**Purpose:** apply the localized fix and prove 848 B passes on HW/TSCH.
**Run:** implement the fix at the point R3/R5 identified (e.g. ensure the secure conn's process
consumes the datagram at the synchronous delivery, or repair the reassembly/demux path);
re-run R2 → `[RAW]` now gets 848 B; then re-run R0 → cert-DTLS handshake completes over TSCH.

---

## Notes
- Sweep timing: `RXDIAG_GAP_MS=1500`, `RXDIAG_TRIALS=4`, 3 trigger rounds → ~5 min/run on HW.
  Tune via `DEFINES=RXDIAG_TRIALS=2,RXDIAG_GAP_MS=1000` for faster iterations.
- The leaf keeps the full bench-matched receiver provisioning (QUEUEBUF 24, TSCH pools,
  `SICSLOWPAN_MAXAGE 160`); the Firefly root uses trimmed pools (cc2538 SRAM) — sender-side
  trimming does not affect the receive-path bisection. See `project-conf.h`.
