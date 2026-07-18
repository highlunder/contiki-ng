# nRF5340 radio-IPC bridge — feasibility scope

**Question:** can we build an inter-core IPC "radio proxy" so the nRF5340-DK **application
core** (512 KB RAM, fits mbedTLS DTLS) drives the 802.15.4 radio that physically lives on
the **network core** — making the nRF5340-DK usable as a TSCH cert-DTLS endpoint (the 2nd
device for the 2-nRF hardware test)?

**Short answer: not for TSCH, not without rearchitecting Contiki-NG's MAC.** A naive
`NETSTACK_RADIO` serialization works only for CSMA. Contiki-NG's TSCH is software-timed and
structurally incompatible with a serialized radio. The only sound split (TSCH on the network
core, DTLS on the app core) is a multi-week RCP/host port that *also* changes the timing
characteristics the paper is trying to measure. **A 2nd nRF52840-DK remains the pragmatic path.**

---

## 1. Why the app core needs a bridge at all
- `arch/cpu/nrf/nrf5340-application-def.h`: `NETSTACK_CONF_RADIO nullradio_driver` — the app
  core has **no 802.15.4 radio**.
- `arch/cpu/nrf/net/nrf-ieee-driver-arch.c` touches the RADIO peripheral registers directly;
  those registers exist only on the network core. No IPC/core-gating in the driver today
  (`nrfx_ipc.c` is compiled but unused for radio).
- Network core RAM = **64 KB** (`lib/nrfx/mdk/nrf5340_xxaa_network.ld`), but the X.509 DTLS
  server needs **≈91 KB bss** (64 KB mbedTLS arena + netstack). So DTLS *must* live on the app
  core; the radio *must* live on the network core; something has to bridge them.

## 2. The radio API is serializable — the timing model is not
`os/dev/radio.h` is a clean 13-function interface (`init/prepare/transmit/send/read/
receiving_packet/pending_packet/on/off/get_value/set_value/get_object/set_object`) — exactly
what Nordic's `nrf_802154_serialization` and Zephyr's nRF5340 IEEE-802.15.4 split serialize
over RPMsg/IPC. Serializing the *calls* is routine.

The problem is **when** and **how fast** TSCH calls them. From `tsch-slot-operation.c`:
- **Software-timed slots.** `RTIMER_BUSYWAIT_UNTIL_ABS(...)` spins to an exact rtimer offset,
  then calls the radio *synchronously in-line*. E.g. it waits to
  `tsch_ts_tx_offset − RADIO_DELAY_BEFORE_TX` (L613) and *immediately* calls
  `NETSTACK_RADIO.transmit()` (L616), trusting the over-air TX to happen exactly
  `RADIO_DELAY_BEFORE_TX` later.
- **`RADIO_DELAY_BEFORE_TX` is a fixed compile-time constant** = `US_TO_RTIMERTICKS(5·32)` =
  **160 µs** (SHR air time); `RADIO_DELAY_BEFORE_RX` = **250 µs** (`nrf-def.h:77-79`). These
  model a *local* radio's deterministic register-to-air latency. Any IPC round-trip latency +
  jitter added on top is *pure TSCH timing error* — it is not accounted for anywhere.
- **µs-granularity RX polling.** ACK detection busy-polls `NETSTACK_RADIO.receiving_packet()`
  in tight `RTIMER_BUSYWAIT_UNTIL_ABS` loops (L649-656, L835-850). Serializing that poll over
  IPC (IRQ + shared-mem handshake per poll) is orders of magnitude too slow/jittery.
- **Cross-core time domain.** TSCH drift correction reads `RADIO_PARAM_LAST_PACKET_TIMESTAMP`
  (L875) in the *app-core* rtimer domain, but the capture happens on the *network-core* timer.
  The two cores have independent clocks → timestamps need a synchronized time base.

TSCH timeslot tolerances are single-digit µs for TX-offset accuracy; an nRF5340 IPC round-trip
(write shared RAM → IPC IRQ → network-core ISR → radio op → reply) is several µs *with jitter*.
**The busy-wait-then-call-transmit model assumes near-zero, deterministic, local latency —
which an inter-core hop cannot provide.** CSMA has no such timing coupling and *would* work
over a serialized radio; TSCH will not.

## 3. Why Zephyr/OpenThread can serialize but Contiki can't (as-is)
Nordic's stacks serialize the **scheduled** radio API — `nrf_802154_transmit_raw_at(timestamp)`
— where the *network-core* radio driver arms its own timer to fire at an absolute time. IPC
latency is then irrelevant as long as the command arrives before the target instant. Contiki-NG
TSCH does **not** use scheduled/absolute-time TX; it times slots in software on the host core.
So serialization would require either:
- **(a)** teaching Contiki TSCH + the nRF driver a scheduled `transmit_at`/`receive_at` API
  (large MAC rewrite, touches portable TSCH core — risky, upstream-scope), or
- **(b)** moving the whole timing-critical slot engine to the network core.

## 4. The only sound architecture = split at the MAC/network boundary (RCP/host)
Run **TSCH + the radio** on the network core (co-located, timing intact); serialize the
*coarse* packetbuf-level MAC↔6LoWPAN handoff over IPC; run **6LoWPAN/IPv6/CoAP/DTLS** on the
app core (512 KB, mbedTLS fits). This is the OpenThread "RCP + host" model and is IPC-latency
tolerant (packet granularity, not µs slot granularity).

Cost/risks:
- Contiki-NG has **no** MAC/network IPC split today — this is new platform code on both cores
  plus a shared-memory packetbuf transport and flow control. Multi-week effort.
- The network core must still hold TSCH + 6LoWPAN *reassembly* + MAC queues in 64 KB — tight,
  and it interacts with the very fragment-reassembly timing the current bench is studying.
- **Methodology caveat:** a bridged node's DTLS/TSCH latency would include the IPC hop and a
  different MAC/upper-layer partition than a single-SoC nRF52840 node — so the numbers would
  **not be directly comparable** to the existing nRF52840 CSMA/TSCH benches. The bridge would
  answer "can the nRF5340 do it," not give a clean apples-to-apples 2nd data point.

## 5. Recommendation
- **For the paper's 2-nRF hardware number:** a 2nd **nRF52840-DK** is the clean path —
  `hw-dtls-x509-tsch-{CLIENT,SERVER}.hex` are already built; no new platform work; comparable
  numbers. Fallback: the emulator TSCH median (3836 ms) already measured.
- **The IPC bridge is a standalone platform-engineering project**, not a test-setup step, and
  even done well it changes what's being measured. Worth it only as its own contribution
  (e.g. "porting Contiki-NG to the nRF5340 dual-core via an RCP-style split"), not to unblock
  this test.

## Build note (independent of the above)
Both nRF5340 cores build with our absolute-path ARM toolchain **iff** `LDFLAGS_WERROR=` is
passed — otherwise `-Wl,--fatal-warnings` turns Nordic's mdk RWX LOAD-segment warning fatal
(the `--no-warn-rwx-segments` auto-suppression only triggers when `CC` is the bare name
`arm-none-eabi-gcc`). Flashing a real nRF5340 node = two images: app core runs
`examples/platform-specific/nrf/start-network-core` (boots + pin-forwards to the network core),
network core runs the app; `nrfjprog --coprocessor CP_APPLICATION | CP_NETWORK`.
