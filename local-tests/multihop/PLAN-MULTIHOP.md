# Four-node / three-hop C509 experiments — design

**Goal.** Extend the single-hop handshake/enroll results (TSCH-C509-VS-X509-LATENCY.md,
TSCH-HW-RESULTS.md) to a realistic **multi-hop** mesh: a constrained client several hops
from the server, with the far end being either another nRF **server** or a **border
router bridged to a Linux server**. The single-hop 2×2 decomposed handshake latency into
*crypto* (~700 ms, endpoint-only), *protocol base* (~264 ms), and *TSCH slotframe penalty*
(~108–175 ms). Multi-hop is where those terms diverge: **crypto is hop-independent
(endpoints only), while the airtime/slotframe term multiplies with hop count** — so the
wire-format (C509) advantage should *compound* with hops while the crypto (CC310)
advantage *dilutes*. That divergence is the headline this setup can produce.

## Topology (both variants)

A straight line, 50 m spacing, UDGM `tx_range=55` / `interference_range=110` (the
`chain-4node-nrf52840-dk.json` recipe): each node reaches only its ±1 neighbours (50 m <
55 m connect; 100 m > 55 m no connect), so RPL forms a deterministic chain. Hop count is
set purely by how many nodes are placed:

```
 1-hop:  [server/root]──[client]                         (x = 0, 50)
 2-hop:  [server/root]──[relay]──[client]                (x = 0, 50, 100)
 3-hop:  [server/root]──[relay]──[relay]──[client]       (x = 0, 50, 100, 150)
```

- **node1 = server / RPL root / TSCH coordinator** (x=0).
- **node2..N-1 = relays** (plain RPL+TSCH 6LoWPAN forwarders; `local-tests/multihop/relay`).
- **nodeN = client** (the constrained initiator; x = 50·(N−1)).

The client resolves the responder as the RPL root (`EDHOC_CONF_SERVER_FROM_ROOT`), so the
**same endpoint firmware works at any hop count** — only the config (node count/positions)
changes. The relay needs forwarding-buffer headroom (a fragmented x5c cert flight transits
each relay): `QUEUEBUF_CONF_NUM 16`, `TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16`,
`SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24` (the rxdiag lesson).

## Two endpoint variants

- **Variant A — all-nRF** (node1 = `edhoc-oscore-{c5t,c5c,x5c}-server`, root). Self-contained,
  fully in-emulator. Primary for the latency-scaling experiments.
- **Variant B — border router → Linux** (node1 = `slip-radio.cooja` native mote +
  `serial_socket` → host `tunslip6` → Linux server: `setest` or the native Contiki
  responder). The pattern already exists in `cooja-ng/configs/c509-dtls-3hop.json` /
  `c509-dtls-border-router.json`. Value: the server is unconstrained and freely
  instrumentable (its logging is off the constrained client's critical path — cf. the
  responder-logging pitfall we hit at 1 hop), and it matches the real deployment (device
  ↔ edge/cloud). This is the emulator counterpart of the hardware task #29 (Firefly/SLIP
  border router) and frees a real DK to be a PPK2 DUT.

## Experiments, by value

| # | Experiment | Configs | Why it's valuable | Where |
|---|---|---|---|---|
| **M1** | **C509-vs-X509 handshake latency vs hop count** ({c5t,c5c,x5c} × {1,2,3} hops, TSCH) | 9 (6 new) | **Headline.** x5c's ~6-fragment MSG_2 vs c5t's ~2 costs extra slots *at every hop*, so the x5c−C509 gap should grow ~linearly with hops (~3× at 3 hops). "C509's wire saving compounds over multi-hop duty-cycled meshes" — a stronger claim than the 1-hop result. | emulator (runnable now) |
| **M2** | Per-hop latency accumulation (c5t, 1/2/3 hops, TSCH **and** CSMA) | 6 | Quantifies the airtime term's hop scaling: TSCH adds ~1 slotframe/hop/message; CSMA adds little. Isolates the MAC's contribution vs hop count. The sw baseline of M1. | emulator |
| **M3** | sw-vs-CC310 vs hop count | HW (4 real nRF) | **Contrast to M1**: crypto is endpoint-only, so the CC310 advantage *dilutes* as hops add airtime (2.44× @1hop → less @3hop). Wire-format compounds, crypto dilutes — orthogonal. CC310 isn't emulated → needs 4 real nodes (node-count limited: have DK+1 dongle; needs +2). | HW |
| **M4** | Reliability/completion under loss over multi-hop (GE medium or sr<1) | 9 | Each hop is a drop opportunity; end-to-end completion falls with path length. C509's fewer fragments → fewer per-hop drops → better multi-hop completion. Extends the GE burst-loss study (cooja-ng-ge). Ties credential size to *reachability*, not just latency. | emulator (GE branch) |
| **M5** | Full enrollment (EDHOC+/crts+/sen) over 3 hops | 2 (c5t, x5c) | The longest workload → maximal compounding of the wire-size gap; the multi-hop analogue of the Tier-2 enroll result. | emulator |
| **M6** | Border-router → Linux server (Variant B), 3 hops | 2 | Deployment-realistic; unconstrained/instrumentable server; emulator counterpart of task #29. | emulator + Linux server |

**Priority: M1 first** (headline, runnable in-emulator now), then M2 (its baseline), then
M6 (the Linux-server topology the user asked for), then M3/M4/M5.

## Config plan (Variant A, TSCH)

Firmware (all on shared nrf platform, `MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1`):
- endpoints: existing `edhoc-oscore-{c5t,c5c,x5c}-{client,server}` (no change — root-resolving client).
- relay: new `local-tests/multihop/relay` (minimal RPL+TSCH forwarder, buffer headroom).

Configs (`local-tests/multihop/`), naming `emul-<cred>-<hops>hop-<mac>.json`:
- M1/M2: `emul-{c5t,c5c,x5c}-{2,3}hop-tsch.json` (1-hop = the existing `bench/emul/emul-edhoc-*-tsch.json`).
- M2 CSMA: `emul-c5t-{1,2,3}hop-csma.json`.
- Node layout: node1 server (x=0, root), node2..N−1 relay, nodeN client (x=50·(N−1)).
- `timeout_ms`: multi-hop TSCH association is sequential (each hop joins outward from the
  coordinator) + the handshake traverses N hops — budget ~400–600 s (the 1-hop join was
  ~25 s in-emul; each extra hop adds association + forwarding latency; the prior 3-hop DTLS
  hardware run settled at ~180 s, emulator is faster but leave margin).
- Validator: client `end-to-end test PASSED`; read `EDHOC finished` timestamp for latency,
  and the per-hop RF-frame timeline for the fragment×hop accounting.

## What to measure / expected shape

For M1, per (cred, hops): the handshake latency `MSG_1 gen → EDHOC finished`. Model:
`T(h) ≈ crypto + h·(base_per_hop + n_frag·T_slot)`, where `n_frag` is the per-message
fragment count (c5t ~2 / x5c ~6). The **x5c−c5t gap grows as `h·(Δn_frag)·T_slot`** —
linear in hops. Confirming that linear growth (and that CSMA shows almost no hop-scaling,
M2) is the result. HW expectation (M3): same ordering; CC310 shifts the crypto constant
down so the airtime/hop term dominates sooner.

## Progress (2026-07-09, third pass) — 2-HOP c5t HANDSHAKE PASSES over TSCH

**`emul-c5t-2hop-tsch.json` PASSES** (`Validator [PASS]: "EDHOC finished"`, node3, over TSCH).
The multi-hop handshake experiment is runnable at 2 hops. It took four fixes:
1. **Relay EB floor** — `tsch_set_eb_period(4 s)` re-asserted every 5 s once associated
   (`relay/relay.c`) → the relay beacons enough for the client to associate.
2. **Client connect-delay** — `MULTIHOP_CONNECT_DELAY_S` (build-time; 90 s) → wait for the
   path to settle before EDHOC.
3. **EDHOC timeout 60 s** — `edhoc-oscore-c5t-client` project-conf: when built multi-hop,
   `EDHOC_CONF_TIMEOUT` 10→60 s. **This was the key one:** MSG_1 forwarding over the hops
   takes >10 s (measured ~12 s at 2 hops via slow CoAP-CON forwarding — vs 0.5 s for a
   RPL DAO), so the 10 s watchdog made the client restart before the round trip finished,
   and the server never completed MSG_2 for the abandoned session.
4. **Validator = `EDHOC finished`** — M1 measures *handshake* latency; the post-handshake
   OSCORE GET is best-effort raw UDP and is unreliable over multi-hop (it retransmits and
   times out), so validate the handshake, not the GET.

Diagnosis chain that got here (all via RPL+EDHOC INFO logging): RPL routing is fine
(DAOs + DAO-ACKs round-trip over 2 hops, root has a route to the client) → MSG_1 *does*
reach the server, just ~12 s late → the client's 10 s watchdog was the culprit.

### ✅ SOLVED 2026-07-09 — multi-hop blocker was a spurious ASN-drift eviction
Both 2-hop and 3-hop c5t handshakes now **PASS** end-to-end over TSCH (`TEST PASSED`).
The chase went through several wrong hypotheses (EB-period backoff; then a supposed
"TX-only death"; Orchestra was tried and *reverted* — it did not help and broke 2-hop),
before instrumenting the TSCH per-node `tx_count`, which revealed the truth:

**Root cause:** the 2nd-tier node (whose TSCH time source is a *relay*, i.e. >=2 hops from
the coordinator) was **repeatedly disassociating and re-joining**, not dying. `tx_count`
reset to 0 every ~30–60 s (only `tsch_reset()` does that). The trigger, logged at MAC WARN:

```
! ASN drifted by 7, leaving the network
```

On every EB from its time source, the node found its ASN disagreed with the EB's stamped
ASN by **exactly 7 = one minimal-slotframe (size 7)**, and the strict 6TiSCH check
(`tsch.c` `eb_input`: `if(asn_diff != 0) tsch_disassociate()`) evicted it. It re-joined,
drifted 7 again, left again — so it never stayed up long enough for the next hop to hear a
stable EB. That is why node4 never associated (3-hop) and why 2-hop only passed when the
client happened to finish EDHOC inside one join window.

**Why it's spurious (safe to tolerate):** the node is *actually* slot-aligned and
communicating — channel hopping lines up and full EDHOC handshakes complete once the check
is relaxed. If its real ASN were 7 off, `channel = hop_seq[(ASN+choff) % hoplen]` (hoplen=4)
would put it on a different channel and nothing would get through. So the drift is in the
DETECTION (`current_input->rx_asn` vs the EB's `ie_asn` — a cycle-accurate-emulator timing
artifact of when `rx_asn` is captured), not in the node's real slot clock. node2 never
drifts because its time source is the *coordinator* (special path); only relay-sourced nodes
hit it.

**Fix (clean, gated, default-safe):** new `TSCH_LEAVE_ON_ASN_DRIFT` (tsch-conf.h, default 1
= strict/upstream). Multi-hop firmwares set `TSCH_CONF_LEAVE_ON_ASN_DRIFT 0` (relay
project-conf always; client project-conf gated on `MULTIHOP_CONNECT_DELAY_S`) so the drift
is warned-but-tolerated. Single-hop syncs to the coordinator → never drifts → unaffected.
Keep 1 on real hardware.

**Two real secondary bugs also fixed** (both were masking / compounding the above):
- `COAP_RESPONSE_TIMEOUT` was `3 s` (comment claimed 15) — far shorter than the >15 s
  multi-hop MSG_1↔MSG_2 fragmented round trip, so CoAP CONs timed out (status 3) and the
  client retransmitted into half-done handshakes. Now **25 s for multi-hop builds only**
  (client Makefile, gated); single-hop stays 3 s → byte-identical single-hop timing.
- `EDHOC_CONF_HS_DEADLINE_SEC` no-progress watchdog was 12 s (separate from
  `EDHOC_CONF_TIMEOUT`), preempting multi-hop handshakes mid-round-trip → now **55 s** for
  multi-hop builds (client project-conf, gated).

**Build recipe (multi-hop fw):** server `MAKE_MAC=MAKE_MAC_TSCH` (coordinator, no extra
flags); relay `MAKE_MAC=MAKE_MAC_TSCH`; client `MAKE_MAC=MAKE_MAC_TSCH
MULTIHOP_CONNECT_DELAY_S=30`. All `TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR=`. (Connect
delay 30 s is enough for routes to settle now that the node stays associated; 90 s is not
needed and only lengthens the run.) Measured latencies: 2-hop c5t ≈ 49 s handshake
(ready→finished, seed 1), 3-hop ≈ 85 s.

### M1 DATA — COLLECTED 2026-07-09 → see MULTIHOP-M1-RESULTS.md
Built the **x5c** multi-hop client (ported the connect-delay + 3 gated fixes onto
`edhoc-oscore-x509-client`), added 1-hop configs, and ran `emul-{c5t,x5c}-{1,2,3}hop`
(3 seeds each). Headline results:
- **1-hop (clean, stable):** c5t **1.11 s** vs x5c **1.98 s** (~1.8× — the precise latency
  comparison; tight across seeds).
- **Reliability vs hops, X.509 degrades faster:** c5t 3/3, 3/3, 2/3 across 1/2/3 hops; x5c
  3/3, 2/3, **0/3** — the big 384 B inline X.509 cert **never completes at 3 hops** (MSG_2
  flight undeliverable even with a 150 s budget), while compact C509 c5t does. That's the
  multi-hop headline for the paper: the compact credential is the difference between the
  handshake completing or not, at depth.
- Multi-hop *total* latency is noisy (CoAP-CON retransmit tails dominate: c5t-2hop 1.8–18.9 s);
  report multi-hop as a reliability+trend result, 1-hop as the precise latency.
Remaining fragility (occasional c5t 2/3-hop failures) is fragmented-message loss over the
6TiSCH minimal single shared slot. Still worth confirming ASN-drift is emulator-only on real
HW (DK + 2 dongles); the gate keeps HW strict by default.

## Progress (2026-07-09, second pass) — TSCH multi-hop JOIN fixed; delivery is a routing issue

- **TSCH EB bootstrapping — FIXED.** The relay now re-asserts a fixed EB floor
  (`tsch_set_eb_period(RELAY_EB_PERIOD=4 s)` every 5 s once associated, `relay/relay.c`),
  overriding the RPL EB-backoff. With it, a client **associates over 2 hops** (node3
  `Network ready` @40 s; was: never). This is the key multi-hop-TSCH enabler.
- **Client connect-delay — added** (`MULTIHOP_CONNECT_DELAY_S`, build-time, default 0;
  `edhoc-oscore-c5t-client` + its Makefile). Waits for routes/slots after `node_is_reachable`
  before EDHOC. Built `fw/edhoc-oscore-c5t-client-mh.nrf` (90 s); the 2/3-hop configs point
  to it.
- **Remaining blocker — multi-hop RPL route establishment (delivery).** Even with the
  90 s delay, the 2-hop c5t handshake fails: the client sends MSG_1 and times out (4 retries),
  the relay **does forward** (node2: 35 data TX frames) but no response reaches the client.
  The client (node3) sends **0 DAOs** in the trace, so the root likely has **no downward
  route** to deliver MSG_2 — the classic RPL-non-storing multi-hop issue. Both endpoints run
  at `LOG_LEVEL_ERR` (server quieted for timing), so the server side (MSG_1 receipt, MSG_2
  gen) and RPL DAO/route logs are invisible.
- **Next (task #30):** build the endpoints + relay with **RPL + EDHOC INFO logging** to
  localize (does MSG_1 reach the root? is a DAO sent/received? does the root have a route to
  the client?); then fix the downward route — likely a DAO-frequency / non-storing-source-route
  tuning, or a longer settle for DAO propagation. Mirrors the prior 3-hop-DTLS bring-up
  ([[project_3hop_dtls_test]]) which needed `CONNECT_DELAY=150 s` + CSMA retries 7. Once a
  handshake completes at 2 hops, extend to 3 and run M1/M2.

## Validation status (2026-07-09) — design proven, multi-hop delivery needs tuning

Built the relay (`relay/`, minimal RPL+TSCH forwarder + buffer headroom) and the M1
configs, and ran `emul-c5t-3hop-{tsch,csma}.json` to validate. Findings:

- **Topology + relay + endpoints boot and the chain forms.** The relays associate and
  become RPL-reachable outward from the root.
- **TSCH multi-hop JOIN blocker — EB bootstrapping.** node1 sent 55 EBs, node2 54, but
  the *deepest* relay (node3) sent only **1**, so node4 never heard an EB to associate.
  Orchestra's `eb_per_time_source` rule gives every node an EB TX slot at `init()`, so
  node3 *can* beacon, but its RPL-governed EB period (`tsch_rpl_callback_new_dio_interval`)
  effectively stops once its trickle backs off with no child to reset it — chicken-and-egg
  (won't beacon without a child, can't get a child without beaconing). Capping the DIO
  interval (`RPL_CONF_DIO_INTERVAL_DOUBLINGS=2`) did **not** fix it. **TODO:** force a
  minimum EB rate on joined relays independent of RPL/children — e.g. a non-zero floor in
  the EB-period path, a periodic `tsch_set_eb_period()`, or an EB rule that beacons on a
  fixed timer. This is the one blocker for the TSCH multi-hop experiments.
- **CSMA multi-hop JOIN works but is slow, and delivery needs tuning.** node4 joined over
  3 hops at **~195 s** (RPL convergence over 3 hops), started EDHOC, but its MSG_1 never
  reached the root (node1 generated MSG_2 zero times) within the 300 s budget — the
  upward multi-hop forwarding / route establishment isn't reliable out of the box.

**Required tuning (from the prior 3-hop DTLS bring-up, [[project_3hop_dtls_test]] — PASS
needed `CONNECT_DELAY=150 s`, `CSMA retries=7`, `POST_HANDSHAKE_SETTLE=8 s`; DTLS\@171 s):**
1. **Client connect delay** — wait for RPL to fully converge (routes both ways) before the
   first EDHOC message: add a `~120`--`150 s` settle in the client before `edhoc_client_run()`
   (or bump the bench's pre-loop wait). The 3-hop RPL convergence alone is ~195 s here.
2. **CSMA `MAX_FRAME_RETRIES` / `MAX_BE`** up (7 worked before) — multi-hop links need more
   MAC retries; also `RPL` route-repair timing.
3. **Longer handshake/timeout budgets** — `EDHOC_CONF_TIMEOUT`, `COAP_RESPONSE_TIMEOUT`,
   and the config `timeout_ms` scaled by hop count (the configs already scale 300+150·h s,
   but the *client-side* EDHOC/CoAP timeouts also need per-hop headroom).
4. **Relay/endpoint buffers** — QUEUEBUF/TSCH-queue/6LoWPAN-fragment headroom (relay has it;
   endpoints already set QUEUEBUF 16 for the cert flight).
5. **Start with 2 hops** — likely completes with less tuning; establish the pipeline there
   (`emul-c5t-2hop-*.json`), then extend to 3.

So M1--M6 are **designed and scaffolded** (topology, relay, endpoint firmware, 4 TSCH
configs + a CSMA validation config); the remaining work before they yield data is the
multi-hop **join+delivery tuning** above — a known, bounded task from the prior 3-hop
bring-up, not a design flaw. Recommended order: (a) TSCH EB-rate fix on the relay,
(b) client connect-delay + CSMA-retry tuning, (c) validate at 2 hops, (d) 3 hops, then run
M1/M2.

## Open design choices
- **Relay count vs a single multi-role node**: use dedicated minimal relays (clearest).
- **Server at root vs client at root**: server=root (client resolves root as responder);
  matches the 1-hop configs.
- **Association robustness**: multi-hop TSCH may need `RPL_MRHOF_CONF_MAX_LINK_METRIC`
  headroom (already in the endpoint project-confs) and a longer settle; relays inherit it.
- **Variant B server**: `setest` (Python, aiocoap+lakers) vs native Contiki responder on
  Linux — either behind `tunslip6` on the `serial_socket` port.
