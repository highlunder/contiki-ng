# Orchestra multi-hop handshake failure — investigation (task #36)

The dedicated-slot Orchestra run (MULTIHOP-DTLS-CSMA-ENROLL-RESULTS.md §D) does not complete
the handshake at 2 hops for *either* credential — even the small c5t flight fails. This is the
root-cause investigation. **PINPOINTED 2026-07-10** to a cooja-ng-ge emulator RX-timestamp
fidelity artifact (a single anomalous ~170 ms RX-time spike halts node3's TSCH slot timer) —
**not** a Contiki Orchestra scheduling bug. Details below; the final Contiki-vs-emulator
cross-check (mainline Cooja / real HW) is the one step this sandbox cannot run.

## Symptom
Client node3 (the 2-hop leaf) **transmits nothing after ~network-ready** (last RF TX at
43.6 s; MSG_1 generated at 75 s never goes on air), so every EDHOC attempt fails with CoAP
status 3 (timeout) and restarts. Meanwhile node3 **keeps receiving** (143 frames after 45 s)
and **stays associated** — this is a TX-only death, RX alive.

## Ruled out
- **ASN-drift eviction** (the minimal-schedule cause): 0 network-leaves; `TSCH_CONF_LEAVE_ON_ASN_DRIFT`
  relax is active and working. node3 does not re-associate.
- **Missing unicast TX link**: node3's schedule (dumped just before MSG_1) *has* a unicast
  Tx|Sh link to its parent node2 at `timeslot=hash(node2)%17=2`, plus its own RX at ts3, the
  EB slotframe, and the common slot. So the link is installed.
- **Channel-offset mismatch**: node3 TX-to-node2 uses `timeslot=hash(node2)`,
  `channel_offset=hash(node2)%range` (set per-packet by `select_packet`); node2's own RX slot
  (`new_time_source`) is at the same `hash(node2)` timeslot and channel offset. Both align.
- **Real ASN divergence** (channel-hop mismatch): the minimal schedule completes handshakes
  once the drift is tolerated, which requires node3's *real* ASN to be aligned (else its
  shared-slot-0 channel would mismatch too) — so the drift detection is spurious and the real
  ASN is aligned; Orchestra's per-packet channel would also align. Not the cause.

## Additional ruled-out (2026-07-10 deep trace)
- **Duplicate unicast-TX link is NOT the cause.** The Orchestra ns rule adds the parent TX cell
  twice at ts2 (`new_time_source→add_uc_link` at 28.4 s *and* `neighbor_updated→add_uc_link` at
  32.2 s, `do_remove=0`, never removed). De-duplicating (`do_remove=1` in `add_uc_link`) did
  **not** fix the failure (node3 still 0 TX after join). The link is present throughout.
- **`get_next_active_link` selection is NOT the cause.** Instrumenting the function's return
  (`DIAG-RET`) shows it is called `<2048` times total on node3, first at 28.4 s, **never after
  ~43.6 s** — i.e. node3's whole slot engine stops; the function is not "mis-selecting", it stops
  being invoked. So the earlier "slot-selection / arbitration shadowing" hypothesis is **wrong**.
- **Adaptive drift compensation is NOT the cause.** Rebuilding all three nodes with
  `TSCH_CONF_ADAPTIVE_TIMESYNC=0` removed the `!too big compensation` log but produced a
  **byte-identical** failure: node3 emits exactly 6 RF frames (34.3–43.65 s) then halts. So the
  compensation log was a *symptom*, not the trigger.

## Pinpointed (2026-07-10) — emulator RX-timestamp spike halts node3's TSCH
Full slot-level trace (`DIAG-NS` add/remove, `DIAG-GNAL`/`DIAG-RET` in `get_next_active_link`,
plus `LOG_LEVEL_MAC=DBG`) gives the exact chain:

1. **node3 associates to node2 at 28.4 s and unicast-TX works fine** during 34–43.3 s: it sends
   seqno 118–122 to node2, each `packet sent … status 0, tx 1`, per-slot drift a normal ±1..15
   ticks (`dr 14, dr -13, dr 1, dr 13 …`).
2. **At 43.65 s node3 receives one anomalous frame from node2** (`uc-1-0 rx LL-0002->LL-0003
   seq 7`) whose reported drift is **`dr -10642`** — ~700× every other slot's drift and ~170 ms
   of timing error (`!dl-miss RxBeforeAck 10560 173`, then `!too big compensation 3338 delta
   -120272`). A 170 ms offset is **physically impossible** at 10 ms slots (17 slots of error) on
   a real radio; it is an emulator RX-timestamp artifact.
3. **That single spike corrupts node3's TSCH synchronization and its slot timer never re-arms**:
   after 43.652 s node3 emits **0** RF frames for the remaining 556 s, `get_next_active_link` is
   never called again, and every enqueued packet (DIS 45.9 s, keep-alive 55.4 s, **EDHOC MSG_1
   75.2 s**) sits in the queue (fills 8/8) and never goes on air. The application still runs and
   reports "Network ready", so it keeps generating MSG_1 → all attempts CoAP-timeout (status 3).

So the root cause is **a cooja-ng-ge RX-timestamp/ASN fidelity spike** (same class as the
minimal-schedule "spurious rx_asn" artifact), surfacing under Orchestra because its extra
slotframes/time-source ACK traffic hit the bad sample. The unicast link is correctly scheduled;
node3 simply loses TSCH sync at the spike and does not recover. **Not a Contiki Orchestra bug.**

## PR assessment
**No Contiki `os/net/mac/tsch` PR is warranted.** The three plausible Contiki-side culprits were
each tested and disproved (duplicate-link dedupe, `get_next_active_link` selection, adaptive-
timesync). The failure is a single anomalous RX-timestamp sample (`dr -10642`, ~170 ms) delivered
by the **cooja-ng-ge** radio/timing layer, which is physically impossible on a real 10 ms-slot
radio and corrupts node3's TSCH sync. The correct PR target is therefore **cooja-ng-ge**
(RX-timestamp / ASN fidelity), matching the earlier minimal-schedule "spurious rx_asn" finding —
the same emulator artifact, one layer down.

Remaining step (needs infra this sandbox lacks): **cross-check on mainline Cooja / real hardware.**
Expectation: with faithful RX timestamps the spike does not occur and the Orchestra 2-hop c5t/x5c
handshakes complete (as the CSMA and default-TSCH multi-hop runs already do). If a real DK pair
reproduces the halt, escalate; otherwise it is confirmed emulator-only and does not affect the
paper's on-HW claims.

The instrumentation used (all reverted): in `tsch_schedule_get_next_active_link` a `DIAG-GNAL`
(per-candidate handle-1 TX link) + `DIAG-RET` (function return / call count) `printf`; in
`orchestra-rule-unicast-per-neighbor-rpl-ns.c` `DIAG-NS` add/remove/init `printf`; built
`DEFINES=DIAG_UC[,LOG_CONF_LEVEL_MAC=LOG_LEVEL_DBG]`. The decisive log line is
`{… link 1 17 … ch 20} uc-1-0 rx LL-0002->LL-0003, … dr -10642` at 43.65 s vs `±1..15` everywhere
else.

## Reproduce
`emul-{c5t,x5c}-{2,3}hop-orch.json`; firmware built `ORCHESTRA=1 MAKE_MAC=MAKE_MAC_TSCH`
(+ `MULTIHOP_CONNECT_DELAY_S=30` for clients), the opt-in `ORCHESTRA=1` gate in the relay + EDHOC
Makefiles. To re-observe the spike: rebuild the client with `DEFINES=…,LOG_CONF_LEVEL_MAC=LOG_LEVEL_DBG`
and grep node3 for `dr -` — one value is ~700× the rest, at node3's last on-air instant (~43.6 s).

_Status: **PINPOINTED (emulator RX-timestamp artifact), 2026-07-10.** Contiki-side hypotheses
disproved; PR target = cooja-ng-ge pending mainline-Cooja/HW cross-check._
