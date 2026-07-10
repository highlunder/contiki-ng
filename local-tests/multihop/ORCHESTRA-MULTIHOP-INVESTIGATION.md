# Orchestra multi-hop handshake failure — investigation (task #36)

The dedicated-slot Orchestra run (MULTIHOP-DTLS-CSMA-ENROLL-RESULTS.md §D) does not complete
the handshake at 2 hops for *either* credential — even the small c5t flight fails. This is the
root-cause investigation. It is a **reproducible, narrowed-but-not-yet-pinpointed** failure;
whether it is a Contiki Orchestra bug or a cooja-ng-ge emulator artifact needs one more pass.

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

## Pinpointed (slot-level trace, 2026-07-10)
Instrumenting `tsch_queue_get_unicast_packet_for_any` (was MSG_1 selectable?) and the slot
operation (`current_link` selection for unicast-slotframe TX links) on node3 gives the exact
failure:

1. **MSG_1 is correctly queued to node2** — TSCH logs `send packet to <node2> … queue 2/8 … 8/8`
   (108 B). So it is *not* a routing/forwarding problem; the packet reaches the TSCH queue and
   the queue then fills to 8/8 because it never drains.
2. **node3's ts2 unicast-TX slot fires 88× during join (28.5–43.6 s) then STOPS at 43.648 s** and
   never fires again. 43.648 s is exactly node3's last on-air frame and coincides with the RPL
   parent / TSCH time-source being set (~network-ready at 45 s).
3. After 43.6 s the packet-selection call (`get_unicast_packet_for_any`) logs neither a SELECTED
   nor a miss for node3 — because `tsch_schedule_get_next_active_link()` **never returns the ts2
   unicast-TX link as `current_link`** anymore, even though the link is still in the schedule (the
   75 s dump shows it present).

So the root is **slot selection, not radio, routing, backoff, or link-selector**: the ts2 TX cell
stops being serviced by the slot operation the moment the Orchestra schedule is reorganised at
time-source assignment. The reorg installs the unicast RX link (`new_time_source`, at hash(own)=ts3)
**and a duplicate TX link** at ts2 (both `new_time_source→add_uc_link(parent)` *and*
`neighbor_updated→add_uc_link(parent)` add one). The strong hypothesis is that this
duplicate-link / RX-TX overlap interacts badly with `tsch_schedule_get_next_active_link`'s
`curr_best`/`curr_backup` arbitration so the ts2 TX cell is permanently shadowed by an overlapping
link after the reorg — plausibly compounded by node3's (spurious, tolerated) one-slotframe ASN
offset shifting its per-slotframe `TSCH_ASN_MOD` timeslot.

## PR assessment
A concrete, reproducible, well-localised bug: **an Orchestra-scheduled unicast TX cell stops being
selected by `tsch_schedule_get_next_active_link` after the time-source reorg, so a 2nd-tier node
can never transmit to its parent** (queue fills, handshake dies). Two follow-ups make it PR-ready:
1. Confirm the mechanism by instrumenting `tsch_schedule_get_next_active_link` (why ts2 is not
   `curr_best` after 43.6 s) and by removing the duplicate add (`neighbor_updated` vs
   `new_time_source`) to see if the ts2 cell keeps firing.
2. **Cross-check mainline Cooja / real hardware** — the minimal-schedule bug here was emulator-side
   (a spurious ASN-drift `rx_asn` artifact), so the ASN-offset angle means the exact failing line
   could still be a cooja-ng-ge slot-timing artifact rather than Contiki Orchestra. Decide the PR
   target (Contiki `os/net/mac/tsch` vs cooja-ng-ge) from that cross-check.

The instrumentation used (revert after): `DIAG_UC` in `tsch_queue_get_unicast_packet_for_any`
(SELECTED / miss-with-backoff) and a `printf` in `tsch_slot_operation` after
`get_packet_and_neighbor_for_link` gated on `current_link->slotframe_handle==1 && TX`, built with
`DEFINES=DIAG_UC,LOG_CONF_LEVEL_MAC=LOG_LEVEL_INFO`.

## Reproduce
`emul-{c5t,x5c}-{2,3}hop-orch.json`; firmware built `ORCHESTRA=1 MAKE_MAC=MAKE_MAC_TSCH`
(+ `MULTIHOP_CONNECT_DELAY_S=30` for clients), the opt-in `ORCHESTRA=1` gate in the relay + EDHOC
Makefiles. A one-shot schedule dump can be re-enabled via `-DDIAG_DUMP_SCHEDULE` (a
`tsch_schedule_print()` after the connect delay).

_Status: investigation; root cause narrowed, not pinpointed. Next: slot-level TX trace on node3 +
mainline-Cooja/HW cross-check before a PR._
