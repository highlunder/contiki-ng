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

## Narrowed suspect
The failure is in the **shared unicast TX slot firing**. Orchestra's ns rule installs the
unicast TX link with `address = tsch_broadcast_address (ffff)` and `LINK_OPTION_SHARED`
(`orchestra-rule-unicast-per-neighbor-rpl-ns.c:82`), relying on `select_packet` + the queued
packet's `PACKETBUF_ATTR_TSCH_{SLOTFRAME,TIMESLOT}` attributes (`TSCH_WITH_LINK_SELECTOR`) to
route the packet to the right cell. At node3's ts2 slot, the slot operation must pick MSG_1
(queued to node2) via `tsch_queue_get_unicast_packet_for_any()` under the link-selector match.
That selection/transmission is what does not happen. Candidate causes to trace next:
1. The link-selector match (`tsch_queue_get_packet_for_nbr` slotframe/timeslot check) rejecting
   the packet (attr mismatch — e.g. select_packet not tagging, or a slotframe-handle mismatch).
2. A stuck shared-link backoff on the unicast neighbour (the same class as the minimal-schedule
   n_eb backoff, but for the unicast queue — the backoff decrement keys on `link->addr=ffff`).
3. A cooja-ng-ge issue handling the Orchestra unicast cell (address ffff + link-selector +
   per-packet channel offset) for the 2nd-tier node — the parallel to the ASN-drift, which was
   an emulator rx_asn-timestamp artifact, makes the emulator side worth checking first.

## Anomaly noticed
node3 has **two identical** `Tx|Sh ts2 cho0` unicast links: `new_time_source` adds a TX link to
the time source (`add_uc_link(new_addr)`) *and* `neighbor_updated` adds a TX link to node2 as a
routing neighbour — both to the same cell. Harmless (redundant), but it confirms both install
paths fire, and is worth noting for anyone auditing the rule.

## PR assessment
Not yet a clean PR: it is a solid, reproducible characterization with the suspect narrowed to
the shared unicast-TX-slot packet selection, but the exact failing line needs a slot-level trace
(instrument `tsch_queue_get_unicast_packet_for_any` / the ts2 slot's `get_packet_and_neighbor_for_link`
+ backoff state on node3) and a **cross-check against mainline Cooja or real hardware** to decide
Contiki-Orchestra vs cooja-ng-ge. Given the minimal-schedule bug here was emulator-side (the
spurious ASN drift), check the emulator's Orchestra unicast/link-selector/channel path first.

## Reproduce
`emul-{c5t,x5c}-{2,3}hop-orch.json`; firmware built `ORCHESTRA=1 MAKE_MAC=MAKE_MAC_TSCH`
(+ `MULTIHOP_CONNECT_DELAY_S=30` for clients), the opt-in `ORCHESTRA=1` gate in the relay + EDHOC
Makefiles. A one-shot schedule dump can be re-enabled via `-DDIAG_DUMP_SCHEDULE` (a
`tsch_schedule_print()` after the connect delay).

_Status: investigation; root cause narrowed, not pinpointed. Next: slot-level TX trace on node3 +
mainline-Cooja/HW cross-check before a PR._
