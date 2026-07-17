# Virtual multi-hop on co-located boards (TOPO_ROLE source-role filter)

Forces a **line topology** among nRF52840 boards that are all within RF range on
one desk — no attenuators, shield boxes, or physical separation. Each node runs a
fixed link address whose last byte is its line position (role), and the radio
driver drops any frame whose source role is not adjacent. Root and leaf therefore
never hear each other even when co-located, so RPL/TSCH form `root—relay—…—leaf`.

**SECURITY NOTICE: Test/bench aid only. Never ship firmware with a fixed link
address or this filter.**

## How it works (gated by `-DTOPO_ROLE=<n>`, no effect unless set)

1. `arch/cpu/nrf/sys/linkaddr-arch.c` — overrides the FICR-derived link address
   with a fixed `02:00:00:00:00:00:00:<role>` (byte 0 = 0x02 = locally
   administered; last byte = role). Deterministic, so it can be whitelisted.
2. `arch/cpu/nrf/net/nrf-ieee-driver-arch.c` `read_frame()` — parses the 802.15.4
   source, extracts the source role (last address byte), and **drops** the frame
   unless `src_role == TOPO_ROLE ± 1`. Applied in the shared radio read path, so it
   governs **both CSMA and TSCH** — including TSCH enhanced-beacon sync, which a
   network-layer filter would miss (the leaf could otherwise sync straight to the
   root). Frames without a parseable extended source (ACKs) pass.

Roles are a line: `1 = root`, `2..N-1 = relays`, `N = leaf`. Adjacency is `±1`, so
it generalises to any number of hops (1-2-3-4 …).

## Validated (cooja-ng-ge, 2026-07-17)

3 nodes **co-located** (UDGM `tx_range=200`, all in mutual range) — so distance
creates no hops; only the filter can. Result: node 3 (leaf) became reachable and
unicasts exclusively to `->0002` (relay), never to `0001` (root), even though the
emulator delivered 45 of the root's frames to node 3 over the air. node 3 joined at
30 s vs node 2's 15 s — the 2-hop-join signature. The filter, not distance, made the
line. Config: `topo-test/emul-topo-validate.json`.

## Build recipe (HW, all boards co-located)

Pass `TOPO_ROLE` via the environment CFLAGS so it reaches the arch files:
```
# root (also the RPL root + TSCH coordinator via its own app config):
env CFLAGS="-DTOPO_ROLE=1" make -C <root-app> TARGET=nrf BOARD=nrf52840/dk \
  LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH <toolchain>
# relay(s):  TOPO_ROLE=2  (add 3,4,… for more hops)
# leaf:      TOPO_ROLE=<N>
```
Flash each board with its role's firmware (2 DKs + dongles, any mix — the filter
is address-based, not board-specific). Because roles are fixed addresses, **do not
run two boards with the same TOPO_ROLE** on the same network.

The root app must actually be a coordinator/root (e.g. `edhoc-oscore-c5t-server`,
which does `tsch_set_coordinator(1)` + `root_start()`); the bare `relay` app is a
forwarder only and cannot be node 1.

## Use for the real experiments

Build any of the multihop endpoints (EDHOC c5t/x5c, DTLS, `/crts`+`/sen` enroll)
with `TOPO_ROLE` set per board and the relays in between — you get a real-RF
multi-hop handshake/enrollment on one desk, comparable to the cooja-ng multi-hop
results (`MULTIHOP-M1-RESULTS.md`, `hw-enroll/`).
