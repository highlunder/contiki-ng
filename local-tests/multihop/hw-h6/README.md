# H6a — real-RF multi-hop EDHOC (c5t vs x5c) via the TOPO_ROLE filter

The LICE-plan §10.6 H6 headline on real silicon: reproduce the cooja-ng finding
that a C509 `c5t` handshake completes at every hop count while the full-cert X.509
`x5c` fails at 3 hops (`MULTIHOP-M1-RESULTS.md`) — **with all boards co-located**,
using the `TOPO_ROLE` source-role filter (`../TOPO-FILTER-README.md`) instead of
physical separation.

**SECURITY NOTICE: Test credentials only. Never use in production.**

## Validated in the emulator (2026-07-17)

EDHOC c5t over a filter-forced **3-hop line, all 4 nodes co-located** (UDGM
`tx_range=200`, mutual range): node 4 received DIOs **only from `fe80::3`** (never
node 1/2), reached **rank 646 (3 hops)**, and **`EDHOC finished`** at 104 s. The
filter, not distance, made the line. Config `emul/emul-h6a-c5t-3hop.json`.

## Firmware (staged, TSCH, `-DTOPO_ROLE` per role)

3-hop line: **root(1) — relay(2) — relay(3) — leaf(4)**.

| hex | board | role | app |
|---|---|---|---|
| `h6-root-c5t.hex` | DK | 1 | `edhoc-oscore-c5t-server` (root+coordinator) |
| `h6-root-x5c.hex` | DK | 1 | `edhoc-oscore-x509-server` (x5c arm) |
| `h6-relay-r2-dongle.hex` | dongle | 2 | `relay` |
| `h6-relay-r3-dongle.hex` | dongle | 3 | `relay` |
| `h6-leaf-c5t-r4.hex` | DK | 4 | `edhoc-oscore-c5t-client` (DUT, `MULTIHOP_CONNECT_DELAY_S=30`) |
| `h6-leaf-x5c-r4.hex` | DK | 4 | `edhoc-oscore-x509-client` (DUT) |

Roles are a line; adjacency ±1. Latency is read from host serial timestamps on the
leaf (`message_1 generation` → `Client has finished`), as in M1.

## Run (3-hop c5t arm)

Nodes: root DK (SN 683609980), 2 relay dongles (DFU), leaf DK (2nd DK — read its
serial). All within RF range is fine.

```
# root DK:
nrfutil device program … --serial-number 683609980 --firmware h6-root-c5t.hex
# relays (dongles, DFU — generate the zip in WSL, see hw-enroll or the nrf dongle note):
nrfutil nrf5sdk-tools pkg generate --hw-version 52 --sd-req 0x00 --application h6-relay-r2-dongle.hex --application-version 1 dfu/relay-r2.zip
nrfutil nrf5sdk-tools dfu usb-serial -pkg dfu/relay-r2.zip -p /dev/ttyACM0   # dongle A
#   … repeat for h6-relay-r3-dongle.hex on dongle B
# leaf (2nd DK):
nrfutil device program … --serial-number <DK2_SN> --firmware h6-leaf-c5t-r4.hex
# read the leaf:
timeout 400 python3 ../../bench/ts-serial.py /dev/ttyACM1 115200
```
Watch for `EDHOC finished` / `Client has finished`; the host-timestamp delta from
`message_1 generation` is the 3-hop c5t latency. Then swap root+leaf to the `x5c`
hexes for the comparison arm — expect x5c to **fail** at 3 hops (the headline).

## Fewer / more hops

Roles are the line position, so rebuild the leaf (and add/remove relays) for other
hop counts:
```
# 1-hop: root(1) + leaf(2). 2-hop: root(1)+relay(2)+leaf(3). N-hop: leaf role = N.
env CFLAGS="-DTOPO_ROLE=<N>" make -C .../edhoc-oscore-c5t-client TARGET=nrf \
  BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MULTIHOP_CONNECT_DELAY_S=30 <toolchain>
```
Relays occupy roles 2..N−1. Never two boards with the same role.

Reproduce the staged set with `build_h6.sh` (in the session scratch; the recipe is
above). Rebuild via `env CFLAGS="-DTOPO_ROLE=<role>"` per board.
