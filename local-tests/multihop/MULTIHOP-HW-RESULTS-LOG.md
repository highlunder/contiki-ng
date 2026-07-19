# H6 real-RF multi-hop — hardware results log

Exp H6 (`PLAN-c509-lice-followup.md §10.6`): the C509-vs-X.509 EDHOC delivery/latency
gap vs hop count, on real silicon, with the `TOPO_ROLE` filter forcing a line topology
among co-located boards. Real-RF counterpart of `table:multihop`.

**Metric** — the leaf/DUT DK prints, per run:
- **c5t arm**: `[BENCH <label> FINAL] … (ms)` (handshake wall-clock; Welford, last line
  = whole result).
- **x5c arm**: EDHOC completion or failure (the headline is *delivery* at 3 hops).

**Firmware** (`fw-hw/`, built by `./stage-h6-firmware.sh`; see `H6-FIRMWARE-STAGING.md`).
Line: root DK (role 1) — dongle relays (roles 2..N−1, DFU) — leaf DK (role N).

| hops | root (DK r1) | relays (dongle) | leaf (DK) |
|---|---|---|---|
| 1 | `*-server-r1-dk` | — | `*-leaf-r2-dk` |
| 2 | `*-server-r1-dk` | `relay-r2-dongle` | `*-leaf-r3-dk` |
| 3 | `*-server-r1-dk` | `relay-r2-dongle`, `relay-r3-dongle` | `*-leaf-r4-dk` |

Record DK/dongle serial numbers + date per row.

**Expected** (from emulation, `MULTIHOP-M1-RESULTS.md`): c5t completes at 1/2/3 hops;
**x5c/X.509 fails to deliver at 3 hops** while c5t succeeds — the multi-hop headline.

---

## Runs

### c5t arm  (root `c5t-server-r1-dk` + `c5t-leaf-r{2,3,4}-dk`)
- 1 hop — DK-serials/date `____`
```
<paste [BENCH ... FINAL] (ms)>
```
- 2 hops — `____`
```
```
- 3 hops — `____`
```
```

### x5c arm  (root `x5c-server-r1-dk` + `x5c-leaf-r{2,3,4}-dk`)
- 1 hop — `____`
```
```
- 2 hops — `____`
```
```
- 3 hops — `____`   (expect: fails to deliver)
```
```

### Summary
| arm | 1 hop | 2 hops | 3 hops |
|---|---|---|---|
| c5t (ok? / ms) |  |  |  |
| x5c (ok? / ms) |  |  |  |
