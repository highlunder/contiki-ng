# H2 enrollment wall-clock — hardware results log

Exp H2 (`PLAN-c509-lice-followup.md §10.2`): on-silicon `/crts`+`/sen` enrollment
wall-clock, **C509 arm vs X.509 arm**, over a real 2-node 802.15.4/TSCH link. The
on-hardware analogue of the original LICE Fig-5 operation-timing box plots.

**Metric** — the client DUT prints one block when EDHOC → `/crts` → `/sen` completes:
```
[ENROLL-TIMING fw:<id> arm:<c509|x509> ok:<0|1>] edhoc_ms=<N> crts_sen_ms=<N> total_ms=<N>
```
- `edhoc_ms` — EDHOC Method-0 `c5t` handshake (start → OSCORE ready).
- `crts_sen_ms` — the enrollment exchange (`GET /crts` + on-device CSR build/sign +
  `POST /sen` + issued-cert verify); **the arm-sensitive number**.
- `total_ms` = `edhoc_ms + crts_sen_ms`. `ok:1` = full flow succeeded.

**Firmware** (`hw-enroll/`, `FW_ID=20260719`, rebuild via `./stage-h2-enroll.sh`):

| arm | server (root/CA) hex | client (DUT) hex |
|---|---|---|
| C509 | `enroll-c509-server-dk.hex` | `enroll-c509-client-dk.hex` |
| X.509 | `enroll-x509-server-dk.hex` | `enroll-x509-client-dk.hex` |

**Setup** — server on DK-A (RPL root + CA), client on DK-B (DUT); read DK-B @115200.
Both arms share CA identity, PoP, and issuance; they differ only in the three flights'
wire encoding (C509/CBOR vs X.509 DER + PKCS#10). Record the DK serial numbers.

**Expected** (from emulation + the size tables): both `ok:1`; `edhoc_ms` ~equal across
arms; `crts_sen_ms` **larger for X.509** (CA-cert 288 B vs 133 B, issued cert 287 B vs
144 B, CSR 212 B vs 150 B — `table:enrollment-sizes`), the gap widening under loss/hops.

---

## Runs

### C509 arm
- Date / DK-A (server) SN: `____` / DK-B (client) SN: `____`
```
<paste the [ENROLL-TIMING ... arm:c509 ...] line here>
```

### X.509 arm
- Date / DK-A (server) SN: `____` / DK-B (client) SN: `____`
```
<paste the [ENROLL-TIMING ... arm:x509 ...] line here>
```

### Summary
| arm | ok | edhoc_ms | crts_sen_ms | total_ms |
|---|----|----------|-------------|----------|
| C509 |   |          |             |          |
| X.509 |  |          |             |          |
| Δ (x509−c509) | | | | |
