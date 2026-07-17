# crl-fetch — E10: multi-hop revocation-object delivery (LRev Tier 2)

The revocation analogue of the LICE multi-hop headline (a 384 B X.509 certificate
that never completes a 3-hop EDHOC handshake where the compact C509 `c5t` form
does — `MULTIHOP-M1-RESULTS.md`). Here the object is a **CRL** rather than a
certificate, and the transport is a plain block-wise CoAP GET rather than a
handshake, which isolates the **size → delivery** effect: the two arms differ
*only* in how the same revocation facts are encoded.

Answers PLAN-revocation.md **E10** → contributions C4, C6, and turns the E2 size
tables (which only *imply* a distribution benefit) into a measured delivery
outcome.

## Design

| | |
|---|---|
| **Server** (node 1) | RPL root + TSCH coordinator; serves one CRL at `/crl`, block-wise, over plain CoAP. |
| **Relays** (nodes 2..N) | the shared `local-tests/multihop/relay` firmware — RPL routers, no traffic of their own. |
| **Client** (node N+1) | resolves the root, does `CRL_TRIALS` block-wise GETs, prints `[E10 trial]` / `[E10 SUMMARY]` / `E10-END`. |
| **Topology** | line, 50 m spacing, UDGM `tx_range=55` → each node reaches only its neighbours. **Lossless** — so any failure is congestion/fragmentation at depth, not radio loss. |
| **Controls** | identical resource, block size, settle time (150 s), trial count and network at both arms; only the payload encoding differs. |

No DTLS/EDHOC by design — securing the fetch is E7/E8. Deliberately keeping the
transport plain is what makes the size effect attributable.

### Both payloads are real

`gen-payloads.py` emits `crl-payload.h` from genuine, verifiable objects over the
**same revoked set** (serials 1..R, `keyCompromise`, 2-byte serials, 8-byte AKID,
ECDSA-P256/SHA-256 — the PLAN §0 constrained profile):

- **c509** — a signed C509 CRL from the `c509rev` reference impl
  (`idc509rev/c509rev/examples/crl_payload.rs`), self-verified before emission and
  byte-identical to what the on-device `c509_crl_parse()` consumes.
- **x509** — a DER X.509 CRL minted by OpenSSL from a throwaway test CA.

The client counts a trial delivered only if the reassembled bytes are
**byte-identical** to the expected object, so "ok" means the relying party could
actually have used the CRL.

### Measured sizes (real bytes, not a model)

| R | C509 CRL (B) | X.509 DER CRL (B) | ratio |
|---:|---:|---:|---:|
| 0 | 108 | 213 | 2.0× |
| 10 | 192 | 561 | 2.9× |
| 20 | 262 | 900 | 3.4× |
| 50 | 473 | 1 920 | 4.1× |
| 100 | 823 | 3 620 | 4.4× |
| 200 | 1 523 | 7 094 | 4.7× |

Fits: **C509 = 108 + 7·R**, **X.509 ≈ 213 + 34.4·R** — a ~4.9× per-entry
reduction (7 B vs 34.4 B), asymptotically ~4.7× overall. This is a *measured*
cross-check of the plan's analytic `~133+6R` / `~147+31R` model (E2): the shapes
match; our per-entry figures are slightly higher on both arms because every entry
carries a revocation **reason** (C509: +1 B fixed-width byte; X.509: a full
`CRLReason` extension), and the C509 base is smaller here thanks to the 8-byte AKID.

## Two block-size regimes

Block size is swept because it decides *which* bottleneck the object meets:

- **`CRL_BLOCK=64`** — each block fits one 6LoWPAN frame, so there is no
  fragmentation and the arms differ purely in the **number of block round-trips**
  (823 B → 13 blocks vs 3 620 B → 57 blocks). Isolates transfer cost.
- **`CRL_BLOCK=256`** — larger blocks, fewer round-trips, and per-block
  fragmentation across the mesh: the LICE regime where a datagram must survive
  reassembly at every hop, and where a delivery **cliff** is expected.

`CRL_BLOCK=1024` does **not** work: it fails for both variants, including an 823 B
C509 CRL that fits in a single block, because a 1024 B CoAP payload exceeds the
uIP/6LoWPAN buffer. That is a stack limit, not a result — cap the sweep at 256.

Both endpoints must agree on the block size — a mismatch silently truncates the
transfer (the `COAP_MAX_CHUNK_SIZE` lesson).

## Running

```
./gen-payloads.py --variant c509 --r 100 --out crl-payload.h   # or x509
make ROLE=server TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= ...
```

The driver does the whole generate → build → stage → run → parse cycle:

```
./run-e10.py --variants c509 x509 --r 100 --blocks 64 1024 --hops 1 2 3 --seeds 1 7 13
./run-e10.py --summary        # re-parse results/ as CSV, run nothing
```

Configs land in `conf/`, logs and per-cell builds in `results/`, staged firmware
in `../fw/e10-*`. Three seeds (1, 7, 13) matching the M1 methodology; a cell that
never prints `E10-END` is an **undeliverable object at that depth** — the headline
outcome, not a harness error.

Prerequisite: the multi-hop network only extends past one hop because of the
ASN-drift fix (`TSCH_CONF_LEAVE_ON_ASN_DRIFT 0`, see `PLAN-MULTIHOP.md`).

## Results

See `../MULTIHOP-E10-RESULTS.md`. **Status: 1-hop done and clean; 2/3-hop blocked**
— at depth the client joins and then goes deaf/mute within seconds (TSCH stops
scheduling slots). The blocker is bisected there; the M1 2-hop baseline still
passes, so it is specific to this app pair.

SECURITY NOTICE: Test credentials only. Never use in production.
