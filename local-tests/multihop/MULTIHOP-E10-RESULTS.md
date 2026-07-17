# E10 — Multi-hop revocation-object delivery (C509 CRL vs X.509 DER CRL)

Status **PARTIAL, 2026-07-17**: the harness, the payloads and the **1-hop** arm are
done and clean; the **2/3-hop** arm — the actual headline — is **blocked** by a TSCH
issue described in §4. Numbers below are emulator (cooja-ng-ge, cycle-accurate
nRF52840), software crypto, `fw:20260717`.

Experiment definition: `paper_space/LRev-followup/PLAN-revocation.md` §E10.
Harness: `local-tests/multihop/crl-fetch/` (see its README for the design).

## 1. Payload sizes — real bytes, both arms (a measured E2 cross-check)

Same revoked set (serials 1..R, `keyCompromise`), same constrained profile
(ECDSA-P256/SHA-256, 2-byte serials, 8-byte AKID). C509 from the `c509rev`
reference impl (self-verified); X.509 DER minted by OpenSSL from a fixed test CA.

| R | C509 CRL (B) | X.509 DER CRL (B) | ratio |
|---:|---:|---:|---:|
| 0 | 108 | 213 | 2.0× |
| 10 | 192 | 561 | 2.9× |
| 20 | 262 | 900 | 3.4× |
| 50 | 473 | 1 920 | 4.1× |
| 100 | 823 | 3 620 | 4.4× |
| 200 | 1 523 | 7 094 | 4.7× |

Fits: **C509 = 108 + 7·R**; **X.509 ≈ 213 + 34.4·R**. Per-entry **7 B vs 34.4 B ≈
4.9× reduction**; overall ratio → ~4.7× and still climbing at R=200.

**This is E2's model measured rather than assumed.** The plan's analytic anchors
(`~133+6R` C509, `~147+31R` X.509) have the right shape; the real bytes differ
slightly because (a) every entry here carries a revocation *reason* (C509: +1 B in
the fixed-width entry; X.509: a whole `CRLReason` extension — which is most of why
the X.509 per-entry cost is 34.4 B rather than 31 B), and (b) the C509 base is
smaller than the anchor because of the 8-byte AKID. The headline "C509 CRL is
~1/5 of the DER X.509 CRL, and binary-searchable" survives contact with real
encoders.

## 2. Delivery — 1 hop (3 seeds: 1, 7, 13; 3 trials each; R=100)

Every trial verified **byte-exact** against the expected object, so "ok" means the
CRL was genuinely usable, not merely that bytes arrived.

| variant | bytes | block | blocks | delivered | latency (mean of 3 seeds) |
|---|---:|---:|---:|:---:|---:|
| C509 | 823 | 64 | 13 | **9/9** | **1.79 s** (1.76 / 1.84 / 1.76) |
| X.509 | 3 619 | 64 | 57 | **9/9** | **8.01 s** (8.01 / 8.00 / 8.03) |
| C509 | 823 | 256 | 4 | 3/3 | **0.94 s** |
| X.509 | 3 620 | 256 | 15 | 3/3 | **4.00 s** |

**Finding.** At one hop both objects are deliverable, and the size ratio converts
almost linearly into **block count and wall-clock**: at a 64 B block the X.509 CRL
needs **57 block round-trips vs 13** (4.4×) and takes **8.01 s vs 1.79 s** (4.5×);
at 256 B, **15 vs 4** blocks and **4.00 s vs 0.94 s** (4.3×). Tight across seeds
(σ ≈ 30 ms), so this is a precise, quotable comparison — the revocation analogue
of the LICE 1-hop latency result (c5t 1.11 s vs x5c 1.98 s).

The interpretation to pair with E4: **fetching** the CRL costs seconds and scales
with encoded size, while **consuming** it costs tens of µs plus one ~110 ms verify
(E4). Distribution dominates, and it is the axis C509 improves.

## 3. Block size

`CRL_BLOCK=1024` fails for **both** variants — including the 823 B C509 CRL, which
is a single block. That is a harness/stack limit (a 1024 B CoAP payload exceeds the
uIP/6LoWPAN buffer), **not** a result; use ≤ 256. The intended "fragmented" regime
should therefore be explored at 256 (which works) rather than 1024.

## 4. BLOCKER — 2/3 hops (the headline is not yet measured)

At ≥2 hops the client **associates, joins the DODAG, sends its DAO, becomes
reachable — and then goes both deaf and mute within a few seconds** (last TX
consistently ~43 s; deterministic). It is not a crash: the emulator reports the
core idling in `platform_idle` with no scheduled wakeup, i.e. TSCH stopped
scheduling slots, while the app keeps running and enqueuing. Packets then pile up
until the global queuebuf pool is exhausted (`queue 2/8 8/8`), so not a single CoAP
request is ever transmitted.

What has been established (each by direct experiment, not inference):

- **Not the emulator or the tree**: the M1 `emul-c5t-2hop-tsch` baseline still
  passes here (EDHOC finished at 86 s).
- **Not the relay, and not EB starvation**: the relay associates, is reachable, and
  keeps beaconing at the same ~4 s cadence in both the passing and failing runs.
- **Not my client**: my client + the **M1 server** at 2 hops stays alive (still
  transmitting at 191 s, DAG joined at 40 s).
- **It follows the server**: the **M1 client** + **my server** also dies (38 s).
- **Not the server's project-conf**: reproduced with no `project-conf.h` at all,
  and with the root's RPL/TSCH knobs removed.
- **Not the process lifetime**: reproduced with the server process kept alive.
- **Not the CoAP block size**: reproduced at 64 and 256.
- A root built **without** the CoAP module leaves the client alive — but that
  comparison is not clean, because against a CoAP-less root the client never gets a
  response and simply idles, so "alive" there may only mean "never did anything".

So the fault is somewhere in *"the RPL root also serves CoAP"* × *"the client's TSCH
time source is a relay"*. Note the working M1 server also serves CoAP, so it is an
interaction rather than CoAP as such. Next candidates: compare the RPL DAG
Configuration advertised by the two roots; instrument `tsch_slot_operation`
rescheduling on the client at the moment it stops; check for a missed-rtimer
(slot set in the past) hang.

Bugs already found and fixed while getting this far (all were harness faults, and
**every "undelivered" result they produced was discarded**, not reported):

1. The apps silently defaulted to **CSMA**; the shared relay is TSCH, so nothing
   could associate. All multi-hop firmware needs `MAKE_MAC=MAKE_MAC_TSCH`. This hid
   because a 1-hop CSMA-only run still passes.
2. `QUEUEBUF_CONF_NUM 16` with an equal per-neighbour bound (copied from the relay)
   let one neighbour take every queuebuf and wedged the node.
3. `RPL_CONF_DIO_INTERVAL_DOUBLINGS 2` (also a relay-only knob) made an endpoint
   emit multicast DIOs faster than TSCH's shared broadcast slot could drain them,
   consuming the whole queuebuf pool.
4. `LPM_CONF_MAX_PM` is inert on the shared `nrf` platform (it belongs to the
   deprecated `nrf52840` tree) — removed rather than left implying a control we
   don't have.

## 5. Reproduce

```
cd local-tests/multihop/crl-fetch
./run-e10.py --variants c509 x509 --r 100 --blocks 64 256 --hops 1 --seeds 1 7 13
./run-e10.py --summary          # CSV
```

SECURITY NOTICE: Test credentials only. Never use in production.
