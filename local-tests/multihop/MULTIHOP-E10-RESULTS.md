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

**Re-characterised 2026-07-18** (correct emulator, committed config, verbose serial).
The earlier "last TX ~43 s / *it follows the server*" notes below the line were from
an older tuning and **do not describe the committed config** — they are kept struck
through for provenance but superseded by the reproduced mechanism here.

### 4a. The reproduced mechanism (`emul-e10-c509-r100-b64-2hop-s1`, seed 1)

Run in **cooja-ng-ge** (`build/test_runner`, the emulator `run-e10.py` uses; plain
`cooja-ng` mis-maps the bare-`.nrf` relay to an MSP430 core — a real bug in *that*
build's extension dispatch, but not the E10 path). Timeline, from the node-3 serial:

- associates ~17 s, joins the DODAG, becomes reachable ~45 s; **its uplink TX dies at
  ~43 s** and never recovers (see 4a-bis for the exact instant);
- the app only starts fetching at ~195 s, so the *first visible* symptom is the global
  queuebuf pinning **8/8** at **224 s** (`queue 2/8 8/8`) and staying there for the rest
  of the run — but that is just when the fetch load exposes an uplink that has been dead
  since 43 s, not a fresh 224 s failure;
- the client keeps *running* (app etimer fires, seqno climbs 156→174, printing failed
  enqueues at 698 s) but executes only **147 M instructions vs 1230 M** on the other
  two nodes — i.e. its **TSCH MAC stopped scheduling slots**, while the RTC-driven app
  layer keeps ticking. Not a crash; a MAC stall.
- **The server and relay are demonstrably healthy the whole run**: node 1 prints
  `reachable=1` every 30 s to 690 s and never sees a GET; node 2 logs **zero** errors
  and beacons to Beacon #205 / `reachable=1` at 700 s. **Only the client is sick.**

### 4a-bis. Pinpointed — the same cooja-ng-ge RX-timestamp spike as the Orchestra failure

Rebuilding the client with `MAC_DBG=1` (TSCH MAC at DEBUG, per-slot drift logged) gives
the exact trigger — **identical to `ORCHESTRA-MULTIHOP-INVESTIGATION.md` (task #36)**:

- node3's last **successful** TX (`status 0`) is at **42.618 s** (seqno 153 → parent
  `…0002`); 7 sends total, all before 42.7 s;
- at **43.034 s** node3 receives one anomalous frame with **`dr -4376`** (vs `±10–15`
  every other slot — ~300× normal), preceded by **`!dl-miss RxBeforeAck 4294 173`** —
  the same **`173`** (~170 ms) marker as task #36's `dr -10642` / `RxBeforeAck 10560 173`.
  A ~170 ms offset is **physically impossible** at 10 ms slots on a real radio;
- after that spike node3 emits **0** successful TX for the rest of the run. TX-only death;
  RX stays alive. The queue then fills and the app times out.

So E10's minimal-schedule 2-hop failure and the Orchestra 2-hop handshake failure
(task #36) are **one and the same cooja-ng-ge RX-timestamp / ASN fidelity artifact** —
a single impossible ~170 ms RX-drift sample that halts the 2-hop leaf's TSCH sync,
**independent of schedule (minimal *and* Orchestra) and of credential (c5t, x5c, and this
CoAP GET), and it hits both arms identically** — which is why 1 hop delivers and ≥2 does
not. It is **not** a Contiki, C509, or app defect (task #36 disproved the three
Contiki-side hypotheses); the fix target is the emulator, and the decisive cross-check is
**real hardware** (the staged `hw-h6` multi-hop run on physical DKs), where faithful RX
timestamps should not produce the spike.

### 4b. Ruled out by direct experiment (this pass)

- **Not hidden-terminal / RF collision.** node1(x=0)↔node3(x=100) are 100 m apart —
  outside tx_range (55) but inside interference_range (110), a textbook hidden
  terminal. Re-running with `interference_range=55` (removes the collision, keeps the
  2-hop line) is **bit-identical**: same jam, same seqno 156→174, same **147,103,234**
  client instructions. Interference plays **no** role.
- **Not the relay, not EB starvation, not the server** (see 4a: both stay healthy).
- **Not a Contiki MAC/schedule bug.** The M1 `emul-c5t-2hop-tsch` EDHOC baseline passes
  here (it completes before ~43 s of sustained uplink and so misses the bad sample),
  and task #36 disproved the three Contiki-side Orchestra hypotheses (duplicate-link
  dedupe, `get_next_active_link` selection, adaptive-timesync). The trigger is a single
  emulator-delivered RX sample (4a-bis), not stack logic.
- **Not schedule-specific** (answers the Orchestra question): the *identical* spike halts
  the leaf under **both** the 6TiSCH minimal single-shared-slot schedule (this experiment)
  **and** Orchestra's dedicated cells (task #36). Leaving the minimal schedule does **not**
  recover the ≥2-hop headline in the emulator, because the fault is below the scheduler.

### 4c. Status — pinpointed to the emulator; the open step is the HW cross-check

The mechanism is no longer open: it is the cooja-ng-ge RX-timestamp / ASN fidelity spike
of 4a-bis (`dr -4376`, ~170 ms, at 43 s), the same class as the minimal-schedule
"spurious rx_asn" artifact and task #36's Orchestra `dr -10642`. The one remaining step
needs infrastructure this sandbox lacks: **re-run the 2-hop line on real hardware** (the
staged `hw-h6` DK/dongle set) — with faithful RX timestamps the impossible ~170 ms sample
should not occur, and the ≥2-hop C509 CRL fetch should complete (with X.509 failing first
at the deeper hop counts, as its 57-block transfer already does one hop out — the actual
headline). Until then the ≥2-hop **emulator** delivery numbers are not measurable and are
**not reported**. The 1-hop headline (§2) and the size cross-check (§1) stand on their own
and do not depend on this.

<details><summary>Superseded (older tuning, retained for provenance)</summary>

> At ≥2 hops the client associates, joins, sends its DAO, becomes reachable — and then
> goes both deaf and mute within a few seconds (last TX ~43 s). Established then:
> *not* the emulator/tree (M1 passes), *not* the relay/EB starvation, my client + M1
> server stays alive (191 s), M1 client + my server dies (38 s) → "it follows the
> server", not the server project-conf, not process lifetime, not block size. That
> "follows the server" reading is **not reproduced** in the committed config (§4a: the
> server is healthy and the client is the one that stalls).

</details>

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

Run everything in **cooja-ng-ge** (`run-e10.py` already points there): plain `cooja-ng`
mis-maps the bare-`.nrf` relay to an MSP430 core (its extension dispatch has no `.nrf`
case), so the relay never runs as ARM — a bug in that build only.

To re-observe the 43 s RX-timestamp spike (§4a-bis): rebuild the client with `MAC_DBG=1`
(raises the TSCH MAC log to DEBUG), run a 2-hop config, and grep node 3 for `dr -` — one
value is ~300× the rest (`dr -4376`), at its last on-air instant (~43 s), preceded by
`!dl-miss RxBeforeAck … 173`. Cross-ref `ORCHESTRA-MULTIHOP-INVESTIGATION.md` (same
artifact under Orchestra, `dr -10642`).

SECURITY NOTICE: Test credentials only. Never use in production.
