# C509 vs X.509 handshake latency over TSCH (in-emulator)

**Purpose.** Quantify how the compact C509 credential encoding affects the *handshake
latency* of a security handshake running over duty-cycled **TSCH** (Orchestra schedule),
versus conventional X.509 — the "C509 shrinks the flight → fewer 6LoWPAN fragments →
lower latency under a slotted MAC" result for the paper. All runs are on the **same**
cooja-ng-ge emulator build (`feat/gilbert-elliott-medium` + upstream `443c1f6`), 2 nodes,
UDGM **lossless**, shared-nrf-platform firmware (`TARGET=nrf BOARD=nrf52840/dk`,
`MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1`).

**SECURITY NOTICE: Test credentials only. Never use in production.**

---

## Part A — DTLS (cert-mode) : X.509 vs native C509 Type-2

Apps: `tests/21-security-protocols/{x509,c509}-native-dtls-{client,server}` (shared nrf,
TSCH+Orchestra). Server = node 1 = RPL root + TSCH coordinator; client = node 2.
Configs: `bench/emul/emul-dtls-{x509,c509}-tsch.json`.

| Metric | X.509 | C509 (native Type-2) | Δ |
|---|---|---|---|
| Client connect (sim time) | 30.253 s | 30.250 s | — |
| DTLS handshake-1 complete | 34.344 s | 34.297 s | — |
| **Pure handshake latency** | **4.091 s** | **4.047 s** | **−44 ms (≈1 %)** |
| Server Certificate flight | **756 B** | **675 B** | **−81 B (≈11 %)** |
| Reconstructed own-cert DER | (native DER) | 281 B | — |

_(nrfx v3.12.1; the nrfx 2.10.0 pass gave 4.099 / 4.054 s — DTLS is stable to <10 ms.)_

**Finding (important, and a little counter-intuitive):** for **DTLS**, C509 does **not**
meaningfully reduce handshake latency under TSCH. Reason: the Contiki C509 DTLS path is a
*storage/provisioning* compression — `mbedtls-support.c` reconstructs the C509 back to
**X.509 DER** (`x509_encode_full_cert`) and hands that DER to Mbed TLS via
`mbedtls_ssl_conf_own_cert`, so **the DTLS Certificate message on the wire is DER**, not
compact C509. The 11 % flight reduction we do see (675 vs 756 B) is only because the
C509-derived DER is a *minimal* cert (281 B) versus the conventionally-encoded X.509 DER;
both still span a similar number of fragments within one Orchestra slotframe, so the
latency is within noise (both ≈4 s, dominated by the fixed ~4 s connect→complete cost:
TSCH association + slotframe-quantised round trips + the 9 s DTLS retransmit granularity).

**Takeaway:** the C509 *wire* win — and hence the TSCH *latency* win — lives in **EDHOC**,
where the credential (c5c = cert by value) or just its thumbprint (c5t) is carried
in-band in the EDHOC messages. DTLS with Mbed TLS always emits DER. See Part B.

---

## Part B — EDHOC+OSCORE : X.509 (x5c) vs C509-by-value (c5c) vs C509-thumbprint (c5t)

**This is the headline result: for EDHOC, the credential is carried *in-band*, so the
compact C509 encoding directly shrinks the handshake messages → fewer 6LoWPAN fragments
→ lower handshake latency under TSCH.** (Unlike DTLS in Part A, where Mbed TLS always
emits DER on the wire.)

Apps: `tests/21-security-protocols/edhoc-oscore-{x509,c5c,c5t}-{client,server}` (EDHOC
Method 0, sw uECC P-256, shared nrf, TSCH+Orchestra). Server = node 2 = RPL root + TSCH
coordinator; client = node 1. Configs: `bench/emul/emul-edhoc-{x509,c5c,c5t}-tsch.json`.

**Controls (identical across all three variants):** client "Network ready" at **25.611 s**;
MSG_1 generated at **25.69 s**; same ECDH/ECDSA crypto path (credential form does not
change the number of P-256 ops). So the *only* thing that varies is the size of the
credential-bearing messages MSG_2 (responder cred) and MSG_3 (initiator cred) — and hence
their fragment count and TSCH airtime.

| Variant | ID_CRED form | MSG_1 | MSG_2 | MSG_3 | MSG_2+3 | **Handshake latency**¹ (nrfx 3.12.1) | (nrfx 2.10.0) | vs x5c |
|---|---|---|---|---|---|---|---|---|
| **c5t** | C509 cert **hash** (by ref) | 38 B | **114 B** | **90 B** | 204 B | **1.37 s** | 1.09 s | −34 % |
| **c5c** | C509 cert (by value, ~160 B) | 38 B | **267 B** | **242 B** | 509 B | **1.30 s** | 1.30 s | −37 % |
| **x5c** | X.509 cert (by value) | 38 B | **492 B** | **468 B** | 960 B | **2.07 s** | 1.93 s | — |

¹ MSG_1 generation → "EDHOC finished" (client). Two nrfx columns: see the alignment note.

**Finding (robust part).** The **X.509-by-value handshake (x5c, 960 B of credential) is
markedly slower than either C509 variant** — ~2.0 s vs ~1.3 s, a **~35 % reduction** — and
this holds across both nrfx driver versions we measured. x5c's MSG_2 is ~6 6LoWPAN
fragments vs ~2 for c5t, and under Orchestra each extra fragment waits for its unicast
slot in the next slotframe, so the ~4–8 extra fragments turn into ~0.7 s. This is the
compression → fragment-count → latency chain that a slotted MAC makes visible and the
sub-second CSMA runs hide.

**Finding (resolution caveat — important).** The **c5t-vs-c5c difference is NOT robustly
resolvable** at this slotframe scale. Their credential-message gap (204 vs 509 B ≈ 1–2
extra fragments ≈ a couple of ~70–140 ms Orchestra slotframes) is comparable to the
slot-*alignment* jitter, and the ordering actually **flipped** between the two nrfx driver
versions (2.10.0: c5t 1.09 « c5c 1.30; 3.12.1: c5c 1.30 < c5t 1.37) with byte-identical
messages. So the honest statement is: **c5t ≈ c5c ≈ 1.3 s** (both « x5c), and resolving
c5t below c5c would need either a longer slotframe (bigger per-fragment step) or a
multi-seed mean±spread. The earlier "monotonic c5t « c5c « x5c, −44 %/−33 %" was
single-seed/single-nrfx and over-stated the c5t/c5c separation; the size *ordering*
(204 « 509 « 960 B) is of course exact, but only the C509-vs-X.509 step exceeds the
measurement resolution.

**Why two nrfx columns.** The absolute latency depends on the nrfx radio/timer driver
version (it perturbs slot phase). The tree is now canonically **nrfx v3.12.1** (pulled in
by the upstream merge); v2.10.0 is what the first pass used. DTLS (Part A) is unaffected
by this to <10 ms; only the fine sub-slotframe EDHOC differences move.

**Caveat.** c5t assumes the peer certificate is **pre-provisioned** at the verifier (only
the hash travels); c5c/x5c are self-contained (cert travels in-band). So c5t's extra win
over c5c is a *provisioning-model* trade-off, not free.

**Why EDHOC latency (~1–2 s) < DTLS latency (~4 s, Part A):** EDHOC is a 3-message /
1.5-round-trip protocol; DTLS-over-CoAPS runs more flights and is additionally paced by
its 9 s retransmit granularity. The two parts are not directly comparable in absolute
terms — the point of Part B is the *within-EDHOC* c5t/c5c/x5c ordering.

### Fragment-count / airtime note (HW expectation)
6LoWPAN over 802.15.4 carries ≈80–90 B of payload per fragment after headers, so MSG_2
spans ≈ 2 (c5t) / 3–4 (c5c) / 6 (x5c) fragments and MSG_3 similarly. Under Orchestra the
root↔leaf unicast link gets ≈1 Tx slot per 7-slot slotframe (~70 ms), so each extra
fragment adds ~one slotframe of latency. **HW expectation:** the *ordering and the
approximate per-fragment step* carry over to real nRF52840-DK / Firefly unchanged (the
Orchestra schedule is firmware-defined and identical); absolute latency tracks the
configured slotframe length and real link quality (retries on a lossy link amplify the
gap, since a lost fragment waits a whole slotframe — see the GE burst-loss note).

---

## Part C — Radio duty cycle (idle listening): CSMA always-on vs TSCH

The latency parts above are only half the duty-cycled-MAC story; the other half is
the *idle-listening* energy the paper's byte-proxy model omits. Measured firmware-side
(the emulator's energest plugin models the CC2420 only, so it can't report the nRF radio
duty cycle) with the `simple-energest` service on a minimal 2-node network (root +
idling leaf), reading the **leaf's** Radio-Rx dwell over 20 s periods. App:
`local-tests/energest/energest-node.c` (built `ROOT=1` vs leaf, TSCH vs CSMA); configs
`emul-energest-{tsch,csma}.json`.

| MAC | Leaf Radio-Rx duty cycle | vs CSMA |
|---|---|---|
| **CSMA (always-on)** | **99.99 %** (1,249,999 / 1,250,000 ticks per 20 s) | 1× |
| **TSCH (Orchestra, default slotframe)** | **4.59 %** (57,349 / 1,250,000; stable 4.59/4.59/4.58 % across 3 periods) | **21.8× lower** |

**Notes.** The nRF `simple-energest` `Total time` counter does not advance (only the
per-mode LISTEN/TRANSMIT counters are wired on this platform), so the printed `permil`
field is bogus; the duty cycle is computed from the raw Radio-Rx ticks over the known
period (20 s × 62500 Hz ENERGEST_SECOND = 1,250,000 ticks), *self-calibrated* by the
CSMA case reading 99.99 %. The measured TSCH idle duty (**4.59 %**) is the same order as
the paper's datasheet-analytic `table:tsch-idle` (3.1 % at L=7); it is slightly higher
because the real Orchestra schedule has the leaf listening on more than the minimal
guard×n\_rx slots (EB, shared, and its unicast-Rx slots). Translating with the
datasheet RX current (~4.6 mA), TSCH cuts idle-listening power ~22× versus always-on
CSMA -- the missing term in the byte-proxy energy budget, now measured rather than only
modelled. **HW expectation:** a real-DK firmware-side energest (or a Power-Profiler-Kit)
gives the same duty cycle; absolute idle power scales with the slotframe length
(a longer slotframe → proportionally lower duty, as in the analytic L=101 row).

---

## Merge-stability (upstream develop 04a3f0a00, 2026-07-08)
After merging upstream `contiki-ng/develop` (166 commits: resolv/lwm2m/uip6 bounds
fixes, nat64, link-stats RSSI→ETX fix, CC_ARRAY_LENGTH sweep, nrf-vpr/nrf5340/nrf54l15
ports), all 10 apps rebuild cleanly and all 5 configs re-PASS with **bit-identical
timestamps** (EDHOC finished: x5c 27.621 / c5c 26.991 / c5t 26.781 s; DTLS complete:
x509 34.351 / c509 34.304 s). The merge does not touch the C509/EDHOC/DTLS, TSCH,
Orchestra, 6LoWPAN or nrf52840 paths, so the results are unaffected. Re-check driver:
`bench/emul/postmerge-recheck.sh`.

## Bottom line
- **DTLS**: C509 is a *storage* compression only (Mbed TLS sends DER) → ~11 % smaller cert
  flight, **no** TSCH-latency win (A ≈ B ≈ 4.05–4.09 s).
- **EDHOC**: C509 is an *on-wire* compression → the X.509-by-value handshake (x5c) is
  **~35 % slower** (~2.0 s) than either C509 variant (c5t/c5c ~1.3 s) under TSCH — the
  robust duty-cycled-MAC latency result. The c5t-vs-c5c sub-difference is below the
  slotframe-alignment resolution (they flip between nrfx versions); treat c5t ≈ c5c.
- **Radio idle listening** (Part C): CSMA ~100 % vs TSCH 4.6 % duty (~22×).

## Repro
```sh
# same emulator build as the TSCH matrix (cooja-ng-ge feat/gilbert-elliott-medium + 443c1f6)
R=/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner
B=/home/joel/gemini_workspace/contiki-ng/local-tests/bench/emul
# Part A — DTLS
$R test $B/emul-dtls-x509-tsch.json     # x509 cert-mode
$R test $B/emul-dtls-c509-tsch.json     # native C509 Type-2
# Part B — EDHOC+OSCORE
$R test $B/emul-edhoc-x509-tsch.json    # x5c  (X.509 by value)
$R test $B/emul-edhoc-c5c-tsch.json     # c5c  (C509 by value)
$R test $B/emul-edhoc-c5t-tsch.json     # c5t  (C509 hash by reference)
```
EDHOC firmware built via `bench/emul/build-edhoc-tsch.sh` (shared nrf platform, TSCH +
Orchestra, sw uECC).

## Fixes required to run these (all local)
1. **`tsch_set_coordinator(1)`** added to the DTLS c509 server and all three EDHOC servers
   (`edhoc-oscore-{x509,c5c,c5t}-server`) — without it the RPL root never coordinates TSCH
   and no node associates. (The x509 DTLS server already had it.)
2. **`EDHOC_CONF_SERVER_FROM_ROOT`** (new opt-in, default off) in `edhoc-client.c` +
   the three EDHOC client apps: overrides the hard-coded `EDHOC_CONF_SERVER_EP` host with
   the dynamically-resolved RPL-root address (`NETSTACK_ROUTING.get_root_ipaddr`). Needed
   because cooja-ng-ge derives node IPv6 from the emulated FICR, not the node id, so the
   old `fd00::202:2:2:2` never matched. Mirrors how the DTLS client already resolves the
   root. Enabled in the three EDHOC client `project-conf.h`.
