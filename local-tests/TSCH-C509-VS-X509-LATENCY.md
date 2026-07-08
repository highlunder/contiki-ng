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
| Client connect (sim time) | 30.252 s | 30.250 s | — |
| DTLS handshake-1 complete | 34.351 s | 34.304 s | — |
| **Pure handshake latency** | **4.099 s** | **4.054 s** | **−45 ms (≈1 %)** |
| Server Certificate flight | **756 B** | **675 B** | **−81 B (≈11 %)** |
| Reconstructed own-cert DER | (native DER) | 281 B | — |

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

| Variant | ID_CRED form | MSG_1 | MSG_2 | MSG_3 | MSG_2+3 | **Handshake latency**¹ | vs x5c | End-to-end PASS² |
|---|---|---|---|---|---|---|---|---|
| **c5t** | C509 cert **hash** (by ref) | 38 B | **114 B** | **90 B** | 204 B | **1.086 s** | **−44 %** | 27.410 s |
| **c5c** | C509 cert (by value, ~160 B) | 38 B | **267 B** | **242 B** | 509 B | **1.295 s** | **−33 %** | 27.620 s |
| **x5c** | X.509 cert (by value) | 38 B | **492 B** | **468 B** | 960 B | **1.925 s** | — | 28.251 s |

¹ MSG_1 generation → "EDHOC finished" (client). ² end-to-end incl. OSCORE GET round trip.

**Finding.** Handshake latency is **monotonic in credential size**: c5t (1.09 s) « c5c
(1.30 s) « x5c (1.93 s). Switching X.509 → C509-by-value (c5c) cuts the two cred-bearing
messages nearly in half (960 → 509 B) and the handshake latency by **33 %** (0.63 s);
switching to C509-hash-by-reference (c5t) cuts them to 204 B and the latency by **44 %**
(0.84 s). This is the compression → fragment-count → latency chain that a slotted MAC
makes visible and that the sub-second CSMA runs hide. On CSMA the same size deltas cost
only a few ms of extra airtime; under Orchestra each extra fragment waits for its unicast
slot in the next slotframe, so bytes turn into seconds.

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

## Bottom line
- **DTLS**: C509 is a *storage* compression only (Mbed TLS sends DER) → ~11 % smaller cert
  flight, **no** TSCH-latency win.
- **EDHOC**: C509 is an *on-wire* compression → **33 % (c5c) / 44 % (c5t)** lower handshake
  latency than X.509 under TSCH. This is the number for the paper's duty-cycled-MAC story.

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
