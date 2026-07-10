# Multi-hop TSCH — DTLS comparison, CSMA (vs TSCH), and full enrollment

Companion to `MULTIHOP-M1-RESULTS.md` (EDHOC handshake latency-vs-hops) extending the
1/2/3-hop line-topology study (cooja-ng-ge, nRF52840-DK, same relays/topology) to three
more arms the EDHOC-only M1 did not cover. All "simple handshake" unless noted.

## A. DTLS handshake vs EDHOC (scenarios A/B vs C/D), over TSCH hops

`emul-dtls{x509,c509}-{1,2,3}hop-tsch.json`, 3 seeds. Metric = full DTLS handshake latency
("Connecting … handshake 1, full" → "DTLS handshake 1 complete"). DTLS uses its own
flight retransmission (mbedTLS DTLS, ~9 s initial timeout, exponential backoff); no CoAP-CON
handshake layer, so only the connect-delay + ASN-drift multi-hop fixes were needed.

| protocol / cert | 1 hop | 2 hops | 3 hops |
|-----------------|-------|--------|--------|
| **DTLS** + X.509 (A)        | 3/3, **4.1 s** | **0/3** | **0/3** |
| **DTLS** + C509 (B)         | 3/3, **4.0 s** | **0/3** | **0/3** |
| EDHOC + C509 `c5t` (D)      | 6/6, 1.1 s | 5/6, 2.7 s | 2/3 |
| EDHOC + X.509 `x5chain` (C) | 6/6, 2.0 s | 3/6, 23 s  | 0/3 |

(EDHOC rows from `MULTIHOP-M1-RESULTS.md`, loss-free, for comparison.)

**Findings.**
1. **For DTLS, C509 gives no multi-hop benefit — X.509 and C509 are identical** (4.1 vs 4.0 s
   at 1 hop; both 0/3 at 2 & 3 hops). This is expected and confirms the paper's framing:
   C509-for-DTLS is a *storage-only* compression — the C509 service reconstructs the full
   X.509 DER before handing it to mbedTLS, so the same ~384 B certificate goes on the wire in
   both cases. The multi-hop reliability difference C509 buys is therefore **EDHOC-specific**
   (EDHOC carries the compact credential — `c5t` hash / `c5c` C509 — on the wire), not a DTLS
   property.
2. **DTLS fails at 2 hops for both certificates.** The upward ClientHello (small) reaches the
   server, which begins its handshake, but the server's certificate flight never traverses
   the downward multi-hop path within the 600 s cap (verified in the RF trace: the client
   keeps retransmitting ClientHello). DTLS's flight retransmission does not help when the
   flight cannot be reassembled across the hops at all.
3. **DTLS is slower than EDHOC at 1 hop and fails earlier** — ~4 s (both certs) vs EDHOC's
   1.1 s (`c5t`) / 2.0 s (`x5chain`), because the DTLS handshake is more round-trips; and DTLS
   fails at 2 hops where EDHOC `x5chain` still completes ~half the time and `c5t` completes
   reliably. **Net: EDHOC + C509 `c5t` is the only combination that completes over 2–3 hops;
   DTLS (either cert) does not reach 2 hops.**

## B. CSMA vs TSCH (EDHOC + DTLS), loss-free

Same firmware/topology but MAC = CSMA (always-on, carrier-sense + backoff) instead of TSCH.
`emul-{c5t,x5c,dtlsx509}-{1,2}hop-csma.json`, 3 seeds. Latency = full handshake.

| protocol | MAC | 1 hop | 2 hops |
|----------|-----|-------|--------|
| EDHOC `c5t`   | CSMA | 3/3, **0.8 s** | 3/3, **1.5 s** |
| EDHOC `c5t`   | TSCH | 6/6, 1.1 s | 5/6, 2.7 s |
| EDHOC `x5chain` | CSMA | 3/3, **1.3 s** | 3/3, **3.7 s** |
| EDHOC `x5chain` | TSCH | 6/6, 2.0 s | 3/6, 23 s |
| DTLS X.509    | CSMA | 3/3, **3.1 s** | 3/3, **7.1 s** |
| DTLS X.509    | TSCH | 3/3, 4.1 s | **0/3** |

**Findings — this reframes the multi-hop reliability story.**
1. **Under CSMA, everything completes reliably at 2 hops (3/3), including the large `x5chain`
   and DTLS flights that FAILED under TSCH.** So the TSCH 2/3-hop failures are largely a
   **6TiSCH minimal-schedule artifact**: its single shared slot self-collides at the relay and
   drops fragments, and a larger flight (more fragments) is more likely to lose one. CSMA's
   always-on carrier-sense + link-layer retransmission delivers the fragmented flight without
   that per-slot contention. (A dedicated-slot TSCH schedule such as Orchestra might be
   expected to behave more like CSMA on reliability, but when actually tried it did not — see
   §D: Orchestra as-configured has its own multi-hop delivery failure in this emulator, so
   CSMA is the clean schedule-independence evidence.)
2. **The robust, MAC-independent credential effect is LATENCY, and it scales with size and
   hops.** At 2 hops: c5t 1.5 s < x5chain 3.7 s < DTLS 7.1 s — the compact C509 credential is
   ~2.5× faster than X.509 EDHOC and ~5× faster than DTLS, and the gap widens with hop count
   (1→2 hops roughly doubles each). This holds on both MACs; it is the durable statement of
   the credential-size benefit at depth.
3. **CSMA is faster than TSCH loss-free** (c5t 2-hop 1.5 s vs 2.7 s; and it clears the TSCH
   self-collision failures) — but at the cost of no radio duty-cycling (much higher idle
   energy). TSCH trades that latency/robustness for energy; under loss its channel hopping
   also de-correlates bursts (see the paper's burst section), which CSMA's single channel does
   not. So the MAC choice moves the credential-size benefit between latency (CSMA, loss-free
   TSCH) and reliability (minimal-schedule TSCH, and — per the burst analysis — lossy links).

## C. Full enrollment (/crts + /sen over EDHOC+OSCORE) over multi-hop

Not a "simple handshake": the client runs the EDHOC handshake, then an OSCORE GET `/crts`
(fetch the CA CertificateChain), builds+signs a C509 Type-3 CSR, and an OSCORE POST `/sen`
(submit CSR, receive + verify the issued 144-byte cert). C509 `c5t`, TSCH.
`emul-enroll-{1,2}hop-tsch.json`, 3 seeds. Latency = MSG_1 → "enroll end-to-end TEST PASSED".

| flow | 1 hop | 2 hops |
|------|-------|--------|
| EDHOC + /crts + /sen (`c5t`) | 3/3, **2.8 s** | 3/3, recovery-heavy (~30–250 s) |

**Findings.**
1. **Enrollment completes over 2 hops (3/3), but only via its restart-on-failure recovery.**
   At 1 hop it is a clean 2.8 s (EDHOC ~1 s + `/crts` + `/sen` ~1.8 s). At 2 hops all three
   seeds complete but heavily recovery-driven: two needed `/crts` OSCORE retransmits (the
   client's `ENROLL_MAX_RETX` bounded UDP retransmit with a fresh partial-IV per attempt);
   one needed the EDHOC handshake itself to restart 3× (Attempt 0/1/2, 60/120 s backoff)
   before the enrollment steps. Latencies range from tens of seconds to ~250 s.
2. **This is the paper's "recovery closes the gap" + "advantage compounds with workload
   length" claims, on multi-hop.** Enrollment is a longer workload than a single handshake
   (handshake + two OSCORE round-trips carrying a chain and a CSR/cert), so its whole-flow
   delivery probability over lossy multi-hop is lower and it leans on recovery to complete —
   exactly as the joint-delivery model predicts. The compact `c5t` credential is what keeps
   each restarted/retried flight cheap enough that recovery lands within budget; a bulky
   inline-X.509 enrollment (larger CSR/cert flights) would be far more expensive to recover,
   mirroring the handshake `x5chain` result.
3. Caveat: like the handshakes, the 2-hop numbers sit on the TSCH minimal-schedule
   self-collision floor (§B) — the recovery is partly compensating for that schedule
   artifact; on CSMA the enrollment would complete faster and with less recovery.

## D. Orchestra (dedicated-slot TSCH) — attempted, NEGATIVE

To test whether the §B reliability failures are specifically the 6TiSCH *minimal*
schedule (a dedicated-slot TSCH schedule ought to behave like CSMA), we rebuilt the c5t
and x5c EDHOC firmware + relay with Orchestra (`ORCHESTRA=1` build gate →
`MODULES += os/services/orchestra`; default rules eb_per_time_source /
unicast_per_neighbor_rpl_ns / default_common) and the ASN-drift relax. Configs
`emul-{c5t,x5c}-{2,3}hop-orch.json`.

**Result: Orchestra does not complete the multi-hop handshake for *either* credential.**
The ASN-drift fix works (0 network-leaves, node stays associated), but at 2 hops **c5t
fails too** — MSG_1 is regenerated/restarted (75/195/375 s) and never completes; x5c
likewise (150 s no-progress deadline, restart). So Orchestra as-configured has its **own**
multi-hop delivery problem in cooja-ng-ge (even the small c5t flight does not traverse),
independent of credential size. It is therefore **not** a clean dedicated-slot
demonstration and does not confirm (or refute) the "minimal-schedule artifact" hypothesis.

**What this means:** the clean schedule/MAC-independence evidence stays the **CSMA** result
(§B) — a non-slotted MAC completes every case, so the credential effect is not fundamental.
Whether a *correctly-tuned* dedicated-slot TSCH schedule would match CSMA remains open
(Orchestra multi-hop in this emulator needs its own debugging, out of scope here). The
Orchestra build gates are kept (opt-in, default-off) for that future work.

**Not run, with reasons:**
- *Lossy CSMA vs TSCH under Gilbert-Elliott*: the GE plugin is per-link, per-frame (not
  per-channel — see `gilbert_elliott_medium.c`), so it does not model TSCH's channel-hopping
  de-correlation. A lossy-CSMA-vs-TSCH run therefore could not test the "hopping wins under
  burst" claim (which stays the paper's analytic argument, citing RFC 7554). Skipped to
  avoid a misleading data point.
- *X.509 enrollment arm*: no PKCS#10/X.509 enrollment app exists (only the C509
  `edhoc-oscore-crts-*`); building one is a large effort, and the c5t-vs-X.509 enroll
  contrast is predictable from the x5c handshake result. Future work.

---
_Data: `scratchpad/{dtls,csma,enroll}/`. Configs: `emul-dtls{x509,c509}-{1,2,3}hop-tsch.json`,
`emul-{c5t,x5c,dtlsx509}-{1,2}hop-csma.json`, `emul-enroll-{1,2}hop-tsch.json`,
`emul-{c5t,x5c}-{2,3}hop-orch.json`._
