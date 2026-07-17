/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * rev-ops-bench -- on-device per-operation microbenchmark for the C509
 * REVOCATION consume path (LRev follow-up, Tier-1 experiment E4 "cycles"). The
 * revocation-paper analogue of enroll-ops-bench: pure compute, no radio; times
 * each consume-path operation N times and prints ONE self-contained result
 * block carrying the firmware build id AND a per-op test id, so a pasted block
 * is fully traceable to which firmware/backend produced it.
 *
 *   crl-parse    : c509_crl_parse()            -- CBOR walk of the 11-elem CRL
 *   crl-lookup   : c509_crl_is_revoked()       -- binary search, worst-case hit
 *   ocsp-lookup  : c509_ocsp_lookup()          -- status lookup in a Basic resp
 *   ocspreq-build: c509_ocsp_build_simple_req  -- CBOR assembly, no crypto
 *   ecdsa-verify : c509_rev_verify_ecdsa_p256  -- SHA-256 + 1 ECDSA-P256 verify
 *
 * The parse/lookup/build ops are microsecond-scale, cycle-accurate on the
 * emulator (cooja-ng-ge) -- they are the C509-specific codec cost, the direct
 * revocation analogue of the LICE paper's "C509->DER overhead" measurement. The
 * ecdsa-verify op is ms-scale (dominated by uECC) and is the honest software
 * baseline for the CC310 hardware comparison. The signed CRL used by
 * ecdsa-verify is synthesised at startup (sign CRL_NO_REVOKED's TBS with a test
 * key), so no external vector is needed and the measured path is exactly
 * locate-TBS -> SHA-256 -> uECC_verify.
 */

#include "contiki.h"
#include <stdio.h>
#include <string.h>

#include "c509-crl.h"
#include "c509-ocsp.h"
#include "c509-ocsp-req.h"
#include "c509-rev-verify.h"
#include "c509-csr-build.h"      /* x509_csr_sign_msg (startup synth only) */
#include "os/net/security/micro-ecc/uECC.h"
#include "bench-stats.h"

#ifndef TEST_ID
#define TEST_ID "rev-ops-p256"
#endif
#ifndef ECC_BACKEND_NAME
#define ECC_BACKEND_NAME "software (uECC)"
#endif
#ifndef ROP_ITERS
#define ROP_ITERS 50
#endif
/* The parse/lookup/build codec ops are a few-to-tens of us, but the emulated nRF
 * has NO DWT cycle counter and its rtimer is only ~16 us granular
 * (RTIMER_SECOND=62500). So each *sample* times a BATCH of ROP_BATCH repeats of
 * the fast op; the per-op figure is the batch total / ROP_BATCH, averaged over
 * ROP_ITERS samples. ecdsa-verify is ms-scale and is timed one-per-sample
 * (batch of 1). */
#ifndef ROP_BATCH
#define ROP_BATCH 128
#endif

/* c509rev KAT vectors (verbatim from local-tests/c509-crl host tests). */
/* CRL with 6 revoked certs (serialNumberLength=2, dateLength=3, reasons). */
static const char *CRL_REVOKED_HEX =
  "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf36"
  "8cdf53c39005d492450e1056021a677c71721a00093a80f68085f6840302031a677488728218571a67748580"
  "5824112206978006123400000001334403f480065566015180065678054600009abc02a30000f6584070bb7a"
  "38065fbcabfe615170f05a9a9fe83dc892d5f735812b2a053af4b300eb466babb4f1a387cdce90d8302c680b7"
  "7aa61566423d7c235f7bd31344cf7f405";
/* CRL with no revoked certs -- used to SYNTHESISE a valid ECDSA-signed CRL. */
static const char *CRL_NO_REVOKED_HEX =
  "8b000c6f746573742063726c6f6373702d6361542f45e78d2c"
  "aedf368cdf53c39005d492450e1056011a6775d7001a00093a80f680f6584013834f4e38aa9f0dc5b8d21c86"
  "50c776a6d961c31c894c36a71a6433f5ed7d30e67f787f13c7e4c349b2848a181fdbbce361a14c220021c4a2"
  "67367ad5f1d90d";
/* Basic OCSP response (type 1), 2 issuers, 4 singles (from the host test). */
static const char *BASIC_RESP_HEX =
  "8a010c005011111111111111111111111111111111480600867838e3311a"
  "1a67c4f100808648a01c73a5f3b06334808f5410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d0039707f1962"
  "70805475d8bc4fbafc6694467641e748dfd53a8b9d176d0139707f1962708054d1ac135d7da29bdcf4dca0d528"
  "1a51605b678400821a67c32f000439707f19627080482222222222222222808554d3a0c1e3db92e8f6810537d4"
  "5cfaecf6ce417e3b0239707f19627080f65840e4869c57a66bab501acaeb7e5024105253d72f45d349ae21fb94"
  "1abe4435f8a6c9d1ca5d2784ab30cf177ff075b5502aeaee09c1146cf490663eaed9243a760d";

/* Requestor test key for the ECDSA-signed CRL synthesis (test only). */
static const uint8_t rev_priv[32] = {
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
  0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x45
};

/* Local stub for the unused Ed25519 rev-sig path. c509-rev-verify.o (which we
 * need for c509_rev_locate_tbs and c509_rev_verify_ecdsa_p256) also contains
 * c509_rev_verify_ed25519, which references ed25519_verify -> mbedTLS SHA-512.
 * This bench never verifies an Ed25519 signature, so we satisfy the linker with
 * a stub instead of dragging in mbedTLS. NEVER CALLED (returns failure). */
int
ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
               const uint8_t *msg, size_t msg_len)
{
  (void)pk; (void)sig; (void)msg; (void)msg_len;
  return -1;
}

static size_t
unhex(const char *h, uint8_t *out)
{
  size_t n = 0;
  for(; h[0] && h[1]; h += 2) {
    unsigned v;
    sscanf(h, "%2x", &v);
    out[n++] = (uint8_t)v;
  }
  return n;
}

/* Print one op's PER-OP microsecond stats on a single grep-friendly line. The
 * bench_stats and running sum accumulate the BATCH-total us of `batch` repeats
 * (batch=1 for the ms-scale verify); per-op figures divide by `batch`. Per-op us
 * are printed with 3 decimals (milli-us) since the codec ops are only a few us
 * each. The mean uses an integer running sum (robust on the emulator's soft
 * double); min/max come from bench_stats. */
static void
rop_print(const char *op, const bench_stats_t *s, uint32_t batch, uint64_t sum_us)
{
  /* Per-op mean in milli-us (per-op us * 1000), from an INTEGER running sum of
   * the batch totals -- robust against the emulator's soft-double Welford, which
   * mis-accumulates for some structs. min/max come from bench_stats (correct). */
  uint32_t mean_mus = (uint32_t)((sum_us * 1000ull) / ((uint64_t)s->n * batch));
  printf("[ROP %-13s] n=%lu fail=%lu batch=%lu mean_us=%lu.%03lu "
         "min_us=%lu.%03lu max_us=%lu.%03lu\n",
         op, (unsigned long)s->n, (unsigned long)s->fail, (unsigned long)batch,
         (unsigned long)(mean_mus / 1000), (unsigned long)(mean_mus % 1000),
         (unsigned long)((s->min_us * 1000 / batch) / 1000),
         (unsigned long)((s->min_us * 1000 / batch) % 1000),
         (unsigned long)((s->max_us * 1000 / batch) / 1000),
         (unsigned long)((s->max_us * 1000 / batch) % 1000));
}

PROCESS(rev_ops_bench, "rev-ops-bench");
AUTOSTART_PROCESSES(&rev_ops_bench);

PROCESS_THREAD(rev_ops_bench, ev, data)
{
  static bench_stats_t s_parse, s_lookup, s_ocsp, s_build, s_verify;
  /* Integer running sums of the batch-total us (robust per-op mean; see rop_print). */
  static uint64_t sum_parse, sum_lookup, sum_ocsp, sum_build, sum_verify;
  static uint8_t crl_rev[512], basic[512], signed_crl[256];
  static size_t crl_rev_len, basic_len, signed_crl_len;
  static uint8_t pub64[64], pub65[65];
  static uint8_t reqbuf[128];
  static int i;
  static rtimer_clock_t t0;
  /* Worst-case (last, highest) serial in the sorted 6-entry list -> full-depth
   * binary search. Reasons byte present, so it is a genuine membership hit. */
  static const uint8_t serial_last[2] = { 0x9a, 0xbc };
  /* Simple-request inputs: 8-byte issuerCertHash + 20-byte serialNumberHash. */
  static const uint8_t ihash8[8]  = { 0,1,2,3,4,5,6,7 };
  static uint8_t shash20[20];
  static const uint8_t nonce8[8]  = { 0xa,0xb,0xc,0xd,0xe,0xf,0x1,0x2 };

  PROCESS_BEGIN();

  printf("[REV-OPS fw:%s compiled:%s %s backend:%s curve:secp256r1 iters:%d batch:%d test:%s]\n",
         FW_BUILD_ID, __DATE__, __TIME__, ECC_BACKEND_NAME, ROP_ITERS, ROP_BATCH, TEST_ID);

  memset(shash20, 0x5a, sizeof(shash20));

  crl_rev_len = unhex(CRL_REVOKED_HEX, crl_rev);
  basic_len = unhex(BASIC_RESP_HEX, basic);

  /* --- Synthesise a valid ECDSA-P256-signed CRL for the verify op. --- */
  signed_crl_len = unhex(CRL_NO_REVOKED_HEX, signed_crl);
  {
    const uint8_t *tbs, *sig;
    size_t tbs_len, sig_len;
    uint8_t rs[64];
    if(uECC_compute_public_key(rev_priv, pub64, uECC_secp256r1()) != 1) {
      printf("[REV-OPS ERROR] public-key derivation failed\n");
      PROCESS_EXIT();
    }
    pub65[0] = 0x04;
    memcpy(pub65 + 1, pub64, 64);
    if(c509_rev_locate_tbs(signed_crl, signed_crl_len,
                           &tbs, &tbs_len, &sig, &sig_len) != 0 || sig_len != 64) {
      printf("[REV-OPS ERROR] TBS locate failed\n");
      PROCESS_EXIT();
    }
    if(x509_csr_sign_msg(tbs, tbs_len, rev_priv, sizeof(rev_priv), rs) != 0) {
      printf("[REV-OPS ERROR] CRL synth-sign failed\n");
      PROCESS_EXIT();
    }
    /* Overwrite the 64-byte sigValue in place, then confirm it verifies. */
    memcpy((uint8_t *)sig, rs, 64);
    if(c509_rev_verify_ecdsa_p256(signed_crl, signed_crl_len, pub65, 65) != 0) {
      printf("[REV-OPS ERROR] synth CRL failed self-verify\n");
      PROCESS_EXIT();
    }
  }

  bench_stats_init(&s_parse);
  bench_stats_init(&s_lookup);
  bench_stats_init(&s_ocsp);
  bench_stats_init(&s_build);
  bench_stats_init(&s_verify);
  sum_parse = sum_lookup = sum_ocsp = sum_build = sum_verify = 0;

  for(i = 0; i < ROP_ITERS; i++) {
    c509_crl_t crl;
    c509_ocsp_result_t r;
    size_t rlen;
    int b;
    volatile int sink = 0;   /* consume results so batched calls aren't elided */

    /* --- crl-parse (batched) --- */
    t0 = RTIMER_NOW();
    for(b = 0; b < ROP_BATCH; b++) {
      sink += c509_crl_parse(crl_rev, crl_rev_len, &crl);
    }
    if(sink == 0) {
      uint32_t e = bench_elapsed_us(t0, RTIMER_NOW());
      sum_parse += e; bench_stats_add_us(&s_parse, e, 0);
    } else {
      bench_stats_add_fail(&s_parse);
      continue;
    }
    /* one clean parse for the lookup op below */
    c509_crl_parse(crl_rev, crl_rev_len, &crl);

    /* --- crl-lookup (binary search, worst-case serial; batched) --- */
    sink = 0;
    t0 = RTIMER_NOW();
    for(b = 0; b < ROP_BATCH; b++) {
      sink += c509_crl_is_revoked(&crl, serial_last, 2);
    }
    if(sink == ROP_BATCH) {   /* every call must return 1 (revoked) */
      uint32_t e = bench_elapsed_us(t0, RTIMER_NOW());
      sum_lookup += e; bench_stats_add_us(&s_lookup, e, 0);
    } else {
      bench_stats_add_fail(&s_lookup);
    }

    /* --- ocsp-lookup (Basic resp status lookup: issuer0@38, revoked@107; batched) --- */
    sink = 0;
    t0 = RTIMER_NOW();
    for(b = 0; b < ROP_BATCH; b++) {
      sink += c509_ocsp_lookup(basic, basic_len, basic + 38, 8, basic + 107, 20, &r);
    }
    if(sink == 0) {   /* every call must return 0 (matched) */
      uint32_t e = bench_elapsed_us(t0, RTIMER_NOW());
      sum_ocsp += e; bench_stats_add_us(&s_ocsp, e, 0);
    } else {
      bench_stats_add_fail(&s_ocsp);
    }

    /* --- ocspreq-build (Simple request assembly; batched) --- */
    sink = 0;
    t0 = RTIMER_NOW();
    for(b = 0; b < ROP_BATCH; b++) {
      rlen = 0;
      sink += c509_ocsp_build_simple_request(reqbuf, sizeof(reqbuf), &rlen, 0,
                                             nonce8, sizeof(nonce8),
                                             ihash8, sizeof(ihash8),
                                             shash20, sizeof(shash20));
    }
    if(sink == 0) {
      uint32_t e = bench_elapsed_us(t0, RTIMER_NOW());
      sum_build += e; bench_stats_add_us(&s_build, e, 0);
    } else {
      bench_stats_add_fail(&s_build);
    }

    /* --- ecdsa-verify (rev-sig verify: SHA-256 + uECC_verify; one per sample) --- */
    t0 = RTIMER_NOW();
    if(c509_rev_verify_ecdsa_p256(signed_crl, signed_crl_len, pub65, 65) == 0) {
      uint32_t e = bench_elapsed_us(t0, RTIMER_NOW());
      sum_verify += e; bench_stats_add_us(&s_verify, e, 0);
    } else {
      bench_stats_add_fail(&s_verify);
    }

    /* Yield each iteration so the watchdog/netstack stay happy on the DK. */
    PROCESS_PAUSE();
  }

  /* One self-contained, traceable result block. */
  rop_print("crl-parse",     &s_parse,  ROP_BATCH, sum_parse);
  rop_print("crl-lookup",    &s_lookup, ROP_BATCH, sum_lookup);
  rop_print("ocsp-lookup",   &s_ocsp,   ROP_BATCH, sum_ocsp);
  rop_print("ocspreq-build", &s_build,  ROP_BATCH, sum_build);
  rop_print("ecdsa-verify",  &s_verify, 1, sum_verify);
  printf("[REV-OPS-END fw:%s backend:%s test:%s]\n",
         FW_BUILD_ID, ECC_BACKEND_NAME, TEST_ID);

  PROCESS_END();
}
