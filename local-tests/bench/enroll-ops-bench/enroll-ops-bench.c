/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * enroll-ops-bench -- on-device per-operation microbenchmark for the C509
 * enrollment crypto path (LICE follow-up, Exp RW-6 remainder: "full per-op
 * timing on nRF52840-DK hardware"). Pure compute, no radio: times each of the
 * five enrollment operations N times and prints ONE self-contained result block
 * (a few lines) carrying the firmware build id AND a per-op test id, so a pasted
 * block is fully traceable to which firmware/backend produced it.
 *
 *   csr-build    : x509_encode_csr_build()  -- CBOR assembly, no asymmetric crypto
 *   csr-sign     : x509_csr_sign()          -- SHA-256 + 1 ECDSA-P256 sign (PoP)
 *   ca-issue     : c509_ca_issue_cert()     -- CBOR assembly + 1 ECDSA-P256 sign
 *   chain-valid  : verify a CA cert's sig   -- SHA-256 + 1 ECDSA-P256 verify
 *   cert-verify  : verify the issued cert   -- SHA-256 + 1 ECDSA-P256 verify
 *
 * The uECC path is the software backend; a CC310 build (ECC_HW_BACKEND=cc310)
 * names itself in the stamp for the hardware comparison. Run on the DK and read
 * the [EOP ...] block; the crypto ops are ms-scale, so a cycle-accurate emulator
 * is too slow -- native gives an x86 sanity figure only.
 */

#include "contiki.h"
#include <stdio.h>
#include <string.h>

#include "c509-csr-build.h"
#include "c509-ca.h"
#include "c509-csr-parse.h"
#include "c509_registry.h"
#include "os/net/security/micro-ecc/uECC.h"
#include "bench-stats.h"

#ifndef TEST_ID
#define TEST_ID "enroll-ops-p256"
#endif
#ifndef ECC_BACKEND_NAME
#define ECC_BACKEND_NAME "software (uECC)"
#endif
#ifndef EOP_ITERS
#define EOP_ITERS 50
#endif

/* Fixed test scalars (well below the secp256r1 group order); public keys are
 * derived at startup. Test credentials only. */
static const uint8_t client_priv[32] = {
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
  0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x45
};
static const uint8_t ca_priv[32] = {
  0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
  0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x89
};
static uint8_t client_pub65[65];   /* 0x04 || X || Y */
static uint8_t ca_pub65[65];

static const uint8_t subject[] = "edhoc-client";
static const uint8_t ca_name[] = "EDHOC-Test-CA";
static const uint8_t serial[] = { 0x12, 0x34 };
#define ISSUED_NOT_BEFORE 1700000000LL
#define ISSUED_NOT_AFTER  2000000000LL

/* Print one op's microsecond stats on a single grep-friendly line. */
static void
eop_print(const char *op, const bench_stats_t *s)
{
  uint32_t sd = bench_stats_stddev_us(s);
  uint32_t mean = (uint32_t)(s->mean_us + 0.5);
  printf("[EOP %-11s] n=%lu fail=%lu mean_us=%lu sd_us=%lu min_us=%lu max_us=%lu\n",
         op, (unsigned long)s->n, (unsigned long)s->fail,
         (unsigned long)mean, (unsigned long)sd,
         (unsigned long)s->min_us, (unsigned long)s->max_us);
}

PROCESS(enroll_ops_bench, "enroll-ops-bench");
AUTOSTART_PROCESSES(&enroll_ops_bench);

PROCESS_THREAD(enroll_ops_bench, ev, data)
{
  static bench_stats_t s_build, s_sign, s_issue, s_chain, s_verify;
  static uint8_t client_pub64[64], ca_pub64[64];
  static uint8_t issued[512], ca_cert[512];
  static size_t issued_len, ca_cert_len;
  static uint8_t csr[256];
  static int i;
  static rtimer_clock_t t0;

  PROCESS_BEGIN();

  bench_marker_init();                 /* no-op unless -DENERGY_MARKER_PIN */

  printf("[ENROLL-OPS fw:%s compiled:%s %s backend:%s curve:secp256r1 iters:%d test:%s]\n",
         FW_BUILD_ID, __DATE__, __TIME__, ECC_BACKEND_NAME, EOP_ITERS, TEST_ID);

  /* Derive public keys (65-byte uncompressed). */
  if(uECC_compute_public_key(client_priv, client_pub64, uECC_secp256r1()) != 1 ||
     uECC_compute_public_key(ca_priv, ca_pub64, uECC_secp256r1()) != 1) {
    printf("[ENROLL-OPS ERROR] public-key derivation failed\n");
    PROCESS_EXIT();
  }
  client_pub65[0] = 0x04;
  memcpy(client_pub65 + 1, client_pub64, 64);
  ca_pub65[0] = 0x04;
  memcpy(ca_pub65 + 1, ca_pub64, 64);

  /* Reference certificates for the verify ops (issued once). */
  issued_len = 0;
  if(c509_ca_issue_cert(issued, sizeof(issued), &issued_len,
                        serial, sizeof(serial),
                        ca_name, sizeof(ca_name) - 1,
                        ISSUED_NOT_BEFORE, ISSUED_NOT_AFTER,
                        subject, sizeof(subject) - 1,
                        C509_PK_SECP256R1, client_pub65, sizeof(client_pub65),
                        ca_priv, sizeof(ca_priv)) != 0) {
    printf("[ENROLL-OPS ERROR] reference issue failed\n");
    PROCESS_EXIT();
  }
  /* Self-signed CA cert (issuer=subject=CA, signed by the CA key). */
  ca_cert_len = 0;
  if(c509_ca_issue_cert(ca_cert, sizeof(ca_cert), &ca_cert_len,
                        serial, sizeof(serial),
                        ca_name, sizeof(ca_name) - 1,
                        ISSUED_NOT_BEFORE, ISSUED_NOT_AFTER,
                        ca_name, sizeof(ca_name) - 1,
                        C509_PK_SECP256R1, ca_pub65, sizeof(ca_pub65),
                        ca_priv, sizeof(ca_priv)) != 0) {
    printf("[ENROLL-OPS ERROR] reference CA cert failed\n");
    PROCESS_EXIT();
  }

  bench_stats_init(&s_build);
  bench_stats_init(&s_sign);
  bench_stats_init(&s_issue);
  bench_stats_init(&s_chain);
  bench_stats_init(&s_verify);

  for(i = 0; i < EOP_ITERS; i++) {
    size_t off, tbs_len, tbs2_len, out_len;

    /* PPK2 energy window: one pulse spans the whole 5-op compute sequence.
     * These ops are pure P-256/SHA-256 compute at near-constant current, so
     * per-op energy = (per-iteration energy) x (the per-op time fraction from
     * H1), rather than needing five separate windows. */
    bench_marker_high();

    /* --- csr-build --- */
    off = 0; tbs_len = 0;
    t0 = RTIMER_NOW();
    if(x509_encode_csr_build(csr, sizeof(csr), &off, subject, sizeof(subject) - 1,
                             C509_PK_SECP256R1, client_pub65, sizeof(client_pub65),
                             &tbs_len) == 0) {
      bench_stats_add_us(&s_build, bench_elapsed_us(t0, RTIMER_NOW()), 0);
    } else {
      bench_marker_low();               /* don't leave the window open on skip */
      bench_stats_add_fail(&s_build);
      continue;
    }

    /* --- csr-sign (PoP) --- */
    t0 = RTIMER_NOW();
    if(x509_csr_sign(csr, tbs_len, off, client_priv, sizeof(client_priv)) == 0) {
      bench_stats_add_us(&s_sign, bench_elapsed_us(t0, RTIMER_NOW()), 0);
    } else {
      bench_stats_add_fail(&s_sign);
    }

    /* --- ca-issue --- */
    out_len = 0;
    t0 = RTIMER_NOW();
    if(c509_ca_issue_cert(issued, sizeof(issued), &out_len,
                          serial, sizeof(serial), ca_name, sizeof(ca_name) - 1,
                          ISSUED_NOT_BEFORE, ISSUED_NOT_AFTER,
                          subject, sizeof(subject) - 1,
                          C509_PK_SECP256R1, client_pub65, sizeof(client_pub65),
                          ca_priv, sizeof(ca_priv)) == 0) {
      bench_stats_add_us(&s_issue, bench_elapsed_us(t0, RTIMER_NOW()), 0);
      issued_len = out_len;
    } else {
      bench_stats_add_fail(&s_issue);
    }

    /* --- chain-valid: verify the CA cert's ECDSA-SHA256 signature --- */
    tbs2_len = ca_cert_len - 2 - 64;   /* strip 58 40 sigValue header + 64 sig */
    t0 = RTIMER_NOW();
    if(c509_csr_verify_pop(ca_cert, tbs2_len, ca_pub65, sizeof(ca_pub65),
                           ca_cert + ca_cert_len - 64, 64) == 0) {
      bench_stats_add_us(&s_chain, bench_elapsed_us(t0, RTIMER_NOW()), 0);
    } else {
      bench_stats_add_fail(&s_chain);
    }

    /* --- cert-verify: verify the issued leaf cert against the CA key --- */
    tbs2_len = issued_len - 2 - 64;
    t0 = RTIMER_NOW();
    if(c509_csr_verify_pop(issued, tbs2_len, ca_pub65, sizeof(ca_pub65),
                           issued + issued_len - 64, 64) == 0) {
      bench_stats_add_us(&s_verify, bench_elapsed_us(t0, RTIMER_NOW()), 0);
    } else {
      bench_stats_add_fail(&s_verify);
    }
    bench_marker_low();                  /* end of the per-iteration compute window */

    /* Yield periodically so the watchdog/netstack stay happy on the DK. */
    if((i & 0x3) == 0) {
      PROCESS_PAUSE();
    }
  }

  /* One self-contained, traceable result block. */
  eop_print("csr-build",   &s_build);
  eop_print("csr-sign",    &s_sign);
  eop_print("ca-issue",    &s_issue);
  eop_print("chain-valid", &s_chain);
  eop_print("cert-verify", &s_verify);
  printf("[ENROLL-OPS-END fw:%s backend:%s test:%s]\n",
         FW_BUILD_ID, ECC_BACKEND_NAME, TEST_ID);

  PROCESS_END();
}
