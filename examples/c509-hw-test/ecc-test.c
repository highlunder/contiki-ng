/*
 * ECC operation microbenchmark for nRF52840 via cooja-ng emulator.
 *
 * Tests each P-256 operation that appears in a DTLS ECDHE-ECDSA handshake:
 *   1. ECDH server keygen   (state=4: server generates ephemeral key)
 *   2. ECDH client keygen   (state=6: client generates ephemeral key)
 *   3. ECDSA keygen         (baseline: generate signing key)
 *   4. ECDSA sign           (state=4: server signs ServerKeyExchange;
 *                            state=7: client signs CertificateVerify)
 *   5. ECDSA verify         (state=11: peer verifies signature)
 *   6. ECDH compute_shared  (state=6/server side, state=6/client side)
 *
 * The cooja-ng simulator timestamps every log line, so the wall-clock
 * difference between START and END lines gives the simulated duration.
 * All large structs are static so they survive PROCESS context switches.
 */

#include "contiki.h"
#include "lib/csprng.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "ECC-Test"
#define LOG_LEVEL  LOG_LEVEL_INFO

PROCESS(ecc_test_process, "ECC Test");
AUTOSTART_PROCESSES(&ecc_test_process);
/*---------------------------------------------------------------------------*/
static int
rng_cb(void *ctx, unsigned char *buf, size_t len)
{
  (void)ctx;
  return csprng_rand(buf, len) ? 0 : -1;
}
/*---------------------------------------------------------------------------*/
/* All large mbedTLS structures are static (placed in BSS, not stack). */
static mbedtls_ecp_group  grp;
static mbedtls_mpi        srv_d;          /* server ECDH private scalar */
static mbedtls_ecp_point  srv_Q;          /* server ECDH public point  */
static mbedtls_mpi        cli_d;          /* client ECDH private scalar */
static mbedtls_ecp_point  cli_Q;          /* client ECDH public point  */
static mbedtls_mpi        shared_srv;     /* ECDH shared secret (server) */
static mbedtls_mpi        shared_cli;     /* ECDH shared secret (client) */
static mbedtls_ecdsa_context ecdsa_ctx;   /* signing context */
static unsigned char      sig_buf[MBEDTLS_ECDSA_MAX_LEN];
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ecc_test_process, ev, data)
{
  static int    ret;
  static size_t sig_len;
  static unsigned char hash[32];
  static int    secrets_match;

  PROCESS_BEGIN();

  LOG_INFO("=== ECC Microbenchmark START ===\n");

  /* ----- Init ----- */
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&srv_d);
  mbedtls_ecp_point_init(&srv_Q);
  mbedtls_mpi_init(&cli_d);
  mbedtls_ecp_point_init(&cli_Q);
  mbedtls_mpi_init(&shared_srv);
  mbedtls_mpi_init(&shared_cli);
  mbedtls_ecdsa_init(&ecdsa_ctx);

  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if(ret != 0) {
    LOG_ERR("ecp_group_load failed: %d\n", ret);
    PROCESS_EXIT();
  }
  /* Fixed (non-random) hash so sign/verify timing and results are
   * reproducible across runs; the value itself is not meaningful. */
  memset(hash, 0xAB, sizeof(hash));

  /* ----- Test 1: ECDH server ephemeral keygen ----- */
  LOG_INFO("--- START: ECDH keygen (server ephemeral) ---\n");
  ret = mbedtls_ecp_gen_keypair(&grp, &srv_d, &srv_Q, rng_cb, NULL);
  LOG_INFO("--- END: ECDH keygen (server) ret=%d ---\n", ret);

  /* ----- Test 2: ECDH client ephemeral keygen ----- */
  LOG_INFO("--- START: ECDH keygen (client ephemeral) ---\n");
  ret = mbedtls_ecp_gen_keypair(&grp, &cli_d, &cli_Q, rng_cb, NULL);
  LOG_INFO("--- END: ECDH keygen (client) ret=%d ---\n", ret);

  /* ----- Test 3: ECDSA keygen (signing key) ----- */
  LOG_INFO("--- START: ECDSA keygen ---\n");
  ret = mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP256R1, rng_cb, NULL);
  LOG_INFO("--- END: ECDSA keygen ret=%d ---\n", ret);

  /* ----- Test 4: ECDSA sign ----- */
  LOG_INFO("--- START: ECDSA sign ---\n");
  sig_len = sizeof(sig_buf);
  ret = mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256,
                                       hash, sizeof(hash),
                                       sig_buf, sizeof(sig_buf), &sig_len,
                                       rng_cb, NULL);
  LOG_INFO("--- END: ECDSA sign ret=%d sig_len=%u ---\n", ret, (unsigned)sig_len);

  /* ----- Test 5: ECDSA verify ----- */
  LOG_INFO("--- START: ECDSA verify ---\n");
  ret = mbedtls_ecdsa_read_signature(&ecdsa_ctx,
                                      hash, sizeof(hash),
                                      sig_buf, sig_len);
  LOG_INFO("--- END: ECDSA verify ret=%d ---\n", ret);

  /* ----- Test 6: ECDH compute_shared (server side) ----- */
  /* Server computes srv_d * cli_Q (its own private scalar times the
   * client's ephemeral public point). */
  LOG_INFO("--- START: ECDH compute_shared (server: srv_d * cli_Q) ---\n");
  ret = mbedtls_ecdh_compute_shared(&grp, &shared_srv,
                                     &cli_Q, &srv_d,
                                     rng_cb, NULL);
  LOG_INFO("--- END: ECDH compute_shared (server) ret=%d ---\n", ret);

  /* ----- Test 7: ECDH compute_shared (client side) ----- */
  /* Client computes cli_d * srv_Q (the mirror operation). By the
   * Diffie-Hellman property both sides should derive the same point,
   * checked below. */
  LOG_INFO("--- START: ECDH compute_shared (client: cli_d * srv_Q) ---\n");
  ret = mbedtls_ecdh_compute_shared(&grp, &shared_cli,
                                     &srv_Q, &cli_d,
                                     rng_cb, NULL);
  LOG_INFO("--- END: ECDH compute_shared (client) ret=%d ---\n", ret);

  /* ----- Correctness check: shared secrets must match ----- */
  /* This is a sanity check on the ECDH math/timing measurements above,
   * not a security property test (no real handshake takes place). */
  secrets_match = (mbedtls_mpi_cmp_mpi(&shared_srv, &shared_cli) == 0);
  LOG_INFO("=== ECDH shared secrets match: %s ===\n",
           secrets_match ? "YES (PASS)" : "NO (FAIL)");

  LOG_INFO("=== ECC Microbenchmark DONE ===\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
