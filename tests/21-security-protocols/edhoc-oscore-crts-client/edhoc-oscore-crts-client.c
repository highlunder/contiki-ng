/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE `/crts` + `/sen` test client — native C509 Type 2, c5t
 *   mode (LICE/C509 enrollment plan, Phase 3.3).
 *
 *   After the EDHOC+OSCORE handshake:
 *   1. Sends an OSCORE GET (`/crts`) and expects a CertificateChain
 *      (`[+ bstr]`) in response. Each chain element is decoded with
 *      `c509_chain_decode()` and validated against the CA trust store with
 *      `edhoc_c509_validate_chain()`.
 *   2. Builds and self-signs a C509 Type-3 CSR for this client's own EDHOC
 *      keypair (x509_encode_csr_build()/x509_csr_sign()) and POSTs it to
 *      `/sen`.
 *   3. Verifies the returned C509 Type-2 cert's signature against the CA's
 *      public key (c509_csr_verify_pop(), reused for generic ECDSA-SHA256
 *      TBS/signature verification) and prints TEST PASSED/FAILED.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"    /* NETSTACK_ROUTING.get_root_ipaddr (EDHOC_CONF_SERVER_FROM_ROOT) */
#include "net/ipv6/simple-udp.h"
#include "coap-engine.h"
#include "edhoc-client.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-cred-c509-native-test.h"
#include "edhoc-cred-c509.h"
#include "edhoc-trust-store.h"
#include "oscore.h"
#include "bench-stats.h"     /* Welford stats: mean/median/p95/sd over N iters */
#include "c509-chain.h"
#include "c509_registry.h"
#include "c509-csr-build.h"
#include "c509-csr-parse.h"
/* ENROLL_X509_DYN implies ENROLL_X509 (same enlarged buffers + X.509 downlink
 * validation) but additionally POSTs a real PKCS#10 DER CSR on /sen instead of
 * the compact C509 Type-3 CSR — the fully-faithful X.509 enrollment uplink. */
#ifdef ENROLL_X509_DYN
#ifndef ENROLL_X509
#define ENROLL_X509 1
#endif
/* cbor-free shim exposing c509_csr_to_pkcs10_der() — keeps the c509/os-lib
 * cbor.h collision out of this TU (same rationale as the crts server). */
#include "c509-x509-wrap.h"
/* minimal PKCS#10 parser — used to locate the reconstructed CertificationRequestInfo
 * so the client can sign exactly those bytes (a genuine PKCS#10 self-signature). */
#include "x509-csr-parse.h"
#endif

#include "sys/log.h"
#define LOG_MODULE "OscoreCrts-Cl"
/* Quiet by default so blocking console I/O does not inflate the timed enrollment
 * (Exp H2 wall-clock). Verdict lines are raw printf() below, so they survive the
 * silenced log level (and the emul validators still match). -DENROLL_DEBUG restores
 * the full progress trace. */
#ifdef ENROLL_DEBUG
#define LOG_LEVEL  LOG_LEVEL_INFO
#else
#define LOG_LEVEL  LOG_LEVEL_ERR
#endif

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

#define COAP_CODE_GET     0x01
#define COAP_CODE_POST    0x02
#define COAP_CODE_CREATED 0x41
#define COAP_CODE_CONTENT 0x45

/* CA public key, for verifying the cert issued over /sen — same trust
 * anchor (C509_NATIVE_CA_PUB_X/Y) used to build the c509 trust store below,
 * in 65-byte uncompressed `0x04||X||Y` form. (Unused in the ENROLL_X509 trial,
 * which validates DER-completeness rather than the signature.) */
#ifndef ENROLL_X509
static const uint8_t ca_pub_key[] = {
  0x04,
  0xb7, 0x9e, 0x3d, 0x7d, 0xcf, 0xa3, 0xf1, 0x11,
  0x81, 0xf4, 0x6f, 0x24, 0x7a, 0xf5, 0x6c, 0x06,
  0x7b, 0x0e, 0xf5, 0x32, 0x50, 0xfc, 0x18, 0xe9,
  0xbe, 0x82, 0xc2, 0x3e, 0x6f, 0x83, 0x3f, 0xee,
  0x89, 0x24, 0x70, 0x41, 0x63, 0x7a, 0x86, 0x44,
  0x2f, 0x45, 0x8b, 0x78, 0xa5, 0xc4, 0x39, 0x60,
  0xbb, 0xac, 0xcc, 0x3e, 0xb1, 0x4c, 0x89, 0xe5,
  0xae, 0x9a, 0xda, 0xf4, 0xf7, 0x94, 0x55, 0x30
};
#endif /* !ENROLL_X509 */

typedef enum {
  CLIENT_STATE_NONE = 0,
  CLIENT_STATE_AWAIT_CRTS,
  CLIENT_STATE_AWAIT_SEN
} client_state_t;

static struct simple_udp_connection oscore_udp;
static oscore_security_context_t client_oscore;
static bool oscore_ready = false;
static client_state_t client_state = CLIENT_STATE_NONE;
static uip_ipaddr_t saved_server_addr;

static uint8_t saved_piv[OSCORE_MAX_PIV_LEN];
static uint8_t saved_piv_len;
static uint8_t saved_kid[OSCORE_MAX_ID_LEN];
static uint8_t saved_kid_len;

static cose_key_t client_key;

/* Enrollment request recovery (restart-on-failure): on a response timeout the
 * outstanding /crts or /sen request is retransmitted with a fresh OSCORE PIV
 * (a new oscore_protect_request call — a byte-identical resend would be dropped
 * by the receiver's replay window). The signed CSR is cached so a /sen retry is
 * byte-identical, which the server treats idempotently (no duplicate issuance).
 * The retransmit timer/backoff is driven by the process; the UDP callback only
 * advances the state machine and polls the process. */
#ifndef ENROLL_MAX_RETX
#define ENROLL_MAX_RETX 5
#endif
#ifndef ENROLL_RETX_T0
#define ENROLL_RETX_T0 (2 * CLOCK_SECOND)
#endif
#ifdef ENROLL_X509_DYN
static uint8_t g_csr[512];   /* PKCS#10 DER CSR (~380 B) needs more than 256 */
#else
static uint8_t g_csr[256];
#endif
static size_t  g_csr_len = 0;
static volatile bool g_advanced = false;      /* callback advanced the FSM */
static volatile bool g_enroll_done = false;
static volatile bool g_enroll_failed = false;

/* Enrollment wall-clock instrumentation (Exp H2, on real silicon). Timed with
 * RTIMER via bench-stats (wrap-safe us), split into the EDHOC handshake vs the
 * post-handshake /crts+/sen enrollment, aggregated over ENROLL_ITERS runs. */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "unstamped"
#endif
#ifdef ENROLL_X509
#define ENROLL_ARM "x509"
#else
#define ENROLL_ARM "c509"
#endif

PROCESS_NAME(edhoc_oscore_crts_client);

static void send_oscore_post_request(const uip_ipaddr_t *server_addr,
                                      const uint8_t *payload, size_t payload_len);

#ifdef ENROLL_X509
/* X.509-DER enrollment trial: the /crts and /sen responses are full X.509 DER
 * certificates (not compact C509). Validate that a complete DER SEQUENCE arrived
 * (header + declared body == received length) — i.e. the whole ~380 B flight was
 * reassembled over the multi-hop path. This is the delivery/size measurement; the
 * cryptographic path is already exercised by the C509 enrollment. */
static bool
der_seq_complete(const uint8_t *p, size_t len)
{
  if(len < 2 || p[0] != 0x30) {
    return false;
  }
  size_t hdr, body;
  if(p[1] < 0x80) { hdr = 2; body = p[1]; }
  else if(p[1] == 0x81 && len >= 3) { hdr = 3; body = p[2]; }
  else if(p[1] == 0x82 && len >= 4) { hdr = 4; body = ((size_t)p[2] << 8) | p[3]; }
  else { return false; }
  return hdr + body == len;
}
#endif
static size_t build_and_sign_csr(const cose_key_t *key, uint8_t *csr_buf, size_t csr_buf_size);

/*---------------------------------------------------------------------------*/
static void
oscore_response_callback(struct simple_udp_connection *c,
                          const uip_ipaddr_t *source_addr, uint16_t source_port,
                          const uip_ipaddr_t *dest_addr, uint16_t dest_port,
                          const uint8_t *data, uint16_t datalen)
{
  if(!oscore_ready) {
    LOG_WARN("Response arrived before OSCORE context ready — ignored\n");
    return;
  }
  if(datalen < 1 + OSCORE_TAG_LEN + 1) {
    LOG_WARN("Response too short (%u bytes)\n", datalen);
    return;
  }
  uint8_t opt_len = data[0];
  if(opt_len != 0) {
    LOG_WARN("Unexpected non-empty response OSCORE option (len=%u)\n", opt_len);
  }

  const uint8_t *ciphertext = data + 1;
  size_t ciphertext_len = datalen - 1;

#ifdef ENROLL_X509
  uint8_t plaintext[640];   /* X.509 DER cert responses are ~390 B */
#else
  uint8_t plaintext[256];
#endif
  size_t plaintext_len = sizeof(plaintext);
  int err = oscore_unprotect_response(&client_oscore,
                                       ciphertext, ciphertext_len,
                                       saved_piv, saved_piv_len,
                                       saved_kid, saved_kid_len,
                                       plaintext, &plaintext_len);
  if(err < 0) {
    LOG_ERR("OSCORE unprotect response failed: %d\n", err);
    return;
  }

  if(plaintext_len < 1) { return; }
  uint8_t code = plaintext[0];
  const uint8_t *payload = NULL;
  size_t payload_len = 0;
  if(plaintext_len > 2 && plaintext[1] == 0xFF) {
    payload = plaintext + 2;
    payload_len = plaintext_len - 2;
  }

  LOG_INFO("OSCORE response OK: code=0x%02x, payload=%zu bytes\n", code, payload_len);

  if(client_state == CLIENT_STATE_AWAIT_CRTS) {
    if(code != COAP_CODE_CONTENT || payload == NULL) {
      LOG_WARN("/crts: unexpected response code 0x%02x or empty payload\n", code);
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED ===\n");
      client_state = CLIENT_STATE_NONE;
      g_enroll_failed = true;
      process_poll(&edhoc_oscore_crts_client);
      return;
    }

#ifdef ENROLL_X509
    /* X.509 DER CA cert (bare): confirm the full DER flight reassembled. */
    if(!der_seq_complete(payload, payload_len)) {
      LOG_ERR("/crts: X.509 DER CA cert malformed/incomplete (%zu bytes)\n", payload_len);
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED (crts) ===\n");
      client_state = CLIENT_STATE_NONE;
      g_enroll_failed = true;
      process_poll(&edhoc_oscore_crts_client);
      return;
    }
    LOG_INFO("/crts: received complete X.509 DER CA cert (%zu bytes)\n", payload_len);
#else
    /* Decode the CertificateChain and validate every element. */
    c509_chain_entry_t chain_entries[4];
    size_t n_certs = 0;

    if(c509_chain_decode(payload, payload_len, chain_entries, 4, &n_certs) != 0) {
      LOG_ERR("c509_chain_decode failed\n");
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED ===\n");
      client_state = CLIENT_STATE_NONE;
      g_enroll_failed = true;
      process_poll(&edhoc_oscore_crts_client);
      return;
    }

    LOG_INFO("Decoded CertificateChain with %zu element(s)\n", n_certs);

    bool all_valid = true;
    for(size_t i = 0; i < n_certs; i++) {
      edhoc_error_t res = edhoc_c509_validate_chain(chain_entries[i].ptr,
                                                     chain_entries[i].len,
                                                     NULL);
      if(res == EDHOC_SUCCESS) {
        LOG_INFO("EDHOC-C509: crts: chain[%zu] verified by trust anchor 0\n", i);
      } else {
        LOG_INFO("EDHOC-C509: crts: chain[%zu] FAIL (%d)\n", i, res);
        all_valid = false;
      }
    }

    if(!all_valid || n_certs == 0) {
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED (crts) ===\n");
      client_state = CLIENT_STATE_NONE;
      return;
    }
#endif

    /* Phase 3.3 step 3-4: build+sign a CSR for our own key and POST it to
     * /sen. Cache it (g_csr) so a /sen retransmit is byte-identical -> the
     * server returns the same cert idempotently. */
    g_csr_len = build_and_sign_csr(&client_key, g_csr, sizeof(g_csr));
    if(g_csr_len == 0) {
      LOG_ERR("CSR build/sign failed\n");
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED ===\n");
      client_state = CLIENT_STATE_NONE;
      g_enroll_failed = true;
      process_poll(&edhoc_oscore_crts_client);
      return;
    }

    client_state = CLIENT_STATE_AWAIT_SEN;
    send_oscore_post_request(&saved_server_addr, g_csr, g_csr_len);
    g_advanced = true;                       /* new step -> reset the retx timer */
    process_poll(&edhoc_oscore_crts_client);
    return;
  }

  if(client_state == CLIENT_STATE_AWAIT_SEN) {
    if(code != COAP_CODE_CREATED || payload == NULL || payload_len < 2 + 64) {
      LOG_WARN("/sen: unexpected response code 0x%02x or short payload (%zu bytes)\n",
               code, payload_len);
      printf("=== EDHOC OSCORE enroll end-to-end test FAILED (sen) ===\n");
      client_state = CLIENT_STATE_NONE;
      g_enroll_failed = true;
      process_poll(&edhoc_oscore_crts_client);
      return;
    }

#ifdef ENROLL_X509
    /* X.509 DER issued cert: confirm the full DER flight reassembled. */
    if(der_seq_complete(payload, payload_len)) {
      LOG_INFO("/sen: received complete X.509 DER issued cert (%zu bytes)\n", payload_len);
      printf("=== EDHOC OSCORE enroll end-to-end test: TEST PASSED ===\n");
      g_enroll_done = true;
    } else {
      LOG_INFO("/sen: X.509 DER issued cert malformed/incomplete (%zu bytes)\n", payload_len);
      printf("=== EDHOC OSCORE enroll end-to-end test: TEST FAILED (sen) ===\n");
      g_enroll_failed = true;
    }
#else
    /* The issued cert is a flat C509 Type-2 sequence ending in a 2-byte
     * bstr(64) header (0x58 0x40) + 64-byte sigValue. Verify it against the
     * CA's public key — c509_csr_verify_pop() is generic ECDSA-SHA256
     * TBS/signature verification, reused here for the issued cert. */
    size_t tbs_len = payload_len - 2 - 64;
    const uint8_t *sig = payload + payload_len - 64;

    if(c509_csr_verify_pop(payload, tbs_len, ca_pub_key, sizeof(ca_pub_key),
                            sig, 64) == 0) {
      LOG_INFO("/sen: issued %zu-byte cert verified against CA public key\n", payload_len);
      printf("=== EDHOC OSCORE enroll end-to-end test: TEST PASSED ===\n");
      g_enroll_done = true;
    } else {
      LOG_INFO("/sen: issued cert signature verification FAILED\n");
      printf("=== EDHOC OSCORE enroll end-to-end test: TEST FAILED (sen) ===\n");
      g_enroll_failed = true;
    }
#endif
    client_state = CLIENT_STATE_NONE;
    process_poll(&edhoc_oscore_crts_client);
    return;
  }

  LOG_WARN("Unexpected response in state %d (code=0x%02x)\n", client_state, code);
}
/*---------------------------------------------------------------------------*/
static void
send_oscore_request(const uip_ipaddr_t *server_addr)
{
  uint8_t inner[1];
  inner[0] = COAP_CODE_GET;

  uint8_t oscore_opt[OSCORE_OPT_MAX_LEN];
  size_t oscore_opt_len = sizeof(oscore_opt);
  uint8_t ciphertext[sizeof(inner) + OSCORE_TAG_LEN];
  size_t ciphertext_len = sizeof(ciphertext);

  int err = oscore_protect_request(&client_oscore,
                                    inner, sizeof(inner),
                                    oscore_opt, &oscore_opt_len,
                                    ciphertext, &ciphertext_len);
  if(err < 0) {
    LOG_ERR("oscore_protect_request failed: %d\n", err);
    return;
  }

  uint8_t n = oscore_opt[0] & 0x07;
  saved_piv_len = n;
  memcpy(saved_piv, oscore_opt + 1, n);
  saved_kid_len = (uint8_t)(oscore_opt_len - 1 - n);
  memcpy(saved_kid, oscore_opt + 1 + n, saved_kid_len);

  uint8_t pkt[1 + OSCORE_OPT_MAX_LEN + sizeof(inner) + OSCORE_TAG_LEN];
  size_t pos = 0;
  pkt[pos++] = (uint8_t)oscore_opt_len;
  memcpy(pkt + pos, oscore_opt, oscore_opt_len); pos += oscore_opt_len;
  memcpy(pkt + pos, ciphertext, ciphertext_len); pos += ciphertext_len;

  LOG_INFO("Sending OSCORE GET /crts (%zu bytes UDP)\n", pos);
  simple_udp_sendto(&oscore_udp, pkt, pos, server_addr);
}
/*---------------------------------------------------------------------------*/
static void
send_oscore_post_request(const uip_ipaddr_t *server_addr,
                          const uint8_t *payload, size_t payload_len)
{
  uint8_t inner[2 + 256];
  inner[0] = COAP_CODE_POST;
  inner[1] = 0xFF;
  memcpy(inner + 2, payload, payload_len);
  size_t inner_len = 2 + payload_len;

  uint8_t oscore_opt[OSCORE_OPT_MAX_LEN];
  size_t oscore_opt_len = sizeof(oscore_opt);
  uint8_t ciphertext[sizeof(inner) + OSCORE_TAG_LEN];
  size_t ciphertext_len = sizeof(ciphertext);

  int err = oscore_protect_request(&client_oscore,
                                    inner, inner_len,
                                    oscore_opt, &oscore_opt_len,
                                    ciphertext, &ciphertext_len);
  if(err < 0) {
    LOG_ERR("oscore_protect_request (POST /sen) failed: %d\n", err);
    return;
  }

  uint8_t n = oscore_opt[0] & 0x07;
  saved_piv_len = n;
  memcpy(saved_piv, oscore_opt + 1, n);
  saved_kid_len = (uint8_t)(oscore_opt_len - 1 - n);
  memcpy(saved_kid, oscore_opt + 1 + n, saved_kid_len);

  uint8_t pkt[1 + OSCORE_OPT_MAX_LEN + sizeof(inner) + OSCORE_TAG_LEN];
  size_t pos = 0;
  pkt[pos++] = (uint8_t)oscore_opt_len;
  memcpy(pkt + pos, oscore_opt, oscore_opt_len); pos += oscore_opt_len;
  memcpy(pkt + pos, ciphertext, ciphertext_len); pos += ciphertext_len;

  LOG_INFO("Sending OSCORE POST /sen (%zu bytes UDP, CSR %zu bytes)\n", pos, payload_len);
  simple_udp_sendto(&oscore_udp, pkt, pos, server_addr);
}
/*---------------------------------------------------------------------------*/
/* Builds and self-signs a C509 Type-3 CSR for this client's own EDHOC
 * keypair using x509_encode_csr_build()/x509_csr_sign() (LICE/C509
 * enrollment plan, Phase 2/3.3). Returns the CSR length, or 0 on failure. */
static size_t
build_and_sign_csr(const cose_key_t *key, uint8_t *csr_buf, size_t csr_buf_size)
{
  size_t tbs_len = 0;
  uint8_t pk_key[65];
  static const uint8_t subject[] = "edhoc-client";
  pk_key[0] = 0x04;
  memcpy(pk_key + 1, key->ecc.pub.x, 32);
  memcpy(pk_key + 33, key->ecc.pub.y, 32);

#ifdef ENROLL_X509_DYN
  /* Fully-faithful X.509 uplink: emit a genuinely self-signed PKCS#10 DER CSR.
   *
   * x509_encode_csr() only transcodes a C509 CSR's fields to DER, copying its
   * sigValue verbatim — but a C509 CSR is signed over its *C509 TBS*, which is
   * not the PKCS#10 CertificationRequestInfo (CRI) bytes, so a straight copy
   * would not verify. So: (1) build the C509 CSR (placeholder sig) and transcode
   * it to obtain the exact CRI bytes; (2) sign those CRI bytes; (3) inject the
   * signature into the C509 CSR's sigValue and transcode again. The CRI does not
   * depend on sigValue, so the second transcode's signature covers the same CRI
   * the server will hash. */
  {
    uint8_t c509_csr[256];
    uint8_t pkcs10_tmp[512];
    size_t c509_len = 0, tmp_len = 0, der_len = 0;

    if(x509_encode_csr_build(c509_csr, sizeof(c509_csr), &c509_len,
                             subject, sizeof(subject) - 1,
                             C509_PK_SECP256R1,
                             pk_key, sizeof(pk_key), &tbs_len) != 0) {
      LOG_ERR("CSR build failed\n");
      return 0;
    }
    /* pass 1: transcode (placeholder sig) to obtain the CRI bytes */
    if(c509_csr_to_pkcs10_der(c509_csr, c509_len,
                              pkcs10_tmp, sizeof(pkcs10_tmp), &tmp_len) != 0) {
      LOG_ERR("PKCS#10 CSR conversion (pass 1) failed\n");
      return 0;
    }
    const uint8_t *subj, *pk, *cri; size_t subj_l, pk_l, cri_l; uint8_t junk_rs[64];
    if(x509_csr_parse(pkcs10_tmp, tmp_len, &subj, &subj_l, &pk, &pk_l,
                      &cri, &cri_l, junk_rs) != 0) {
      LOG_ERR("PKCS#10 CRI locate failed\n");
      return 0;
    }
    /* sign the CRI and inject r||s into the C509 CSR's sigValue placeholder */
    uint8_t rs[64];
    if(x509_csr_sign_msg(cri, cri_l, key->ecc.priv, sizeof(key->ecc.priv), rs) != 0) {
      LOG_ERR("CRI sign failed\n");
      return 0;
    }
    memcpy(c509_csr + c509_len - 64, rs, 64);
    /* pass 2: transcode with the real signature -> genuinely self-signed CSR */
    if(c509_csr_to_pkcs10_der(c509_csr, c509_len,
                              csr_buf, csr_buf_size, &der_len) != 0) {
      LOG_ERR("PKCS#10 CSR conversion (pass 2) failed\n");
      return 0;
    }
    LOG_INFO("Built %zu-byte C509 CSR -> %zu-byte self-signed PKCS#10 DER CSR\n",
             c509_len, der_len);
    return der_len;
  }
#else
  size_t offset = 0;
  if(x509_encode_csr_build(csr_buf, csr_buf_size, &offset,
                            subject, sizeof(subject) - 1,
                            C509_PK_SECP256R1,
                            pk_key, sizeof(pk_key), &tbs_len) != 0) {
    LOG_ERR("CSR build failed\n");
    return 0;
  }

  if(x509_csr_sign(csr_buf, tbs_len, offset,
                    key->ecc.priv, sizeof(key->ecc.priv)) != 0) {
    LOG_ERR("CSR sign failed\n");
    return 0;
  }

  LOG_INFO("Built+signed %zu-byte CSR: ", offset);
  for(size_t i = 0; i < offset; i++) {
    LOG_INFO_("%02x", csr_buf[i]);
  }
  LOG_INFO_("\n");

  return offset;
#endif
}
/*---------------------------------------------------------------------------*/
/* Statistical enrollment benchmark (Exp H2): repeat the full EDHOC + /crts + /sen
 * enrollment ENROLL_ITERS times and keep incremental (Welford) stats, so the FINAL
 * lines alone give n / mean / median / p95 / sd / min / max. A single functional
 * pass (the old single-shot) is ENROLL_ITERS=1. */
#ifndef ENROLL_ITERS
#define ENROLL_ITERS 20
#endif
/* Per-iteration hard cap on the EDHOC handshake so a stuck iteration cannot hang
 * the whole run on the protocol's internal retry budget. */
#ifndef ENROLL_HS_DEADLINE_S
#define ENROLL_HS_DEADLINE_S 30
#endif
/* dbg flag stamped into the FINAL line: 1 = verbose logging compiled in (inflates
 * timing), 0 = quiet. Mirrors the bench convention so a pasted result is never
 * silently mis-read. */
#ifdef ENROLL_DEBUG
#define ENROLL_DBG 1
#else
#define ENROLL_DBG 0
#endif

PROCESS(edhoc_oscore_crts_client, "EDHOC OSCORE /crts Client");
AUTOSTART_PROCESSES(&edhoc_oscore_crts_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_oscore_crts_client, ev, data)
{
  static struct etimer timer;
  static struct etimer retx_timer;
  static struct etimer hs_deadline;
  static struct etimer settle;
  static uint8_t enroll_attempt;
  static unsigned iter;
  static bool hs_ok, iter_ok;
  /* Three metrics, each with its own incremental stats + samples buffer for the
   * median/p95: total enrollment, the EDHOC handshake, and the post-handshake
   * /crts+/sen exchange. */
  static bench_stats_t st_total, st_edhoc, st_crtssen;
  static uint32_t s_total[ENROLL_ITERS], s_edhoc[ENROLL_ITERS], s_crtssen[ENROLL_ITERS];
  static rtimer_clock_t rt_start, rt_edhoc, rt_end;
  static cose_key_t server_key;

  /* CA trust anchor (same for every iteration). */
  static const cose_key_t ca_anchor = {
    .kty = 2, .crv = 1,
    .ecc = {
      .priv = { 0 },
      .pub  = {
        .x = C509_NATIVE_CA_PUB_X,
        .y = C509_NATIVE_CA_PUB_Y
      }
    }
  };

  PROCESS_BEGIN();

  simple_udp_register(&oscore_udp, OSCORE_UDP_PORT, NULL, OSCORE_UDP_PORT,
                       oscore_response_callback);

  etimer_set(&timer, CLOCK_SECOND * 5);
  while(1) {
    if(NETSTACK_ROUTING.node_is_reachable()) {
      LOG_INFO("Network ready\n");
      break;
    }
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }

  /* Multi-hop settle (build-time; default 0 = no delay for single-hop). Lets the RPL
   * downward route (for the responses) and per-hop TSCH slots settle before the
   * EDHOC handshake + /crts + /sen. Mirrors the c5t handshake client. */
#ifndef MULTIHOP_CONNECT_DELAY_S
#define MULTIHOP_CONNECT_DELAY_S 0
#endif
#if MULTIHOP_CONNECT_DELAY_S > 0
  LOG_INFO("Multi-hop connect delay %d s...\n", MULTIHOP_CONNECT_DELAY_S);
  etimer_set(&timer, CLOCK_SECOND * MULTIHOP_CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
#endif

  printf("[ENROLL-BENCH] starting arm:%s fw:%s iters:%d\n",
         ENROLL_ARM, FW_BUILD_ID, ENROLL_ITERS);
  bench_stats_init(&st_total);
  bench_stats_init(&st_edhoc);
  bench_stats_init(&st_crtssen);

  for(iter = 0; iter < ENROLL_ITERS; iter++) {
    /* Recover before each iteration: RPL churn or a prior failure may have dropped
     * the route -- wait until the root is reachable again. */
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      etimer_set(&timer, CLOCK_SECOND * 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    }

    /* (Re)build the credential key list each iteration -- edhoc_create_key_list
     * re-initialises it, a clean per-iteration setup (mirrors edhoc-c5t-bench). */
    if(edhoc_create_key_list() != EDHOC_SUCCESS) {
      LOG_ERR("edhoc_create_key_list failed\n");
      break;
    }
    /* Own key (Initiator): cert pre-provisioned so the c5t hash can be computed. */
    memcpy(&client_key, &auth_c509_native_client_template, sizeof(cose_key_t));
    c509_native_client_attach_cert(&client_key);
    /* Peer key (Responder): cert pre-provisioned so received hash can be resolved. */
    memcpy(&server_key, &auth_c509_native_server_template, sizeof(cose_key_t));
    memset(server_key.ecc.priv, 0, sizeof(server_key.ecc.priv));
    c509_native_server_attach_cert(&server_key);
    if(edhoc_add_key(&client_key) != EDHOC_SUCCESS ||
       edhoc_add_key(&server_key) != EDHOC_SUCCESS) {
      LOG_ERR("Failed to add EDHOC keys\n");
      break;
    }
    edhoc_set_c509_trust_store(&ca_anchor, 1);
    edhoc_set_cert_validator(edhoc_c509_validate_chain, NULL);

    /* --- timed EDHOC handshake --- */
    hs_ok = false;
    iter_ok = false;
    oscore_ready = false;
    g_enroll_done = false;
    g_enroll_failed = false;
    enroll_attempt = 0;
    rt_start = bench_time_now();       /* H2: enrollment wall-clock starts */
    edhoc_client_run();
    etimer_set(&hs_deadline, CLOCK_SECOND * ENROLL_HS_DEADLINE_S);
    while(1) {
      PROCESS_WAIT_EVENT();
      int8_t ret = edhoc_client_callback(ev, data);
      if(ret > 0) { rt_edhoc = bench_time_now(); hs_ok = true; break; }
      if(ret < 0) { LOG_ERR("EDHOC failure: %d\n", ret); break; }
      if(etimer_expired(&hs_deadline)) {
        LOG_ERR("enroll: handshake deadline (%d s)\n", ENROLL_HS_DEADLINE_S);
        break;
      }
    }

    if(hs_ok) {
      LOG_INFO("EDHOC finished\n");
      oscore_ctx_t edhoc_out;
      if(edhoc_exporter_oscore(&edhoc_out, edhoc_ctx) >= 0 &&
         oscore_derive_context(&client_oscore, &edhoc_out) >= 0) {
        oscore_ready = true;

        static coap_endpoint_t server_ep;
        coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
#ifdef EDHOC_CONF_SERVER_FROM_ROOT
        /* /crts + /sen target = RPL root (the CA/responder); resolve dynamically
         * to match the EDHOC handshake fix (platform-derived node addressing). */
        {
          uip_ipaddr_t enroll_root_ipaddr;
          if(NETSTACK_ROUTING.get_root_ipaddr(&enroll_root_ipaddr)) {
            uip_ipaddr_copy(&server_ep.ipaddr, &enroll_root_ipaddr);
          }
        }
#endif /* EDHOC_CONF_SERVER_FROM_ROOT */
        uip_ipaddr_copy(&saved_server_addr, &server_ep.ipaddr);

        etimer_set(&timer, CLOCK_SECOND / 2);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

        /* Enrollment with restart-on-failure: send /crts, then retransmit the
         * outstanding request (fresh OSCORE PIV) on a response timeout, bounded
         * by ENROLL_MAX_RETX with exponential backoff. The callback advances the
         * state machine (/crts -> /sen -> done) and polls us; g_advanced resets
         * the timer for each new step. */
        client_state = CLIENT_STATE_AWAIT_CRTS;
        g_advanced = false;
        send_oscore_request(&saved_server_addr);
        etimer_set(&retx_timer, ENROLL_RETX_T0);

        while(!g_enroll_done && !g_enroll_failed) {
          PROCESS_WAIT_EVENT();
          if(g_advanced) {
            g_advanced = false;
            enroll_attempt = 0;
            etimer_set(&retx_timer, ENROLL_RETX_T0);
            continue;
          }
          if(etimer_expired(&retx_timer)) {
            const char *what = (client_state == CLIENT_STATE_AWAIT_CRTS) ? "/crts" : "/sen";
            if(enroll_attempt < ENROLL_MAX_RETX) {
              enroll_attempt++;
              LOG_WARN("Enrollment %s response timeout — retransmit attempt %u\n",
                       what, enroll_attempt);
              if(client_state == CLIENT_STATE_AWAIT_CRTS) {
                send_oscore_request(&saved_server_addr);
              } else if(client_state == CLIENT_STATE_AWAIT_SEN) {
                send_oscore_post_request(&saved_server_addr, g_csr, g_csr_len);
              }
              /* exponential backoff, capped at 8*T0 */
              etimer_set(&retx_timer,
                         ENROLL_RETX_T0 << (enroll_attempt < 3 ? enroll_attempt : 3));
            } else {
              LOG_ERR("Enrollment %s retransmit budget exhausted\n", what);
              printf("=== EDHOC OSCORE enroll end-to-end test FAILED (timeout) ===\n");
              g_enroll_failed = true;
            }
          }
        }
        if(g_enroll_done) {
          rt_end = bench_time_now();
          iter_ok = true;
        }
      } else {
        LOG_ERR("OSCORE context derivation failed\n");
      }
    }

    /* Record this iteration. Split: total, EDHOC handshake, and /crts+/sen. */
    if(iter_ok) {
      uint32_t total_us   = bench_elapsed_us(rt_start, rt_end);
      uint32_t edhoc_us   = bench_elapsed_us(rt_start, rt_edhoc);
      uint32_t crtssen_us = bench_elapsed_us(rt_edhoc, rt_end);
      s_total[st_total.n]       = total_us;
      s_edhoc[st_edhoc.n]       = edhoc_us;
      s_crtssen[st_crtssen.n]   = crtssen_us;
      bench_stats_add_us(&st_total,   total_us,   enroll_attempt);
      bench_stats_add_us(&st_edhoc,   edhoc_us,   0);
      bench_stats_add_us(&st_crtssen, crtssen_us, enroll_attempt);
      printf("[ENROLL-TIMING fw:%s arm:%s iter:%u ok:1] edhoc_ms=%lu.%03lu "
             "crts_sen_ms=%lu.%03lu total_ms=%lu.%03lu\n",
             FW_BUILD_ID, ENROLL_ARM, iter,
             BENCH_MS_INT(edhoc_us),   BENCH_MS_FRAC(edhoc_us),
             BENCH_MS_INT(crtssen_us), BENCH_MS_FRAC(crtssen_us),
             BENCH_MS_INT(total_us),   BENCH_MS_FRAC(total_us));
    } else {
      bench_stats_add_fail(&st_total);
      bench_stats_add_fail(&st_edhoc);
      bench_stats_add_fail(&st_crtssen);
      printf("[ENROLL-TIMING fw:%s arm:%s iter:%u ok:0]\n",
             FW_BUILD_ID, ENROLL_ARM, iter);
    }

    edhoc_client_close();

    /* Settle before the next iteration; longer after a failure so RPL/ETX can heal
     * before hammering the link again. */
    etimer_set(&settle, CLOCK_SECOND * (iter_ok ? 3 : 8));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&settle));
  }

  /* Three self-contained result lines (copy for the run's statistics). Integer-only
   * reduction from the stored samples -- robust on the cooja-ng emulator's soft-float
   * `double` path (which corrupts the Welford mean) and exact on real HW alike. */
  bench_stats_print_final_int("enroll-total-"   ENROLL_ARM, s_total,
                              st_total.n,   st_total.fail,   0, bench_rpl_hops(), ENROLL_DBG);
  bench_stats_print_final_int("enroll-edhoc-"   ENROLL_ARM, s_edhoc,
                              st_edhoc.n,   st_edhoc.fail,   0, bench_rpl_hops(), ENROLL_DBG);
  bench_stats_print_final_int("enroll-crtssen-" ENROLL_ARM, s_crtssen,
                              st_crtssen.n, st_crtssen.fail, 0, bench_rpl_hops(), ENROLL_DBG);
  printf("=== ENROLL-BENCH %s DONE: %lu ok / %lu fail of %d ===\n",
         ENROLL_ARM, (unsigned long)st_total.n, (unsigned long)st_total.fail,
         ENROLL_ITERS);

  LOG_INFO("Client done\n");
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
