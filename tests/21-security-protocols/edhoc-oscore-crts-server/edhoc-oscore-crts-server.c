/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE `/crts` + `/sen` test server — native C509 Type 2, c5t
 *   mode.
 *
 *   After the EDHOC+OSCORE handshake:
 *   - any OSCORE GET (`/crts`) is answered with a CertificateChain
 *     (`[+ bstr]`, RFC 8949 array of byte strings) containing the CA's
 *     C509 trust-anchor certificate (`c509_native_ca_cert`), encoded via
 *     `c509_chain_encode()`.
 *   - any OSCORE POST (`/sen`, LICE/C509 enrollment plan Phase 3.2) carries
 *     a C509 Type-3 CSR as its payload. The CSR's proof-of-possession
 *     self-signature is verified (c509_csr_verify_pop()), and on success a
 *     new C509 Type-2 cert is issued for the CSR's subject/key
 *     (c509_ca_issue_cert()) and returned bare (2.01 Created) — or 4.00 Bad
 *     Request if PoP verification or parsing fails.
 *
 *   This single raw-OSCORE callback dispatches on the inner CoAP code
 *   (GET vs. POST) rather than on the URI path — there is only one
 *   resource of each kind, so a full coap-engine resource isn't needed
 *   here (see PLAN-c509-enrollment-phases1-3.md, 3.2).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#if MAC_CONF_WITH_TSCH
#include "net/mac/tsch/tsch.h"     /* the root must also be the TSCH coordinator */
#endif
#include "net/ipv6/simple-udp.h"
#include "edhoc-server.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-cred-c509-native-test.h"
#include "edhoc-cred-c509.h"
#include "edhoc-trust-store.h"
#include "oscore.h"
#include "c509-chain.h"
#include "c509-csr-parse.h"
#include "c509-ca.h"
#include "c509_registry.h"

#include "sys/log.h"
#define LOG_MODULE "OscoreCrts-Sv"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

#define COAP_CODE_GET      0x01
#define COAP_CODE_POST     0x02
#define COAP_CODE_CREATED  0x41
#define COAP_CODE_CONTENT  0x45
#define COAP_CODE_BAD_REQUEST 0x80

/* CA identity for /sen issuance — same test credential as
 * tests/07-c509/test-c509.c's run_ca_issue_test() and
 * CBOR-certificates/c509_demo_impl/src/generate.rs::CA_PRIVATE_KEY. */
static const uint8_t ca_priv_key_d[] = {
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f
};
static const uint8_t ca_issuer_name[] = "EDHOC-Test-CA";
static const uint8_t issued_serial[] = { 0x05 };
#define ISSUED_NOT_BEFORE 1700000000
#define ISSUED_NOT_AFTER  2000000000

/* /sen idempotency cache (restart-on-failure recovery): remembers the last CSR
 * issued and the cert returned for it, so a client that retransmits /sen after
 * losing our response gets the SAME cert back instead of a duplicate issuance
 * (the CA signs with fresh randomness, so re-issuing would differ). A single
 * entry suffices for the one-client enrollment test; generalise to a small LRU
 * for a multi-client CA. */
static uint8_t g_last_csr[256];
static size_t  g_last_csr_len = 0;
static uint8_t g_last_cert[256];
static size_t  g_last_cert_len = 0;

static struct simple_udp_connection oscore_udp;
static oscore_security_context_t server_oscore;
static bool oscore_ready = false;

/*---------------------------------------------------------------------------*/
static void
oscore_request_callback(struct simple_udp_connection *c,
                         const uip_ipaddr_t *source_addr, uint16_t source_port,
                         const uip_ipaddr_t *dest_addr, uint16_t dest_port,
                         const uint8_t *data, uint16_t datalen)
{
  if(!oscore_ready) {
    LOG_WARN("Request arrived before OSCORE context ready — ignored\n");
    return;
  }
  if(datalen < 2) {
    LOG_WARN("Request too short (%u bytes)\n", datalen);
    return;
  }
  uint8_t opt_len = data[0];
  if(1 + opt_len >= datalen) {
    LOG_WARN("opt_len %u overflows packet\n", opt_len);
    return;
  }

  const uint8_t *oscore_opt = data + 1;
  const uint8_t *ciphertext = data + 1 + opt_len;
  size_t ciphertext_len = datalen - 1 - opt_len;

  uint8_t plaintext[256];
  size_t plaintext_len = sizeof(plaintext);
  uint8_t req_piv[OSCORE_MAX_PIV_LEN];
  uint8_t req_piv_len = 0;
  uint8_t req_kid[OSCORE_MAX_ID_LEN];
  uint8_t req_kid_len = 0;

  int err = oscore_unprotect_request(&server_oscore,
                                      oscore_opt, opt_len,
                                      ciphertext, ciphertext_len,
                                      plaintext, &plaintext_len,
                                      req_piv, &req_piv_len,
                                      req_kid, &req_kid_len);
  if(err < 0) {
    LOG_ERR("OSCORE unprotect request failed: %d\n", err);
    return;
  }

  if(plaintext_len < 1) { return; }
  uint8_t code = plaintext[0];
  const uint8_t *req_payload = NULL;
  size_t req_payload_len = 0;
  if(plaintext_len > 2 && plaintext[1] == 0xFF) {
    req_payload = plaintext + 2;
    req_payload_len = plaintext_len - 2;
  }
  LOG_INFO("OSCORE request OK: code=0x%02x, payload=%zu bytes\n", code, req_payload_len);

  uint8_t resp_code;
  static uint8_t resp_payload[256];
  size_t resp_payload_len = 0;

  if(code == COAP_CODE_GET) {
    /* /crts: respond with the CertificateChain [c509_native_ca_cert]. */
    c509_chain_entry_t chain_entries[1];
    chain_entries[0].ptr = c509_native_ca_cert;
    chain_entries[0].len = sizeof(c509_native_ca_cert);

    resp_payload_len = c509_chain_encode(resp_payload, sizeof(resp_payload),
                                          chain_entries, 1);
    if(resp_payload_len == 0) {
      LOG_ERR("/crts: c509_chain_encode failed\n");
      return;
    }
    resp_code = COAP_CODE_CONTENT;
    LOG_INFO("/crts: returning CertificateChain (%zu bytes)\n", resp_payload_len);
  } else if(code == COAP_CODE_POST) {
    /* /sen (Phase 3.2): req_payload is a C509 Type-3 CSR. Verify its PoP
     * self-signature, then issue a new Type-2 cert for the CSR's
     * subject/key. */
    if(g_last_csr_len != 0 && g_last_csr_len == req_payload_len &&
       memcmp(req_payload, g_last_csr, req_payload_len) == 0) {
      /* Idempotent retransmit of a CSR we already issued: return the cached
       * cert (no duplicate issuance). */
      memcpy(resp_payload, g_last_cert, g_last_cert_len);
      resp_payload_len = g_last_cert_len;
      resp_code = COAP_CODE_CREATED;
      LOG_INFO("/sen: idempotent replay — returning cached %zu-byte cert\n",
               resp_payload_len);
    } else {
      int64_t csr_type, csr_sig_alg, csr_pk_alg;
      const uint8_t *subject, *pk_key, *sig;
      size_t subject_len, pk_key_len, tbs_len, sig_len;

      if(c509_csr_parse(req_payload, req_payload_len,
                         &csr_type, &csr_sig_alg,
                         &subject, &subject_len,
                         &csr_pk_alg, &pk_key, &pk_key_len,
                         &tbs_len, &sig, &sig_len) != 0 ||
         csr_type != 3 || csr_sig_alg != C509_SIG_ECDSA_SHA256 ||
         csr_pk_alg != C509_PK_SECP256R1) {
        LOG_ERR("/sen: CSR parse failed or unsupported algorithm\n");
        resp_code = COAP_CODE_BAD_REQUEST;
      } else if(c509_csr_verify_pop(req_payload, tbs_len, pk_key, pk_key_len, sig, sig_len) != 0) {
        LOG_ERR("/sen: CSR proof-of-possession verification failed\n");
        resp_code = COAP_CODE_BAD_REQUEST;
      } else if(c509_ca_issue_cert(resp_payload, sizeof(resp_payload), &resp_payload_len,
                                    issued_serial, sizeof(issued_serial),
                                    ca_issuer_name, sizeof(ca_issuer_name) - 1,
                                    ISSUED_NOT_BEFORE, ISSUED_NOT_AFTER,
                                    subject, subject_len,
                                    csr_pk_alg, pk_key, pk_key_len,
                                    ca_priv_key_d, sizeof(ca_priv_key_d)) != 0) {
        LOG_ERR("/sen: c509_ca_issue_cert failed\n");
        resp_code = COAP_CODE_BAD_REQUEST;
        resp_payload_len = 0;
      } else {
        resp_code = COAP_CODE_CREATED;
        LOG_INFO("/sen: issued %zu-byte Type-2 cert for CSR subject\n", resp_payload_len);
        /* Cache (CSR -> cert) so a retransmit is idempotent. */
        if(req_payload_len <= sizeof(g_last_csr) &&
           resp_payload_len <= sizeof(g_last_cert)) {
          memcpy(g_last_csr, req_payload, req_payload_len);
          g_last_csr_len = req_payload_len;
          memcpy(g_last_cert, resp_payload, resp_payload_len);
          g_last_cert_len = resp_payload_len;
        }
      }
    }
  } else {
    LOG_WARN("Unsupported request code 0x%02x\n", code);
    return;
  }

  uint8_t inner[2 + sizeof(resp_payload)];
  size_t inner_len;
  inner[0] = resp_code;
  if(resp_payload_len > 0) {
    inner[1] = 0xFF;
    memcpy(inner + 2, resp_payload, resp_payload_len);
    inner_len = 2 + resp_payload_len;
  } else {
    inner_len = 1;
  }

  uint8_t resp_ct[2 + sizeof(resp_payload) + OSCORE_TAG_LEN];
  size_t resp_ct_len = sizeof(resp_ct);

  err = oscore_protect_response(&server_oscore,
                                 inner, inner_len,
                                 req_piv, req_piv_len,
                                 req_kid, req_kid_len,
                                 resp_ct, &resp_ct_len);
  if(err < 0) {
    LOG_ERR("OSCORE protect response failed: %d\n", err);
    return;
  }

  uint8_t pkt[1 + sizeof(resp_ct)];
  pkt[0] = 0x00;
  memcpy(pkt + 1, resp_ct, resp_ct_len);

  LOG_INFO("Sending OSCORE response code=0x%02x (%zu bytes UDP, payload %zu bytes)\n",
           resp_code, 1 + resp_ct_len, resp_payload_len);
  simple_udp_sendto(&oscore_udp, pkt, 1 + resp_ct_len, source_addr);

  if(code == COAP_CODE_GET) {
    LOG_INFO("=== EDHOC native C509 c5t + OSCORE /crts server exchange complete ===\n");
  } else {
    LOG_INFO("=== EDHOC native C509 c5t + OSCORE /sen server exchange complete ===\n");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS(edhoc_oscore_crts_server, "EDHOC OSCORE /crts Server");
AUTOSTART_PROCESSES(&edhoc_oscore_crts_server);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_oscore_crts_server, ev, data)
{
  PROCESS_BEGIN();

#if MAC_CONF_WITH_TSCH
  /* On TSCH the RPL root must also be the coordinator, else nodes can't associate. */
  if(IS_NETWORK_ROUTING_ROOT) {
    tsch_set_coordinator(1);
  }
#endif

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
  } else {
    static struct etimer timer;
    etimer_set(&timer, CLOCK_SECOND * 5);
    while(1) {
      if(NETSTACK_ROUTING.node_is_reachable()) {
        LOG_INFO("Network ready\n");
        break;
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
      etimer_reset(&timer);
    }
  }

  simple_udp_register(&oscore_udp, OSCORE_UDP_PORT, NULL, OSCORE_UDP_PORT,
                       oscore_request_callback);

  /* Own key (Responder): cert pre-provisioned for c5t hash transmission. */
  static cose_key_t server_key;
  memcpy(&server_key, &auth_c509_native_server_template, sizeof(cose_key_t));
  c509_native_server_attach_cert(&server_key);

  /* Peer key (Initiator): cert pre-provisioned so received hash can be resolved. */
  static cose_key_t client_key;
  memcpy(&client_key, &auth_c509_native_client_template, sizeof(cose_key_t));
  memset(client_key.ecc.priv, 0, sizeof(client_key.ecc.priv));
  c509_native_client_attach_cert(&client_key);

  edhoc_error_t result = edhoc_setup_key_pair(&server_key, &client_key,
                                               "Server", "Client");
  if(result != EDHOC_SUCCESS) {
    LOG_ERR("edhoc_setup_key_pair: %d\n", result);
    PROCESS_EXIT();
  }

  /* Register CA trust store and chain validator. */
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
  edhoc_set_c509_trust_store(&ca_anchor, 1);
  edhoc_set_cert_validator(edhoc_c509_validate_chain, NULL);

  edhoc_server_init();
  if(!edhoc_server_start()) {
    LOG_ERR("Failed to start EDHOC server\n");
    PROCESS_EXIT();
  }

  while(1) {
    PROCESS_WAIT_EVENT();
    int8_t res = edhoc_server_callback(ev, data);

    if(res == SERV_HANDSHAKE_COMPLETE) {
      LOG_INFO("EDHOC handshake completed\n");

      oscore_ctx_t edhoc_out;
      if(edhoc_exporter_oscore(&edhoc_out, edhoc_ctx) < 0) {
        LOG_ERR("edhoc_exporter_oscore failed\n");
      } else {
        print_oscore_ctx(&edhoc_out);
        if(oscore_derive_context(&server_oscore, &edhoc_out) < 0) {
          LOG_ERR("oscore_derive_context failed\n");
        } else {
          oscore_print_context(&server_oscore);
          oscore_ready = true;
          LOG_INFO("OSCORE context ready — waiting for client request\n");
        }
      }
      res = SERV_HANDSHAKE_RESET;
    }

    if(res == SERV_HANDSHAKE_RESET) {
      if(!edhoc_server_reset_handshake()) {
        LOG_ERR("Failed to reset EDHOC handshake state\n");
        PROCESS_EXIT();
      }
    }

    if(res < 0 && res != SERV_HANDSHAKE_RESET && res != SERV_HANDSHAKE_COMPLETE) {
      LOG_ERR("EDHOC server callback error: %d\n", res);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
