/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE end-to-end test server — native C509 Type 2, c5t mode,
 *   Method 2 (I:StaticDH | R:Sig).
 *
 *   Uses hash-by-reference (c5t) credential delivery: both sides pre-provision
 *   the peer's certificate so the 8-byte truncated SHA-256 hash received
 *   in-band can be resolved to the full cert.  The chain validator then
 *   verifies the cert's ECDSA signature against the CA trust anchor.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/simple-udp.h"
#include "edhoc-server.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-cred-c509-native-test.h"
#include "edhoc-cred-c509.h"
#include "edhoc-trust-store.h"
#include "oscore.h"

#include "sys/log.h"
#define LOG_MODULE "NativeM2C5t-Sv"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

#define COAP_CODE_GET     0x01
#define COAP_CODE_CONTENT 0x45

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

  uint8_t plaintext[64];
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
  LOG_INFO("OSCORE request OK: code=0x%02x\n", code);

  static const uint8_t hello[] = "hello";
  uint8_t inner[2 + sizeof(hello) - 1];
  inner[0] = COAP_CODE_CONTENT;
  inner[1] = 0xFF;
  memcpy(inner + 2, hello, sizeof(hello) - 1);

  uint8_t resp_ct[sizeof(inner) + OSCORE_TAG_LEN];
  size_t resp_ct_len = sizeof(resp_ct);

  err = oscore_protect_response(&server_oscore,
                                 inner, sizeof(inner),
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

  LOG_INFO("Sending OSCORE 2.05 Content (%zu bytes UDP)\n", 1 + resp_ct_len);
  simple_udp_sendto(&oscore_udp, pkt, 1 + resp_ct_len, source_addr);

  LOG_INFO("=== EDHOC native C509 c5t M2 + OSCORE server exchange complete ===\n");
}
/*---------------------------------------------------------------------------*/
PROCESS(edhoc_native_m2_c5t_server, "EDHOC native C509 c5t M2 Server");
AUTOSTART_PROCESSES(&edhoc_native_m2_c5t_server);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_native_m2_c5t_server, ev, data)
{
  PROCESS_BEGIN();

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

  /* Own key (Responder, Sig): cert pre-provisioned for c5t hash transmission. */
  static cose_key_t server_key;
  memcpy(&server_key, &auth_c509_native_server_template, sizeof(cose_key_t));
  c509_native_server_attach_cert(&server_key);

  /* Peer key (Initiator, StaticDH): cert pre-provisioned so received hash can be resolved. */
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
