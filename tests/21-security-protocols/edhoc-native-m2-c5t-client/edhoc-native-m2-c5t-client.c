/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE end-to-end test client — native C509 Type 2, c5t mode,
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
#include "coap-engine.h"
#include "edhoc-client.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-cred-c509-native-test.h"
#include "edhoc-cred-c509.h"
#include "edhoc-trust-store.h"
#include "oscore.h"

#include "sys/log.h"
#define LOG_MODULE "NativeM2C5t-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

#define COAP_CODE_GET     0x01
#define COAP_CODE_CONTENT 0x45

static struct simple_udp_connection oscore_udp;
static oscore_security_context_t client_oscore;
static bool oscore_ready = false;

static uint8_t saved_piv[OSCORE_MAX_PIV_LEN];
static uint8_t saved_piv_len;
static uint8_t saved_kid[OSCORE_MAX_ID_LEN];
static uint8_t saved_kid_len;

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

  uint8_t plaintext[64];
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

  LOG_INFO("OSCORE response OK: code=0x%02x", code);
  if(payload_len > 0) {
    LOG_INFO_(" payload=\"%.*s\"", (int)payload_len, payload);
  }
  LOG_INFO_("\n");

  if(code == COAP_CODE_CONTENT) {
    LOG_INFO("=== EDHOC native C509 c5t M2 + OSCORE end-to-end test PASSED ===\n");
  } else {
    LOG_WARN("Unexpected response code 0x%02x\n", code);
  }
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

  LOG_INFO("Sending OSCORE GET (%zu bytes UDP)\n", pos);
  simple_udp_sendto(&oscore_udp, pkt, pos, server_addr);
}
/*---------------------------------------------------------------------------*/
PROCESS(edhoc_native_m2_c5t_client, "EDHOC native C509 c5t M2 Client");
AUTOSTART_PROCESSES(&edhoc_native_m2_c5t_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_native_m2_c5t_client, ev, data)
{
  static struct etimer timer;

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

  edhoc_error_t result = edhoc_create_key_list();
  if(result != EDHOC_SUCCESS) {
    LOG_ERR("edhoc_create_key_list: %d\n", result);
    PROCESS_EXIT();
  }

  /* Own key (Initiator, StaticDH): cert pre-provisioned so the c5t hash can be computed. */
  static cose_key_t client_key;
  memcpy(&client_key, &auth_c509_native_client_template, sizeof(cose_key_t));
  c509_native_client_attach_cert(&client_key);

  /* Peer key (Responder, Sig): cert pre-provisioned so received hash can be resolved. */
  static cose_key_t server_key;
  memcpy(&server_key, &auth_c509_native_server_template, sizeof(cose_key_t));
  memset(server_key.ecc.priv, 0, sizeof(server_key.ecc.priv));
  c509_native_server_attach_cert(&server_key);

  if(edhoc_add_key(&client_key) != EDHOC_SUCCESS ||
     edhoc_add_key(&server_key) != EDHOC_SUCCESS) {
    LOG_ERR("Failed to add EDHOC keys\n");
    PROCESS_EXIT();
  }

  /* Register CA trust store and chain validator.
   * The validator is invoked after hash lookup resolves the peer's cert. */
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

  edhoc_client_run();

  while(1) {
    PROCESS_WAIT_EVENT();
    int8_t ret = edhoc_client_callback(ev, data);
    if(ret > 0) {
      LOG_INFO("EDHOC finished\n");

      oscore_ctx_t edhoc_out;
      if(edhoc_exporter_oscore(&edhoc_out, edhoc_ctx) < 0) {
        LOG_ERR("edhoc_exporter_oscore failed\n");
        break;
      }
      print_oscore_ctx(&edhoc_out);

      if(oscore_derive_context(&client_oscore, &edhoc_out) < 0) {
        LOG_ERR("oscore_derive_context failed\n");
        break;
      }
      oscore_print_context(&client_oscore);
      oscore_ready = true;

      static coap_endpoint_t server_ep;
      coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

      etimer_set(&timer, CLOCK_SECOND / 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

      send_oscore_request(&server_ep.ipaddr);
      break;
    }
    if(ret < 0) {
      LOG_ERR("EDHOC failure: %d\n", ret);
      break;
    }
  }

  edhoc_client_close();
  LOG_INFO("Client done\n");
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
