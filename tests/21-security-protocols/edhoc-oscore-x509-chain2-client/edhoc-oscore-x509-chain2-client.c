/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE end-to-end test client — X.509 x5chain credentials,
 *   chain-length 2 (Phase 5 evaluation, scenario C chain2 variant).
 *
 *   Identical flow to edhoc-oscore-x509-chain-client (chain-length 1) but
 *   each peer sends its own leaf cert *and* the two issuing Sub CA certs
 *   inline as a CBOR array (ID_CRED_x = {33: [bstr<leaf>, bstr<Sub CA 2>,
 *   bstr<Sub CA 1>]}), and edhoc_x509_validate_chain() verifies
 *   leaf -> Sub CA 2 -> Sub CA 1 -> Root CA 2, with the Root CA 2 public key
 *   as the out-of-band trust anchor.
 *     - Own [cert, Sub CA 2, Sub CA 1] chain is attached and sent inline in
 *       MSG_3
 *     - Peer's [cert, Sub CA 2, Sub CA 1] chain arrives inline in MSG_2 — no
 *       pre-provisioning needed beyond the Root CA 2 trust anchor
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
#include "edhoc-cred-x509-test-chain2.h"
#include "edhoc-cred-x509.h"
#include "oscore.h"

#include "sys/log.h"
#define LOG_MODULE "OSCORE-x509chain2-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

#define COAP_CODE_GET     0x01
#define COAP_CODE_CONTENT 0x45

static struct simple_udp_connection oscore_udp;
static oscore_security_context_t client_oscore;
static bool oscore_ready = false;
static bool oscore_test_passed = false;

PROCESS_NAME(edhoc_oscore_x509_chain2_client);

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
    LOG_INFO("=== EDHOC+OSCORE x509-chain2 end-to-end test PASSED ===\n");
    oscore_test_passed = true;
    process_post(&edhoc_oscore_x509_chain2_client, PROCESS_EVENT_CONTINUE, NULL);
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
PROCESS(edhoc_oscore_x509_chain2_client, "EDHOC+OSCORE x509-chain2 Client");
AUTOSTART_PROCESSES(&edhoc_oscore_x509_chain2_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_oscore_x509_chain2_client, ev, data)
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

  /* Set up X.509 x5chain chain-length-2 credentials.
   * Own key (initiator): attach [client2 cert, Sub CA 2 cert, Sub CA 1 cert]
   * chain — sent inline in MSG_3.
   * Peer key (responder): register minimal entry with no cert — the
   * server's chain arrives inline in MSG_2 and is extracted from there. */
  edhoc_error_t result = edhoc_create_key_list();
  if(result != EDHOC_SUCCESS) {
    LOG_ERR("edhoc_create_key_list: %d\n", result);
    PROCESS_EXIT();
  }

  static cose_key_t client_key;
  memcpy(&client_key, &auth_x509_chain2_client_template, sizeof(cose_key_t));
  x509_chain2_test_attach_client_cert(&client_key);

  static cose_key_t server_key;
  memcpy(&server_key, &auth_x509_chain2_server_template, sizeof(cose_key_t));
  memset(server_key.ecc.priv, 0, sizeof(server_key.ecc.priv));
  /* No cert pre-provisioned for the peer in x5chain — chain arrives inline. */
  server_key.c509_data = NULL;
  server_key.c509_len  = 0;

  if(edhoc_add_key(&client_key) != EDHOC_SUCCESS ||
     edhoc_add_key(&server_key) != EDHOC_SUCCESS) {
    LOG_ERR("Failed to add EDHOC keys\n");
    PROCESS_EXIT();
  }

  /* Register the Root CA 2 as the out-of-band trust anchor, and use the
   * chain-aware validator: verifies leaf -> Sub CA 2 -> Sub CA 1 -> Root CA 2.
   * The pending validator and trust store are copied into the EDHOC context
   * by edhoc_new(). */
  edhoc_set_c509_trust_store(&x509_chain2_root_ca_anchor, 1);
  edhoc_set_cert_validator(edhoc_x509_validate_chain, NULL);

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
      etimer_set(&timer, CLOCK_SECOND * 5);
      while(!oscore_test_passed) {
        PROCESS_WAIT_EVENT();
        if(etimer_expired(&timer)) {
          LOG_INFO("OSCORE GET timeout, retrying\n");
          send_oscore_request(&server_ep.ipaddr);
          etimer_reset(&timer);
        }
      }
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
