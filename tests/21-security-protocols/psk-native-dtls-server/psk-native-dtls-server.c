/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS server for PSK DTLS test (Exp RW-3: S3K ROM comparison).
 *
 *   Scenario E of the memory-footprint comparison: standard mbedTLS
 *   DTLS 1.2 with a pre-shared key (TLS-PSK-WITH-AES-256-CCM-8).
 *   No certificates, no C509 codec, no uECC.  Exposes GET /test/hello.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "coap-engine.h"
#include "coap-keystore.h"

#include "sys/log.h"
#define LOG_MODULE "PSK-Nat-Sv"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* 16-byte pre-shared key (128-bit AES key size, typical IoT deployment) */
static const uint8_t psk_key[]      = { 0x01, 0x02, 0x03, 0x04,
                                        0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0a, 0x0b, 0x0c,
                                        0x0d, 0x0e, 0x0f, 0x10 };
/* 6-byte PSK identity */
static const uint8_t psk_identity[] = { 'c', 'l', 'i', 'e', 'n', 't' };

/*---------------------------------------------------------------------------*/
static void
res_get_handler(coap_message_t *request, coap_message_t *response,
                uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static const char msg[] = "Hello from native PSK server!";

  memcpy(buffer, msg, sizeof(msg) - 1);
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, buffer, sizeof(msg) - 1);
  LOG_INFO("=== PSK DTLS server exchange complete ===\n");
}

RESOURCE(res_hello,
         "title=\"PSK Hello\";rt=\"Text\"",
         res_get_handler, NULL, NULL, NULL);

/*---------------------------------------------------------------------------*/
static int
get_psk_info(const coap_endpoint_t *ep, coap_keystore_psk_entry_t *info)
{
  info->identity_hint     = NULL;
  info->identity_hint_len = 0;
  info->identity          = psk_identity;
  info->identity_len      = sizeof(psk_identity);
  info->key               = psk_key;
  info->key_len           = sizeof(psk_key);
  return 1;
}

static const coap_keystore_t server_keystore = {
  .coap_get_psk_info  = get_psk_info,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = NULL,
};

/*---------------------------------------------------------------------------*/
PROCESS(psk_native_dtls_server, "Native PSK DTLS Server");
AUTOSTART_PROCESSES(&psk_native_dtls_server);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(psk_native_dtls_server, ev, data)
{
  PROCESS_BEGIN();

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
  }

  LOG_INFO("Starting native PSK DTLS server\n");

  coap_set_keystore(&server_keystore);
  coap_engine_init();
  coap_activate_resource(&res_hello, "test/hello");

  if(!coap_secure_server_setup()) {
    LOG_ERR("DTLS server setup failed\n");
    PROCESS_EXIT();
  }
  LOG_INFO("DTLS PSK server ready\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
