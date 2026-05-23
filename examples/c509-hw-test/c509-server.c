/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         CoAPS server with C509 certificate authentication for nRF52840.
 *
 *         This application is the hardware-target counterpart of the native
 *         Linux server in secure-endpoint-test-server/native-server/.  It
 *         exposes a single CoAP resource at "test/hello" over DTLS, using a
 *         self-signed Type 3 C509 certificate (secp256r1).
 *
 *         Expected Renode UART output (success):
 *           [INFO] C509 Server: CoAP engine started
 *           [INFO] C509 Server: DTLS server ready
 *           [INFO] C509 Server: GET /test/hello from <addr>
 */

#include "contiki.h"
#include "net/ipv6/uiplib.h"
#include "coap-engine.h"
#include "coap-keystore.h"
#include "mbedtls-support/mbedtls-support.h"
#include "../c509-credentials.h"

#include <stdio.h>
#include <string.h>

#define LOG_MODULE "C509 Server"
#define LOG_LEVEL  LOG_LEVEL_INFO
#include "sys/log.h"

/*---------------------------------------------------------------------------*/
/* CoAP resource: GET /test/hello */
/*---------------------------------------------------------------------------*/
static void
res_get_handler(coap_message_t *request, coap_message_t *response,
                uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static const char msg[] = "Hello from C509 nRF52840 Server!";

  LOG_INFO("GET /test/hello\n");
  memcpy(buffer, msg, sizeof(msg) - 1);
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, buffer, sizeof(msg) - 1);
}

RESOURCE(res_hello,
         "title=\"C509 Hello\";rt=\"Text\"",
         res_get_handler, NULL, NULL, NULL);
/*---------------------------------------------------------------------------*/
/* Keystore: supply credentials from the shared test vector header. */
/*---------------------------------------------------------------------------*/
static int
get_c509_info(const coap_endpoint_t *ep, coap_keystore_c509_entry_t *info)
{
  info->ca_cert     = test_c509_cert;
  info->ca_cert_len = sizeof(test_c509_cert);
  info->own_cert     = test_c509_cert;
  info->own_cert_len = sizeof(test_c509_cert);
  info->priv_key     = test_priv_key;
  info->priv_key_len = sizeof(test_priv_key);
  return 1;
}

static const coap_keystore_t server_keystore = {
  .coap_get_psk_info  = NULL,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = get_c509_info,
};
/*---------------------------------------------------------------------------*/
PROCESS(c509_server_process, "C509 CoAPS Server");
AUTOSTART_PROCESSES(&c509_server_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_server_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Starting C509 CoAPS server\n");

  coap_set_keystore(&server_keystore);
  coap_engine_init();
  LOG_INFO("CoAP engine started\n");

  coap_activate_resource(&res_hello, "test/hello");

  if(!coap_secure_server_setup()) {
    LOG_ERR("DTLS server setup failed\n");
    PROCESS_EXIT();
  }
  LOG_INFO("DTLS server ready\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
