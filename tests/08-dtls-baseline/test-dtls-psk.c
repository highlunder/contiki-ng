#include "contiki.h"
#include "net/ipv6/uiplib.h"
#include "coap-constants.h"
#include "coap-keystore.h"

#include "lib/list.h"
#include "lib/memb.h"

/* Define PSK support before including mbedtls-support.h */
#ifndef COAP_DTLS_CONF_WITH_PSK
#define COAP_DTLS_CONF_WITH_PSK 1
#endif
#ifndef COAP_DTLS_CONF_WITH_CLIENT
#define COAP_DTLS_CONF_WITH_CLIENT 1
#endif
#include "mbedtls-support/mbedtls-support.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mock heapmem for native target */
#include "lib/heapmem.h"
void *heapmem_calloc(size_t n, size_t size) { return calloc(n, size); }
bool heapmem_free(void *ptr) { free(ptr); return true; }
void *heapmem_zone_alloc(heapmem_zone_t zone, size_t size) { (void)zone; return malloc(size); }

static int get_psk_info(const coap_endpoint_t *address_info, coap_keystore_psk_entry_t *info) {
  static const uint8_t identity[] = "client-id";
  static const uint8_t key[] = "secret-key";
  info->identity = identity;
  info->identity_len = sizeof(identity) - 1;
  info->key = key;
  info->key_len = sizeof(key) - 1;
  return 1;
}

static const coap_keystore_t psk_keystore = {
  .coap_get_psk_info = get_psk_info,
  .coap_get_cert_info = NULL
};

PROCESS(test_dtls_psk_process, "DTLS Baseline PSK Test");
AUTOSTART_PROCESSES(&test_dtls_psk_process);

PROCESS_THREAD(test_dtls_psk_process, ev, data)
{
  PROCESS_BEGIN();

  printf("DTLS Baseline PSK Test: Starting\n");

  /* Initialize DTLS context */
  coap_dtls_init();
  static struct uip_udp_conn mock_conn;
  memset(&mock_conn, 0, sizeof(mock_conn));
  coap_dtls_conn_init(&mock_conn, PROCESS_CURRENT());

  coap_set_keystore(&psk_keystore);

  coap_endpoint_t server_ep;
  uiplib_ipaddrconv("fd00::1", &server_ep.ipaddr);
  server_ep.port = UIP_HTONS(COAP_DEFAULT_SECURE_PORT);
  server_ep.secure = 1;

  printf("DTLS Baseline PSK Test: Attempting coap_ep_dtls_connect\n");
  int ret = coap_ep_dtls_connect(&server_ep, COAP_DTLS_SEC_MODE_PSK, NULL);

  if(ret >= 0) {
    printf("DTLS Baseline PSK Test: coap_ep_dtls_connect result = %d (Success)\n", ret);
    coap_dtls_session_info_t *session = coap_ep_get_dtls_session_info(&server_ep);
    if(session != NULL) {
      printf("DTLS Baseline PSK Test: Session created successfully\n");
    } else {
      printf("DTLS Baseline PSK Test: ERROR - Session not found in list\n");
    }
  } else {
    printf("DTLS Baseline PSK Test: ERROR - coap_ep_dtls_connect failed (%d)\n", ret);
  }

  printf("DTLS Baseline PSK Test: Finished\n");

  /* Exit for native target */
  exit(0);

  PROCESS_END();
}
