#include "contiki.h"
#include "coap-keystore.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mock heapmem for native target to satisfy MbedTLS requirements in this test */
#include "lib/heapmem.h"

void *heapmem_calloc(size_t n, size_t size) { return calloc(n, size); }
bool heapmem_free(void *ptr) { free(ptr); return true; }
void *heapmem_zone_alloc(heapmem_zone_t zone, size_t size) { (void)zone; return malloc(size); }

static int get_psk_info(const coap_endpoint_t *address_info, coap_keystore_psk_entry_t *info) {
  info->identity = (const uint8_t *)"test-id";
  info->identity_len = 7;
  return 1;
}

static int get_cert_info(const coap_endpoint_t *address_info, coap_keystore_cert_entry_t *info) {
  info->own_cert = (const uint8_t *)"test-cert";
  info->own_cert_len = 9;
  return 1;
}

static const coap_keystore_t test_keystore = {
  .coap_get_psk_info = get_psk_info,
  .coap_get_cert_info = get_cert_info,
  .coap_get_c509_info = NULL
};

PROCESS(test_keystore_api_process, "Keystore API Test");
AUTOSTART_PROCESSES(&test_keystore_api_process);

PROCESS_THREAD(test_keystore_api_process, ev, data)
{
  PROCESS_BEGIN();

  printf("Keystore API Test: Starting\n");

  /* 1. Test coap_get_keystore when NULL */
  coap_set_keystore(NULL);
  assert(coap_get_keystore() == NULL);
  printf("Keystore API Test: NULL keystore check passed\n");

  /* 2. Test retrieval when NULL */
  coap_keystore_psk_entry_t psk_info;
  assert(coap_keystore_get_psk_info(NULL, &psk_info) == 0);
  printf("Keystore API Test: NULL retrieval check passed\n");

  /* 3. Set keystore and test coap_get_keystore */
  coap_set_keystore(&test_keystore);
  assert(coap_get_keystore() == &test_keystore);
  printf("Keystore API Test: coap_get_keystore passed\n");

  /* 4. Test PSK retrieval */
  memset(&psk_info, 0, sizeof(psk_info));
  assert(coap_keystore_get_psk_info(NULL, &psk_info) == 1);
  assert(psk_info.identity_len == 7);
  assert(memcmp(psk_info.identity, "test-id", 7) == 0);
  printf("Keystore API Test: PSK retrieval passed\n");

  /* 5. Test Cert retrieval */
  coap_keystore_cert_entry_t cert_info;
  memset(&cert_info, 0, sizeof(cert_info));
  assert(coap_keystore_get_cert_info(NULL, &cert_info) == 1);
  assert(cert_info.own_cert_len == 9);
  assert(memcmp(cert_info.own_cert, "test-cert", 9) == 0);
  printf("Keystore API Test: Cert retrieval passed\n");

  /* 6. Test C509 retrieval (should be 0 as it's NULL in test_keystore) */
  coap_keystore_c509_entry_t c509_info;
  assert(coap_keystore_get_c509_info(NULL, &c509_info) == 0);
  printf("Keystore API Test: C509 retrieval (NULL callback) passed\n");

  printf("Keystore API Test: ALL TESTS PASSED\n");

  /* Exit for native target */
  exit(0);

  PROCESS_END();
}
