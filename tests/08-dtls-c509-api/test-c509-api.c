#include "contiki.h"
#include "coap-keystore.h"
#include "mbedtls-support.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mock heapmem for native target to satisfy MbedTLS requirements in this test */
#include "lib/heapmem.h"

void *heapmem_calloc(size_t n, size_t size) { return calloc(n, size); }
bool heapmem_free(void *ptr) { free(ptr); return true; }
void *heapmem_zone_alloc(heapmem_zone_t zone, size_t size) { (void)zone; return malloc(size); }

static int get_c509_info(const coap_endpoint_t *address_info, coap_keystore_c509_entry_t *info) {
  (void)address_info;
  (void)info;
  return 1;
}

static const coap_keystore_t my_keystore = {
  .coap_get_psk_info = NULL,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = get_c509_info
};

PROCESS(test_api_process, "C509 API Test");
AUTOSTART_PROCESSES(&test_api_process);

PROCESS_THREAD(test_api_process, ev, data)
{
  PROCESS_BEGIN();

  printf("C509 API Test: Starting\n");

  /* COAP_DTLS_SEC_MODE_C509 is an enum value */
  printf("C509 API Test: Security mode C509 value = %d\n", (int)COAP_DTLS_SEC_MODE_C509);

  coap_set_keystore(&my_keystore);
  printf("C509 API Test: Keystore set successfully\n");

  /* Verify field access */
  if(my_keystore.coap_get_c509_info != NULL) {
    printf("C509 API Test: Keystore C509 callback is present\n");
  }

  printf("C509 API Test: Finished\n");

  /* Exit for native target */
  exit(0);

  PROCESS_END();
}
