/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Shared boot banner for the Firefly-gateway OTA test ladder (local-tests/).
 * Each firmware calls local_test_banner() right after PROCESS_BEGIN so that,
 * whichever .hex you flashed, the console immediately states what it is and
 * how it is configured. See local-tests/README.md.
 */
#ifndef LOCAL_TEST_BANNER_H_
#define LOCAL_TEST_BANNER_H_

#include <stdio.h>

#ifndef LOCAL_TEST_FWID
#define LOCAL_TEST_FWID "local-tests"
#endif

/* name   : rung label, e.g. "2-dtls-psk"
 * server : target server literal (e.g. "fd00::1") or NULL for a pure
 *          connectivity rung
 * port   : UDP port on the server (ignored when server == NULL)         */
static inline void
local_test_banner(const char *name, const char *server, unsigned port)
{
  printf("\n");
  printf("========================================================\n");
  printf(" LOCAL-TEST : %s\n", name);
#ifdef LOCAL_TEST_DEBUG
  printf(" build      : DEBUG (verbose RPL/DTLS logging)\n");
#else
  printf(" build      : release (INFO logging)\n");
#endif
  printf(" fw-id      : %s\n", LOCAL_TEST_FWID);
  printf(" role       : plain RPL node (joins the Firefly DAG over 2.4GHz)\n");
  printf(" radio      : see 'PANID'/'Default channel' in the boot lines above\n");
  if(server != NULL) {
    printf(" server     : [%s]:%u  (setest, via the Firefly gateway)\n",
           server, port);
  } else {
    printf(" server     : none — connectivity/RPL-join test only\n");
  }
  printf("========================================================\n\n");
}

#endif /* LOCAL_TEST_BANNER_H_ */
