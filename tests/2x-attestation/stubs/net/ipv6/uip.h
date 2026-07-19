/* Minimal stub of net/ipv6/uip.h for the STANDALONE (host gcc) build of the
 * attestation P1 test: os/lib/sha-256.c only uses the byte-order macros. The
 * Contiki build uses the real uip.h. Host (x86-64) is little-endian. */
#ifndef UIP_STUB_H_
#define UIP_STUB_H_
#define UIP_LITTLE_ENDIAN 3412
#define UIP_BIG_ENDIAN    1234
#define UIP_BYTE_ORDER    UIP_LITTLE_ENDIAN
#endif
