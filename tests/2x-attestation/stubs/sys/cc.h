/* Minimal stub of sys/cc.h for the standalone host build. os/lib/sha-256.c uses
 * MIN; the Contiki build uses the real header. */
#ifndef CC_STUB_H_
#define CC_STUB_H_
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#endif
