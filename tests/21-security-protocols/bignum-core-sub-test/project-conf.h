#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP LOG_LEVEL_DBG

/* Mbed TLS needs a heap arena even though this test only calls
 * mbedtls_mpi_core_sub_int() directly (no TLS context is created). */
#define HEAPMEM_CONF_ARENA_SIZE (32 * 1024)

#define LPM_CONF_ENABLE 0

/* Pulls in MBEDTLS_BIGNUM_C (and its prerequisites) so bignum_core.c is
 * built and check_config.h is satisfied, even though this test never
 * opens a TLS context. */
#define COAP_DTLS_CONF_WITH_CERT 1

#define CSPRNG_CONF_ENABLED 1

#endif /* PROJECT_CONF_H_ */
