#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define IS_NETWORK_ROUTING_ROOT 1

/* EDHOC Method 0, C509 c5t (cert-hash-by-reference), responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* Own authentication KID (matches auth_c509_native_server_template.kid = 0x04). */
#define EDHOC_AUTH_KID 0x04

#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define CSPRNG_CONF_ENABLED 1

#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384
#define COAP_MAX_CHUNK_SIZE 300

#define OSCORE_UDP_PORT 5686

/* Conservative handshake timeout for emulated and real HW alike. */
#define EDHOC_CONF_TIMEOUT 100000
/* Quiet EDHOC by default (Exp H2 timing); -DENROLL_DEBUG restores full logging. */
#ifdef ENROLL_DEBUG
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_ERR
#endif

#endif /* PROJECT_CONF_H_ */
