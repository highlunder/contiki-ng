#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* EDHOC Method 0, C509 c5c (cert inline delivery), responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* Own authentication KID (matches auth_c509_native_server_template.kid = 0x04). */
#define EDHOC_AUTH_KID 0x04

#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define CSPRNG_CONF_ENABLED 1

/* Make this node the RPL DAG root (native Cooja server). */
#define IS_NETWORK_ROUTING_ROOT 1

/* COAP_MAX_CHUNK_SIZE must match client (300) to avoid silent MSG_3 truncation.
 * coap.c truncates incoming payloads > 64 bytes if this is not raised. */
#define COAP_MAX_CHUNK_SIZE 300

#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   512
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

#define OSCORE_UDP_PORT 5686

/* Conservative handshake timeout for emulated and real HW alike. */
#define EDHOC_CONF_TIMEOUT 100000
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
