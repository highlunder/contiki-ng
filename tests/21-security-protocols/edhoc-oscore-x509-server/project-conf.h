#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 0, X.509 x5chain (cert inline delivery), responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_X509_X5C

/* RFC 9529 C_R (responder CID). */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_x509_server_template.kid = 0x01). */
#define EDHOC_AUTH_KID 0x01

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* x5chain buffers — sized for the 384-byte X.509 DER cert.
 * EDHOC_MAX_BUFFER must hold CRED + PLAINTEXT (ID_CRED + Signature_or_MAC +
 * CBOR overhead) for TH_3/TH_4 computation, i.e. > cred_sz + plaintext_sz. */
#define EDHOC_CONF_MAX_CRED_LEN 512
#define EDHOC_CONF_MAX_BUFFER   1024
#define EDHOC_CONF_MAX_PAYLOAD_LEN 512

/* Must match client — see edhoc-oscore-x509-client/project-conf.h. */
#define COAP_MAX_CHUNK_SIZE 512

/* RPL tuning for x5chain large-message tolerance. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog.  Matches the client timeout.  x5chain
 * block-wise delivery of MSG_3 (with inline 387-byte cert) takes additional
 * round trips, but 100 s is still very conservative for both emulated and
 * real hardware. COAP_RESPONSE_TIMEOUT and RPL tuning are not needed here —
 * the server is a native process with no 802.15.4 radio or RPL stack. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
