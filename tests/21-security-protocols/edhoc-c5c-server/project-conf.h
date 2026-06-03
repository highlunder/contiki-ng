#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LPM_CONF_MAX_PM 1

/* nRF52840 client needs time to compute ECDSA for MSG_3 (c5c cert inline).
 * Default 10s is too short; 60s covers the compute + 6LoWPAN delivery. */
#define EDHOC_CONF_TIMEOUT 60000

/* Large payload to accommodate c5c inline cert delivery */
#define COAP_MAX_CHUNK_SIZE 300

/* C509 c5c credential mode: cert delivered inline in MSG_2/MSG_3 */
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* C509 cert can be up to 256 bytes; ID_CRED_x for c5c includes the full cert */
#define EDHOC_CONF_MAX_CRED_LEN 256
/* TH input = TH(34) + PLAINTEXT(~231) + CRED(~159) = ~424 bytes */
#define EDHOC_CONF_MAX_BUFFER 512
/* MSG_2 = CBOR_bstr(G_Y=32 + CIPHERTEXT_2=231) = 265 bytes */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

/* KID used by edhoc_get_own_auth_key() to find the server's own key */
#define EDHOC_AUTH_KID 0x01

#define EDHOC_CONF_ROLE EDHOC_RESPONDER

#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

#define CSPRNG_CONF_ENABLED 1

#define LOG_CONF_WITH_COMPACT_BYTES 0
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_DBG

#endif /* PROJECT_CONF_H_ */
