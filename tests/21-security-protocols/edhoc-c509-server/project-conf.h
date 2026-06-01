#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LPM_CONF_MAX_PM 1

/* C509 c5t credential mode */
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* C509 cert can be up to 256 bytes */
#define EDHOC_CONF_MAX_CRED_LEN 256
/* TH input = TH(34) + PLAINTEXT(~80) + CRED(~159) = ~273 bytes */
#define EDHOC_CONF_MAX_BUFFER 384

/* Large payload to avoid block-wise for C509 cred */
#define COAP_MAX_CHUNK_SIZE 300

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
