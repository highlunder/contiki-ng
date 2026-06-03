#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LPM_CONF_MAX_PM 1

#define EDHOC_CONF_TIMEOUT 100000

#define EDHOC_CONF_CID 0x37

/* Large payload to accommodate c5c inline cert delivery */
#define COAP_MAX_CHUNK_SIZE 300

/* C509 c5c credential mode: cert delivered inline in MSG_2/MSG_3 */
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* C509 cert can be up to 256 bytes; ID_CRED_x for c5c includes the full cert */
#define EDHOC_CONF_MAX_CRED_LEN 256
/* TH input = TH(34) + PLAINTEXT(~231) + CRED(~159) = ~424 bytes */
#define EDHOC_CONF_MAX_BUFFER 512
/* MSG_2 = CBOR_bstr(G_Y=32 + CIPHERTEXT_2=231) = 265 bytes;
 * MSG_3 similarly large (client cert = 164 bytes in ID_CRED_I) */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* KID used by edhoc_get_own_auth_key() to find the client's own key */
#define EDHOC_AUTH_KID 0x02

#define EDHOC_CONF_ROLE EDHOC_INITIATOR

#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

#define CSPRNG_CONF_ENABLED 1

/* Prevent a second EDHOC session from starting while the first session's
 * MSG_2 is still in flight.  A CoAP-level timeout fires shortly after MSG_1
 * is sent (before MSG_2 arrives over 6LoWPAN), triggering EVT_RESTART.  With
 * ATTEMPTS>1 a competing session starts, conflicting with the in-progress one.
 * ATTEMPTS=1 means the client does not retry; MSG_2 still arrives and
 * the session completes normally through the existing receive handler. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

/* RPL tuning: keep the parent even when CSMA retransmissions during the
 * EDHOC handshake temporarily spike the ETX above the default limit of 512. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30

#define LOG_CONF_WITH_COMPACT_BYTES 0
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
