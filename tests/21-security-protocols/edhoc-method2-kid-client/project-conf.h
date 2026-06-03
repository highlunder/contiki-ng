#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja (same as existing EDHOC tests). */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 2 (StaticDH|Sig): initiator uses Static DH, responder signs.
 * RFC 9528 §3.3: I authenticates with a static DH key; R authenticates with
 * a signature key.  The same P-256 key material works for both roles because
 * cipher suite 2 uses ES256 (ECDSA-P256) for signatures and ECDH-P256 for DH.
 * The method number is carried in MSG_1 so the server selects the matching path. */
#define EDHOC_CONF_METHOD   EDHOC_METHOD2
#define EDHOC_CONF_ROLE     EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_I (initiator CID) = -24 in CBOR encoding. */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_rfc9529_static_dh_client.kid = 0x2b).
 * Used as a Static DH key in Method 2 (no ECDSA signature from the initiator). */
#define EDHOC_AUTH_KID 0x2b

/* Cipher suites supported (suite 2 = secp256r1 + AES-CCM-16-64-128 + SHA-256). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* Enable Cryptographically Secure PRNG for EDHOC ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port (separate from CoAP 5683 and DTLS 5684). */
#define OSCORE_UDP_PORT 5686

/* Enough buffer for OSCORE exchange. */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 256
#define EDHOC_CONF_MAX_BUFFER      256

/* EDHOC session watchdog.  100 s is conservative for both emulated and real HW. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
