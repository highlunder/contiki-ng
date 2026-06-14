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

/* Own authentication KID (matches auth_x509_chain_server_template.kid = 0x34). */
#define EDHOC_AUTH_KID 0x34

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* Chain-length-1 x5chain: CRED_x = [bstr<leaf 381B>, bstr<Sub CA 394B>] =
 * 782 B, ID_CRED_x = {33: <782 B array>} = ~785 B. Sized to 832 with margin. */
#define EDHOC_CONF_MAX_CRED_LEN    832
#define EDHOC_CONF_MAX_ID_CRED_LEN 832
/* TH input = TH-bstr(34) + PLAINTEXT_3(~851, incl. ID_CRED_I ~785 +
 * Signature_or_MAC_3 ~66) + CRED(~782) = ~1667 bytes. Sized to 1792 with margin. */
#define EDHOC_CONF_MAX_BUFFER      1792
/* MSG_2/MSG_3 with inline 2-cert X.509 chain (~871 B incl. AEAD tag). */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 1024

/* Must be a power of two (CoAP block SZX encoding): 16/32/.../1024. Must
 * match client. See edhoc-oscore-c5c-chain-server/project-conf.h. */
#define COAP_MAX_CHUNK_SIZE 256

/* RPL tuning for x5chain large-message tolerance. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog. Matches the client timeout. x5chain
 * block-wise delivery of MSG_3 (with inline 2-cert chain) takes additional
 * round trips, but 100 s is still very conservative for both emulated and
 * real hardware. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
