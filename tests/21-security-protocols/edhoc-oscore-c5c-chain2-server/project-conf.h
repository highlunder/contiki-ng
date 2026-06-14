#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 0, C509 c5c (cert inline delivery), responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* RFC 9529 C_R (responder CID). */
#define EDHOC_CONF_CID 0x29

/* Own authentication KID (matches auth_c509_chain2_server_template.kid = 0x44). */
#define EDHOC_AUTH_KID 0x44

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* Chain-length-2 c5c: CRED_x = [bstr<leaf 139B>, bstr<Sub CA 2 149B>,
 * bstr<Sub CA 1 150B>] = 445 B, ID_CRED_x = {25: <445 B array>} = ~447 B.
 * Sized to 480 with margin. */
#define EDHOC_CONF_MAX_CRED_LEN    480
#define EDHOC_CONF_MAX_ID_CRED_LEN 480
/* TH input = TH-bstr(34) + PLAINTEXT_3(~520, incl. ID_CRED_I ~447 +
 * Signature_or_MAC_3 ~66) + CRED(~445) = ~1000 bytes. Sized to 1200 with
 * margin. */
#define EDHOC_CONF_MAX_BUFFER      1200
/* MSG_2/MSG_3 with inline 3-cert chain (larger than chain-length-1 c5c's
 * 512). */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 1024

/* Must be a power of two (CoAP block SZX encoding): 16/32/.../1024. 300 is
 * NOT valid — for a multi-block MSG_3, a block's offset would be computed
 * as a rounded SZX instead of 300, corrupting reassembly. */
#define COAP_MAX_CHUNK_SIZE 256

/* RPL tuning for c5c large-message tolerance. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog.  Matches the client timeout.  c5c
 * block-wise delivery of MSG_3 (with inline chain) takes additional round
 * trips, but 100 s is still very conservative for both emulated and real
 * hardware. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
