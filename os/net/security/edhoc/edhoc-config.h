/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB (RISE), Stockholm, Sweden
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/**
 * \file
 *      EDHOC configuration file
 * \author
 *      Lidia Pocero <pocero@isi.gr>, Rikard Höglund, Marco Tiloca,
 *      Niclas Finne <niclas.finne@ri.se>, and Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

/**
 * \addtogroup edhoc
 * @{
 */

#ifndef _EDHOC_CONFIG_H_
#define _EDHOC_CONFIG_H_

/* Credential type constants — must be defined early so #if checks below work. */
#define EDHOC_CRED_KID      2  /* Key ID (compact integer or {4: bstr}) */
#define EDHOC_CRED_INCLUDE  3  /* Full COSE_Key inline */
#define EDHOC_CRED_C509_C5T 4  /* C509 hash-by-reference {22: COSE_CertHash} */
#define EDHOC_CRED_C509_C5C 5  /* C509 by-value {25: COSE_C509} */
#define EDHOC_CRED_X509_X5C 6  /* X.509 DER by-value {33: bstr(DER cert)} */

/* Resolve EDHOC_AUTHENT_TYPE early so buffer-size #if checks work. */
#ifdef EDHOC_CONF_AUTHENT_TYPE
#define EDHOC_AUTHENT_TYPE EDHOC_CONF_AUTHENT_TYPE
#else
#define EDHOC_AUTHENT_TYPE EDHOC_CRED_KID
#endif

/**
 * \brief The max size of the transcript hash input buffer.
 * Must be >= CBOR_BYTE_STRING_SIZE(HASH_LEN) + PLAINTEXT_sz + CRED_sz.
 * With C509 certs (~159 bytes) and Method 0 PLAINTEXT (~80 bytes): ~273 bytes min.
 */
#ifdef EDHOC_CONF_MAX_BUFFER
#define EDHOC_MAX_BUFFER EDHOC_CONF_MAX_BUFFER
#else
#define EDHOC_MAX_BUFFER 256
#endif

/**
 * \brief Optimized buffer sizes for credentials based on COSE standard analysis
 * CRED_X: 84-120 bytes typical for CCS; up to ~200 bytes for C509 → 256 bytes
 * ID_CRED_X: 4-7 bytes (KID), ~15 bytes (c5t), or full cert (c5c/include mode)
 */
#ifdef EDHOC_CONF_MAX_CRED_LEN
#define EDHOC_MAX_CRED_LEN EDHOC_CONF_MAX_CRED_LEN
#elif (EDHOC_AUTHENT_TYPE == EDHOC_CRED_X509_X5C)
#define EDHOC_MAX_CRED_LEN 512      /* X.509 DER cert (~387 bytes typical) */
#else
#define EDHOC_MAX_CRED_LEN 256
#endif

#ifdef EDHOC_CONF_MAX_ID_CRED_LEN
#define EDHOC_MAX_ID_CRED_LEN EDHOC_CONF_MAX_ID_CRED_LEN
#elif (EDHOC_AUTHENT_TYPE == EDHOC_CRED_KID) || (EDHOC_AUTHENT_TYPE == EDHOC_CRED_C509_C5T)
#define EDHOC_MAX_ID_CRED_LEN 32    /* KID/c5t: ≤ 16 bytes typical → 32 bytes (safe) */
#elif (EDHOC_AUTHENT_TYPE == EDHOC_CRED_C509_C5C)
#define EDHOC_MAX_ID_CRED_LEN 256   /* c5c: full cert inline (override for chains, see EDHOC_CONF_MAX_ID_CRED_LEN) */
#elif (EDHOC_AUTHENT_TYPE == EDHOC_CRED_X509_X5C)
#define EDHOC_MAX_ID_CRED_LEN 512   /* x5chain: full DER cert inline (~387 bytes) */
#else
#define EDHOC_MAX_ID_CRED_LEN 256   /* Include mode / fallback */
#endif

/**
 * \brief The max number of suites
 *
 * There are nine suites that are defined at the time of
 * writing (0-6 and 24-25). We select just a slightly larger
 * value to avoid using too much unnecessary space for
 * the array of suites.
 */
#define EDHOC_SUITES_MAX_COUNT 10

/**
 * \brief Set EDHOC connection identifier
 */
#ifndef EDHOC_CID
#ifdef EDHOC_CONF_CID
#define EDHOC_CID EDHOC_CONF_CID
#else
#define EDHOC_CID 0x1
#endif
#endif /* EDHOC_CID */

/* Variable-length CID support for testing */
#ifdef EDHOC_CONF_CID_BYTES
#define EDHOC_CID_BYTES EDHOC_CONF_CID_BYTES
#endif

/*---------------------------------------------------------------------------*/
/*
 * Configurable Buffer Sizes for Credential Handling
 *
 * These buffer sizes control memory usage for EDHOC credential storage.
 * All can be overridden in project-conf.h using EDHOC_CONF_* variants.
 *
 * Example project-conf.h configuration:
 *
 *   // Increase KID buffer to support longer key identifiers
 *   #define EDHOC_CONF_MAX_KID_LEN 8
 *
 *   // Increase identity buffer for longer credential names
 *   #define EDHOC_CONF_MAX_IDENTITY_LEN 64
 *
 *   // Increase CID buffer for applications using longer connection IDs
 *   #define EDHOC_CONF_MAX_CID_LEN 16
 */

/**
 * \brief Maximum length of connection identifiers
 * RFC 9528 allows variable-length CIDs including negative integers
 *
 * To override in project-conf.h:
 * \code
 * #define EDHOC_CONF_MAX_CID_LEN 16
 * \endcode
 */
#ifdef EDHOC_CONF_MAX_CID_LEN
#define EDHOC_MAX_CID_LEN EDHOC_CONF_MAX_CID_LEN
#else
#define EDHOC_MAX_CID_LEN 8
#endif

/**
 * \brief Default CID length for backward compatibility
 */
#define EDHOC_DEFAULT_CID_LEN 1

/**
 * \brief Maximum length of Key Identifiers (KID) in credentials
 * COSE Key IDs can be 1-4 bytes typically, but allowing larger for flexibility
 *
 * To override in project-conf.h:
 * \code
 * #define EDHOC_CONF_MAX_KID_LEN 8
 * \endcode
 */
#ifdef EDHOC_CONF_MAX_KID_LEN
#define EDHOC_MAX_KID_LEN EDHOC_CONF_MAX_KID_LEN
#else
#define EDHOC_MAX_KID_LEN 4
#endif

/**
 * \brief Maximum length of identity strings in credentials
 * Used for human-readable credential identities (e.g., "example.edu")
 *
 * To override in project-conf.h:
 * \code
 * #define EDHOC_CONF_MAX_IDENTITY_LEN 64
 * \endcode
 */
#ifdef EDHOC_CONF_MAX_IDENTITY_LEN
#define EDHOC_MAX_IDENTITY_LEN EDHOC_CONF_MAX_IDENTITY_LEN
#else
#define EDHOC_MAX_IDENTITY_LEN 32
#endif

/* EDHOC Role definitions */
#define EDHOC_RESPONDER 0   /* The Responder of the EDHOC protocol */
#define EDHOC_INITIATOR 1   /* The Initiator of the EDHOC protocol */

/**
 * \brief Set the EDHOC Protocol role
 */
#ifdef EDHOC_CONF_ROLE
#define EDHOC_ROLE EDHOC_CONF_ROLE
#else
#define EDHOC_ROLE EDHOC_INITIATOR
#endif

/* EDHOC Authentication Method Types: Initiator (I) | Responder (R) */
#define EDHOC_METHOD0 0                  /* Signature Key  | Signature Key  */
#define EDHOC_METHOD1 1                  /* Signature Key  | Static DH Key  */
#define EDHOC_METHOD2 2                  /* Static DH Key  | Signature Key  */
#define EDHOC_METHOD3 3                  /* Static DH Key  | Static DH Key  */

/**
 * \brief Set the Authentication method
 */
#ifndef EDHOC_METHOD
#ifdef EDHOC_CONF_METHOD
#define EDHOC_METHOD EDHOC_CONF_METHOD
#else
#define EDHOC_METHOD EDHOC_METHOD0
#endif
#endif /* EDHOC_METHOD */

/**
 * \brief Buffer size for mac_or_sig
 */
#if EDHOC_METHOD == EDHOC_METHOD3
#define EDHOC_MAC_OR_SIG_BUF_LEN EDHOC_MAX_MAC_LEN
#else
#define EDHOC_MAC_OR_SIG_BUF_LEN P256_SIGNATURE_LEN
#endif

/**
 * \brief Helper defines for method handling on msg. reception
 */
#define INITIATOR_METHOD2 \
  (EDHOC_METHOD == EDHOC_METHOD2 && EDHOC_ROLE == EDHOC_INITIATOR)
#define RESPONDER_METHOD1 \
  (EDHOC_METHOD == EDHOC_METHOD1 && EDHOC_ROLE == EDHOC_RESPONDER)
#define INITIATOR_METHOD1 \
  (EDHOC_METHOD == EDHOC_METHOD1 && EDHOC_ROLE == EDHOC_INITIATOR)
#define RESPONDER_METHOD2 \
  (EDHOC_METHOD == EDHOC_METHOD2 && EDHOC_ROLE == EDHOC_RESPONDER)

/* COSE header labels for ID_CRED_X identification methods */
#define COSE_HEADER_LABEL_COMPACT_ENCODING 0  /* Compact encoding (bare KID) */
#define COSE_HEADER_LABEL_CRED_FULL 1         /* Full credential inclusion */
#define COSE_HEADER_LABEL_KID 4               /* Key ID in map format {4: kid} */
/* C509 COSE header parameters (draft-ietf-cose-cbor-encoded-cert-11) */
#define COSE_HEADER_LABEL_C5T 22  /* C509 hash-by-reference              */
#define COSE_HEADER_LABEL_C5C 25  /* C509 by-value (ordered chain)       */
/* X.509 COSE header parameter (draft-ietf-cose-x509): by-value DER cert(s) */
#define COSE_HEADER_LABEL_X5CHAIN 33  /* X.509 DER by-value (ordered chain) */
/* SHA-256/64 (8-byte truncated SHA-256) COSE algorithm ID for c5t      */
#define COSE_HASH_ALG_SHA256_64  (-15)
/* Recommended truncated hash length for c5t per RFC 9528 §9.3          */
#define EDHOC_C5T_HASH_LEN 8

/* EDHOC_AUTHENT_TYPE and credential type constants are resolved at the top of
 * this file so the #if guards on EDHOC_MAX_ID_CRED_LEN work correctly. */

/* cipher suites */
#define EDHOC_CIPHERSUITE_0 0   /* AES-CCM-16-64-128,  (HMAC 256/256) SHA-256,  MAC LEN 8,  X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256 */
#define EDHOC_CIPHERSUITE_1 1   /* AES-CCM-16-128-128, (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256 */
#define EDHOC_CIPHERSUITE_2 2 /* AES-CCM-16-64-128,  (HMAC 256/256) SHA-256,  MAC LEN 8,  P-256,  ES256, P-256,   AES-CCM-16-64-128, SHA-256 */   /* Supported */
#define EDHOC_CIPHERSUITE_3 3 /* AES-CCM-16-128-128, (HMAC 256/256) SHA-256,  MAC LEN 16, P-256,  ES256, P-256,   AES-CCM-16-64-128, SHA-256 */   /* Supported */
#define EDHOC_CIPHERSUITE_4 4   /* ChaCha20/Poly1305,  (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, EdDSA, Ed25519, ChaCha20/Poly1305, SHA-256 */
#define EDHOC_CIPHERSUITE_5 5   /* ChaCha20/Poly1305,  (HMAC 256/256) SHA-256,  MAC LEN 16, P-256,  ES256, P-256,   ChaCha20/Poly1305, SHA-256 */
#define EDHOC_CIPHERSUITE_6 6   /* A128GCM,            (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, ES256, P-256,   A128GCM,           SHA-256 */
#define EDHOC_CIPHERSUITE_24 24 /* A256GCM,            (HMAC 384/384) SHA-384,  MAC LEN 16, P-384,  ES384, P-384,   A256GCM,           SHA-384 */
#define EDHOC_CIPHERSUITE_25 25 /* ChaCha20/Poly1305,  (HMAC 256/256) SHAKE256, MAC LEN 16, X448,   EdDSA, Ed448,   ChaCha20/Poly1305, SHAKE256 */

/* EDHOC MAC lengths */
#define EDHOC_MAC_LEN_16  16
#define EDHOC_MAC_LEN_8   8
#define EDHOC_MAX_MAC_LEN 16

/* Curves for EDHOC key exchange algorithm (ECDH curve) */
#define EDHOC_CURVE_P256 1
#define EDHOC_CURVE_BRAINPOOLP256R1 2

/* Curve used for the COSE_Sign1 signature (credential's static authentication
 * key), as opposed to EDHOC_CURVE_P256 above which is the ephemeral ECDH
 * curve. These are independent: a ciphersuite's nominal "P-256" signature
 * curve can be overridden here for test apps whose credential uses a
 * different curve (e.g. brainpoolP256r1, see PLAN-c509-lice-followup.md
 * SS5.3.3 scenario D). Override via EDHOC_CONF_SIGNATURE_CURVE in
 * project-conf.h. */
#ifdef EDHOC_CONF_SIGNATURE_CURVE
#define EDHOC_SIGNATURE_CURVE EDHOC_CONF_SIGNATURE_CURVE
#else
#define EDHOC_SIGNATURE_CURVE EDHOC_CURVE_P256
#endif

/* COSE_Sign1 signature algorithm for the credential's static authentication
 * key, independent of the ciphersuite-derived default (ES256). Override via
 * EDHOC_CONF_SIGNATURE_ALG in project-conf.h (e.g. EDDSA, see
 * PLAN-c509-lice-followup.md SS5.3.3 Ed25519 scenario D). 0 means "use the
 * ciphersuite default" (get_edhoc_sign_alg() in edhoc.c). */
#ifdef EDHOC_CONF_SIGNATURE_ALG
#define EDHOC_SIGNATURE_ALG EDHOC_CONF_SIGNATURE_ALG
#else
#define EDHOC_SIGNATURE_ALG 0
#endif

/* Common settings for supported cipher suites */
#define ECC_KEY_LEN 32
#define HASH_LEN 32

/**
 * \brief Length of signatures
 */
#define P256_SIGNATURE_LEN 64
#define ED25519_SIGNATURE_LEN 64
#define ED448_SIGNATURE_LEN 114
#define P384_SIGNATURE_LEN 96

/**
 * \brief Set EDHOC cipher suite config
 */
#ifdef EDHOC_CONF_SUPPORTED_SUITE_1
#define EDHOC_SUPPORTED_SUITE_1 EDHOC_CONF_SUPPORTED_SUITE_1
#else
#define EDHOC_SUPPORTED_SUITE_1 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUITE_2
#define EDHOC_SUPPORTED_SUITE_2 EDHOC_CONF_SUPPORTED_SUITE_2
#else
#define EDHOC_SUPPORTED_SUITE_2 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUITE_3
#define EDHOC_SUPPORTED_SUITE_3 EDHOC_CONF_SUPPORTED_SUITE_3
#else
#define EDHOC_SUPPORTED_SUITE_3 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUITE_4
#define EDHOC_SUPPORTED_SUITE_4 EDHOC_CONF_SUPPORTED_SUITE_4
#else
#define EDHOC_SUPPORTED_SUITE_4 -1
#endif

/* Handle settings for test vectors */
#define EDHOC_NO_TEST 0
#define EDHOC_TEST_VECTOR_TRACE_DH 1
#define EDHOC_TEST_VECTOR_TRACE_SIG 2

#ifdef EDHOC_CONF_TEST
#define EDHOC_TEST EDHOC_CONF_TEST
#else
#define EDHOC_TEST EDHOC_NO_TEST
#endif

/**
 * \brief The number of attempts to try to connect with the EDHOC server successfully
 */
#ifndef EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 2
#endif

/**
 * \brief The max length of the EDHOC message
 */
#ifdef EDHOC_CONF_MAX_PAYLOAD_LEN
#define EDHOC_MAX_PAYLOAD_LEN EDHOC_CONF_MAX_PAYLOAD_LEN
#else
#define EDHOC_MAX_PAYLOAD_LEN 256
#endif

/**
 * \brief The max length of the Application Data
 */
#ifdef EDHOC_CONF_MAX_AD_SZ
#define EDHOC_MAX_AD_SZ EDHOC_CONF_MAX_AD_SZ
#else
#define EDHOC_MAX_AD_SZ 8
#endif

/**
 * \brief Enable/disable External Authorization Data (EAD) processing
 *
 * When enabled, the implementation will process EAD items according to RFC 9528 Section 6:
 * - Critical EAD items (negative ead_label) that cannot be processed will trigger an error
 * - Non-critical EAD items (non-negative ead_label) will be ignored if not recognized
 *
 * To disable in project-conf.h:
 * \code
 * #define EDHOC_CONF_EAD_PROCESSING 0
 * \endcode
 */
#ifdef EDHOC_CONF_EAD_PROCESSING
#define EDHOC_EAD_PROCESSING EDHOC_CONF_EAD_PROCESSING
#else
#define EDHOC_EAD_PROCESSING 1
#endif

/**
 * \brief Maximum number of application EAD handler registrations.
 *
 * Applications call edhoc_register_ead_handler() to attach a callback for a
 * specific EAD label.  Increase this value if more than 4 distinct labels
 * need to be handled simultaneously.
 */
#ifdef EDHOC_CONF_EAD_MAX_HANDLERS
#define EDHOC_EAD_MAX_HANDLERS EDHOC_CONF_EAD_MAX_HANDLERS
#else
#define EDHOC_EAD_MAX_HANDLERS 4
#endif

/**
 * \brief EDHOC resource CoAP URI path
 */
#define EDHOC_COAP_URI_PATH ".well-known/edhoc"

#endif /* _EDHOC_CONFIG_H_ */

/** @} */
