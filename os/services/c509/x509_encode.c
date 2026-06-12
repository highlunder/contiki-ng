/**
 * @file x509_encode.c
 * @brief Implementation of X.509 DER encoding for C509 certificates.
 */

#include "c509/x509_encode.h"
#include "c509/der.h"
#include "c509/validity.h"
#include "c509/c509_registry.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <mbedtls/ecp.h>

/* Unix timestamp of 2050-01-01T00:00:00Z */
#define UNIX_2050 2524608000LL

/* Hex-encode binary bytes into a lowercase ASCII string (no NUL added). */
static void bin_to_hex(const uint8_t *in, size_t ilen, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < ilen; i++) {
        out[2*i]   = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 0x0F];
    }
}

/* Reverse the bits of a byte (for C509 KeyUsage UINT → DER BIT STRING). */
static uint8_t bit_reverse8(uint8_t b) {
    b = (uint8_t)(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
    b = (uint8_t)(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
    b = (uint8_t)(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
    return b;
}

/* ── Signature algorithm OIDs ────────────────────────────────────────────── */
static const uint8_t OID_ECDSA_SHA256[]   = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t OID_ECDSA_SHA384[]   = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
static const uint8_t OID_ECDSA_SHA512[]   = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 };
static const uint8_t OID_ED25519[]        = { 0x2B, 0x65, 0x70 };
static const uint8_t OID_ED448[]          = { 0x2B, 0x65, 0x71 };
static const uint8_t OID_RSA_V15_SHA256[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
static const uint8_t OID_RSA_V15_SHA384[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
static const uint8_t OID_RSA_V15_SHA512[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
static const uint8_t OID_RSA_PSS[]        = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
static const uint8_t OID_ECDSA_SHA1[]     = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01 };
static const uint8_t OID_RSA_V15_SHA1[]   = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
static const uint8_t OID_SM2_SM3[]        = { 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75 };
static const uint8_t OID_ECDSA_SHAKE128[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x20 };
static const uint8_t OID_ECDSA_SHAKE256[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x21 };
static const uint8_t OID_UNSIGNED[]        = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x24 };
/* DH Proof-of-Possession OIDs (RFC 6955 / C509 §9.1 Table 3, IDs 14–16) */
static const uint8_t OID_ECDHPOP_SHA256[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1A };
static const uint8_t OID_ECDHPOP_SHA384[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1B };
static const uint8_t OID_ECDHPOP_SHA512[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1C };

/* ── Public key algorithm OIDs ───────────────────────────────────────────── */
static const uint8_t OID_ID_EC_PUBKEY[]   = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OID_SECP256R1[]      = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_SECP384R1[]      = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_SECP521R1[]      = { 0x2B, 0x81, 0x04, 0x00, 0x23 };
static const uint8_t OID_BRAINPOOLP256R1[]= { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
static const uint8_t OID_BRAINPOOLP384R1[]= { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
static const uint8_t OID_BRAINPOOLP512R1[]= { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
static const uint8_t OID_FRP256V1[]       = { 0x2A, 0x81, 0x7A, 0x01, 0x81, 0x5F, 0x65, 0x82, 0x00, 0x01 };
static const uint8_t OID_SM2P256V1[]      = { 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D };
static const uint8_t OID_X25519[]         = { 0x2B, 0x65, 0x6E };
static const uint8_t OID_X448[]           = { 0x2B, 0x65, 0x6F };
static const uint8_t OID_RSA[]            = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

/* ── Extension OIDs ──────────────────────────────────────────────────────── */
static const uint8_t OID_EXT_SUBJECT_KEY_ID[]    = { 0x55, 0x1D, 0x0E };
static const uint8_t OID_EXT_KEY_USAGE[]         = { 0x55, 0x1D, 0x0F };
static const uint8_t OID_EXT_SUBJECT_ALT_NAME[]  = { 0x55, 0x1D, 0x11 };
static const uint8_t OID_EXT_BASIC_CONSTRAINTS[] = { 0x55, 0x1D, 0x13 };
static const uint8_t OID_EXT_CRL_DIST_POINTS[]   = { 0x55, 0x1D, 0x1F };
static const uint8_t OID_EXT_CERT_POLICIES[]     = { 0x55, 0x1D, 0x20 };
static const uint8_t OID_EXT_AUTHORITY_KEY_ID[]  = { 0x55, 0x1D, 0x23 };
static const uint8_t OID_EXT_EXT_KEY_USAGE[]     = { 0x55, 0x1D, 0x25 };
static const uint8_t OID_EXT_AIA[]               = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
static const uint8_t OID_EXT_SUBJECT_DIR_ATTR[]  = { 0x55, 0x1D, 0x09 };
static const uint8_t OID_EXT_NAME_CONSTRAINTS[]  = { 0x55, 0x1D, 0x1E };
static const uint8_t OID_EXT_POLICY_MAPPINGS[]   = { 0x55, 0x1D, 0x21 };
static const uint8_t OID_EXT_POLICY_CONSTRAINTS[]= { 0x55, 0x1D, 0x24 };
static const uint8_t OID_EXT_INHIBIT_ANY[]       = { 0x55, 0x1D, 0x36 };
static const uint8_t OID_EXT_OCSP_NO_CHECK[]     = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05 };
static const uint8_t OID_EXT_TLS_FEATURES[]      = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 };
static const uint8_t OID_EXT_IP_ADDR_BLOCKS[]    = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07 };
static const uint8_t OID_EXT_AS_IDENTIFIERS[]    = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08 };
static const uint8_t OID_EXT_IP_ADDR_BLOCKS_V2[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1C };
static const uint8_t OID_EXT_AS_IDENTIFIERS_V2[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1D };
static const uint8_t OID_EXT_FRESHEST_CRL[]      = { 0x55, 0x1D, 0x2E };
static const uint8_t OID_EXT_SUBJECT_INFO_ACCESS[]= { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B };

/* ── RSA-PSS hash algorithm OIDs ─────────────────────────────────────────── */
static const uint8_t OID_SHA256[]         = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t OID_SHA384[]         = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t OID_SHA512[]         = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
static const uint8_t OID_MGF1[]           = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };
/* id-RSASSA-PSS-SHAKE128 (1.3.6.1.5.5.7.6.30) and -SHAKE256 (1.3.6.1.5.5.7.6.31) */
static const uint8_t OID_RSA_PSS_SHAKE128_ALG[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1E };
static const uint8_t OID_RSA_PSS_SHAKE256_ALG[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x1F };

/* ── PKCS#9 attribute OIDs (used by CSR encoder) ────────────────────────── */
/* extensionRequest: 1.2.840.113549.1.9.14 */
static const uint8_t OID_PKCS9_EXT_REQ[]  = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0E };
/* challengePassword: 1.2.840.113549.1.9.7 */
static const uint8_t OID_PKCS9_CHAL_PWD[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x07 };
/* PrivKeyPossession (draft-ietf-cose-cbor-encoded-cert §8): 1.3.6.1.4.1.22112.48.2.1 */
static const uint8_t OID_PKCS9_PKS_STMT[] = { 0x2B,0x06,0x01,0x04,0x01,0x81,0xAC,0x60,0x02,0x01 };

/* ── RDN attribute OIDs ──────────────────────────────────────────────────── */
static const uint8_t OID_ATT_EMAIL[]             = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 };
static const uint8_t OID_ATT_COMMON_NAME[]       = { 0x55, 0x04, 0x03 };
static const uint8_t OID_ATT_SUR_NAME[]          = { 0x55, 0x04, 0x04 };
static const uint8_t OID_ATT_SERIAL_NUMBER[]     = { 0x55, 0x04, 0x05 };
static const uint8_t OID_ATT_COUNTRY[]           = { 0x55, 0x04, 0x06 };
static const uint8_t OID_ATT_LOCALITY[]          = { 0x55, 0x04, 0x07 };
static const uint8_t OID_ATT_STATE[]             = { 0x55, 0x04, 0x08 };
static const uint8_t OID_ATT_STREET[]            = { 0x55, 0x04, 0x09 };
static const uint8_t OID_ATT_ORGANIZATION[]      = { 0x55, 0x04, 0x0A };
static const uint8_t OID_ATT_ORG_UNIT[]          = { 0x55, 0x04, 0x0B };
static const uint8_t OID_ATT_TITLE[]             = { 0x55, 0x04, 0x0C };
static const uint8_t OID_ATT_BUSINESS_CATEGORY[] = { 0x55, 0x04, 0x0F };
static const uint8_t OID_ATT_POSTAL_CODE[]       = { 0x55, 0x04, 0x11 };
static const uint8_t OID_ATT_GIVEN_NAME[]        = { 0x55, 0x04, 0x2A };
static const uint8_t OID_ATT_INITIALS[]          = { 0x55, 0x04, 0x2B };
static const uint8_t OID_ATT_GENERATION_QUALIFIER[] = { 0x55, 0x04, 0x2C };
static const uint8_t OID_ATT_DN_QUALIFIER[]      = { 0x55, 0x04, 0x2E };
static const uint8_t OID_ATT_PSEUDONYM[]         = { 0x55, 0x04, 0x41 };
static const uint8_t OID_ATT_ORG_IDENTIFIER[]    = { 0x55, 0x04, 0x61 };
static const uint8_t OID_ATT_NAME[]              = { 0x55, 0x04, 0x29 };
static const uint8_t OID_ATT_TELEPHONE_NUMBER[]  = { 0x55, 0x04, 0x14 };
static const uint8_t OID_ATT_DIR_MAN_DOMAIN_NAME[] = { 0x55, 0x04, 0x36 };
/* 0.9.2342.19200300.100.1.x — X.500 pilot attributes */
static const uint8_t OID_ATT_USER_ID[]           = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01 };
static const uint8_t OID_ATT_DC[]                = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };
/* 1.2.840.113549.1.9.x — PKCS#9 attributes */
static const uint8_t OID_ATT_UNSTRUCTURED_NAME[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02 };
static const uint8_t OID_ATT_UNSTRUCTURED_ADDR[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x08 };
/* 1.3.6.1.4.1.311.60.2.1.x — EV jurisdiction attributes */
static const uint8_t OID_ATT_JURISDICTION_LOCALITY[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x01 };
static const uint8_t OID_ATT_JURISDICTION_STATE[]    = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x02 };
static const uint8_t OID_ATT_JURISDICTION_COUNTRY[]  = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x03 };

/* ── EKU OIDs ────────────────────────────────────────────────────────────── */
static const uint8_t OID_EKU_TLS_SERVER[]        = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const uint8_t OID_EKU_TLS_CLIENT[]        = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
static const uint8_t OID_EKU_CODE_SIGNING[]      = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
static const uint8_t OID_EKU_EMAIL_PROTECTION[]  = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
static const uint8_t OID_EKU_TIME_STAMPING[]     = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
static const uint8_t OID_EKU_OCSP_SIGNING[]      = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

/* ─────────────────────────────────────────────────────────────────────────── */

int x509_encode_algorithm_identifier(uint8_t *buffer, size_t size, size_t *offset, int64_t alg_id) {
    const uint8_t *oid;
    size_t oid_len;
    int needs_null = 0;

    switch (alg_id) {
        case C509_SIG_ECDSA_SHA256:  oid = OID_ECDSA_SHA256;   oid_len = sizeof(OID_ECDSA_SHA256);   break;
        case C509_SIG_ECDSA_SHA384:  oid = OID_ECDSA_SHA384;   oid_len = sizeof(OID_ECDSA_SHA384);   break;
        case C509_SIG_ECDSA_SHA512:  oid = OID_ECDSA_SHA512;   oid_len = sizeof(OID_ECDSA_SHA512);   break;
        case C509_SIG_ED25519:       oid = OID_ED25519;         oid_len = sizeof(OID_ED25519);         break;
        case C509_SIG_ED448:         oid = OID_ED448;           oid_len = sizeof(OID_ED448);           break;
        case C509_SIG_UNSIGNED:      oid = OID_UNSIGNED;        oid_len = sizeof(OID_UNSIGNED);        break;
        case C509_SIG_ECDSA_SHAKE128: oid = OID_ECDSA_SHAKE128; oid_len = sizeof(OID_ECDSA_SHAKE128);  break;
        case C509_SIG_ECDSA_SHAKE256: oid = OID_ECDSA_SHAKE256; oid_len = sizeof(OID_ECDSA_SHAKE256);  break;
        case C509_SIG_SM2_SM3:       oid = OID_SM2_SM3;         oid_len = sizeof(OID_SM2_SM3);         break;
        case C509_SIG_ECDHPOP_SHA256: oid = OID_ECDHPOP_SHA256; oid_len = sizeof(OID_ECDHPOP_SHA256);  break;
        case C509_SIG_ECDHPOP_SHA384: oid = OID_ECDHPOP_SHA384; oid_len = sizeof(OID_ECDHPOP_SHA384);  break;
        case C509_SIG_ECDHPOP_SHA512: oid = OID_ECDHPOP_SHA512; oid_len = sizeof(OID_ECDHPOP_SHA512);  break;
        case C509_SIG_ECDSA_SHA1:    oid = OID_ECDSA_SHA1;      oid_len = sizeof(OID_ECDSA_SHA1);      break;
        case C509_SIG_RSA_V15_SHA1:  oid = OID_RSA_V15_SHA1;    oid_len = sizeof(OID_RSA_V15_SHA1);    needs_null = 1; break;
        case C509_SIG_RSA_V15_SHA256:oid = OID_RSA_V15_SHA256;  oid_len = sizeof(OID_RSA_V15_SHA256);  needs_null = 1; break;
        case C509_SIG_RSA_V15_SHA384:oid = OID_RSA_V15_SHA384;  oid_len = sizeof(OID_RSA_V15_SHA384);  needs_null = 1; break;
        case C509_SIG_RSA_V15_SHA512:oid = OID_RSA_V15_SHA512;  oid_len = sizeof(OID_RSA_V15_SHA512);  needs_null = 1; break;
        case C509_SIG_RSA_PSS_SHAKE128:
        case C509_SIG_RSA_PSS_SHAKE256: break; /* handled separately below */
        case C509_SIG_RSA_PSS_SHA256:
        case C509_SIG_RSA_PSS_SHA384:
        case C509_SIG_RSA_PSS_SHA512:   oid = OID_RSA_PSS; oid_len = sizeof(OID_RSA_PSS); break;
        default: return -1;
    }

    /* RSA-PSS SHAKE variants use a combined OID (no params) */
    if (alg_id == C509_SIG_RSA_PSS_SHAKE128 || alg_id == C509_SIG_RSA_PSS_SHAKE256) {
        const uint8_t *shake_oid = (alg_id == C509_SIG_RSA_PSS_SHAKE128)
                                   ? OID_RSA_PSS_SHAKE128_ALG : OID_RSA_PSS_SHAKE256_ALG;
        size_t shake_oid_len = (alg_id == C509_SIG_RSA_PSS_SHAKE128)
                               ? sizeof(OID_RSA_PSS_SHAKE128_ALG) : sizeof(OID_RSA_PSS_SHAKE256_ALG);
        uint8_t inner[16]; size_t inner_off = 0;
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, shake_oid_len);
        memcpy(inner + inner_off, shake_oid, shake_oid_len); inner_off += shake_oid_len;
        if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, inner_off) != 0) return -1;
        memcpy(buffer + *offset, inner, inner_off); *offset += inner_off;
        return 0;
    }

    /* RSA-PSS SHA256/384/512 need explicit PSS parameters */
    if (alg_id == C509_SIG_RSA_PSS_SHA256 || alg_id == C509_SIG_RSA_PSS_SHA384
        || alg_id == C509_SIG_RSA_PSS_SHA512) {
        const uint8_t *hash_oid;
        size_t         hash_oid_len;
        uint8_t        salt_byte;
        if (alg_id == C509_SIG_RSA_PSS_SHA256) {
            hash_oid = OID_SHA256; hash_oid_len = sizeof(OID_SHA256); salt_byte = 0x20;
        } else if (alg_id == C509_SIG_RSA_PSS_SHA384) {
            hash_oid = OID_SHA384; hash_oid_len = sizeof(OID_SHA384); salt_byte = 0x30;
        } else {
            hash_oid = OID_SHA512; hash_oid_len = sizeof(OID_SHA512); salt_byte = 0x40;
        }
        /* hashAlgorithm SEQUENCE { OID, NULL } */
        uint8_t ha[16]; size_t ha_off = 0;
        ha[ha_off++] = DER_TAG_OID;
        ha[ha_off++] = (uint8_t)hash_oid_len;
        memcpy(ha + ha_off, hash_oid, hash_oid_len); ha_off += hash_oid_len;
        ha[ha_off++] = 0x05; ha[ha_off++] = 0x00;
        uint8_t ha_seq[18]; size_t ha_seq_off = 0;
        der_write_tag_len(ha_seq, sizeof(ha_seq), &ha_seq_off, DER_TAG_SEQUENCE, ha_off);
        memcpy(ha_seq + ha_seq_off, ha, ha_off); ha_seq_off += ha_off;
        /* [0] hash, [1] mgf1(hash), [2] saltLen */
        uint8_t params[96]; size_t p = 0;
        params[p++] = 0xA0; params[p++] = (uint8_t)ha_seq_off;
        memcpy(params + p, ha_seq, ha_seq_off); p += ha_seq_off;
        uint8_t mgf_seq[32]; size_t ms = 0;
        der_write_tag_len(mgf_seq, sizeof(mgf_seq), &ms, DER_TAG_OID, sizeof(OID_MGF1));
        memcpy(mgf_seq + ms, OID_MGF1, sizeof(OID_MGF1)); ms += sizeof(OID_MGF1);
        memcpy(mgf_seq + ms, ha_seq, ha_seq_off); ms += ha_seq_off;
        uint8_t mgf_outer[40]; size_t mo = 0;
        der_write_tag_len(mgf_outer, sizeof(mgf_outer), &mo, DER_TAG_SEQUENCE, ms);
        memcpy(mgf_outer + mo, mgf_seq, ms); mo += ms;
        params[p++] = 0xA1; params[p++] = (uint8_t)mo;
        memcpy(params + p, mgf_outer, mo); p += mo;
        params[p++] = 0xA2; params[p++] = 0x03;
        params[p++] = 0x02; params[p++] = 0x01; params[p++] = salt_byte;
        /* params SEQUENCE */
        uint8_t pss_params[100]; size_t pp = 0;
        der_write_tag_len(pss_params, sizeof(pss_params), &pp, DER_TAG_SEQUENCE, p);
        memcpy(pss_params + pp, params, p); pp += p;
        /* AlgorithmIdentifier SEQUENCE { OID id-RSASSA-PSS, pss_params } */
        uint8_t inner[120]; size_t inner_off = 0;
        inner[inner_off++] = DER_TAG_OID;
        inner[inner_off++] = (uint8_t)sizeof(OID_RSA_PSS);
        memcpy(inner + inner_off, OID_RSA_PSS, sizeof(OID_RSA_PSS)); inner_off += sizeof(OID_RSA_PSS);
        memcpy(inner + inner_off, pss_params, pp); inner_off += pp;
        if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, inner_off) != 0) return -1;
        memcpy(buffer + *offset, inner, inner_off); *offset += inner_off;
        return 0;
    }

    uint8_t inner[32]; size_t inner_off = 0;
    der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, oid_len);
    memcpy(inner + inner_off, oid, oid_len); inner_off += oid_len;
    if (needs_null) {
        inner[inner_off++] = 0x05; /* NULL */
        inner[inner_off++] = 0x00;
    }

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, inner_off) != 0) return -1;
    memcpy(buffer + *offset, inner, inner_off); *offset += inner_off;
    return 0;
}

int x509_encode_ec_public_key_alg(uint8_t *buffer, size_t size, size_t *offset, int64_t pk_alg_id) {
    uint8_t inner[64]; size_t inner_off = 0;

    if (pk_alg_id == C509_PK_ED25519) {
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_ED25519));
        memcpy(inner + inner_off, OID_ED25519, sizeof(OID_ED25519));
        inner_off += sizeof(OID_ED25519);
    } else if (pk_alg_id == C509_PK_ED448) {
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_ED448));
        memcpy(inner + inner_off, OID_ED448, sizeof(OID_ED448));
        inner_off += sizeof(OID_ED448);
    } else if (pk_alg_id == C509_PK_X25519) {
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_X25519));
        memcpy(inner + inner_off, OID_X25519, sizeof(OID_X25519));
        inner_off += sizeof(OID_X25519);
    } else if (pk_alg_id == C509_PK_X448) {
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_X448));
        memcpy(inner + inner_off, OID_X448, sizeof(OID_X448));
        inner_off += sizeof(OID_X448);
    } else if (pk_alg_id == C509_PK_RSA) {
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_RSA));
        memcpy(inner + inner_off, OID_RSA, sizeof(OID_RSA));
        inner_off += sizeof(OID_RSA);
        inner[inner_off++] = 0x05; /* NULL — required in RSA SPKI AlgorithmIdentifier */
        inner[inner_off++] = 0x00;
    } else {
        const uint8_t *curve_oid;
        size_t curve_oid_len;
        switch (pk_alg_id) {
            case C509_PK_SECP256R1:      curve_oid = OID_SECP256R1;       curve_oid_len = sizeof(OID_SECP256R1);       break;
            case C509_PK_SECP384R1:      curve_oid = OID_SECP384R1;       curve_oid_len = sizeof(OID_SECP384R1);       break;
            case C509_PK_SECP521R1:      curve_oid = OID_SECP521R1;       curve_oid_len = sizeof(OID_SECP521R1);       break;
            case C509_PK_BRAINPOOLP256R1:curve_oid = OID_BRAINPOOLP256R1; curve_oid_len = sizeof(OID_BRAINPOOLP256R1); break;
            case C509_PK_BRAINPOOLP384R1:curve_oid = OID_BRAINPOOLP384R1; curve_oid_len = sizeof(OID_BRAINPOOLP384R1); break;
            case C509_PK_BRAINPOOLP512R1:curve_oid = OID_BRAINPOOLP512R1; curve_oid_len = sizeof(OID_BRAINPOOLP512R1); break;
            case C509_PK_FRP256V1:       curve_oid = OID_FRP256V1;        curve_oid_len = sizeof(OID_FRP256V1);        break;
            case C509_PK_SM2P256V1:      curve_oid = OID_SM2P256V1;       curve_oid_len = sizeof(OID_SM2P256V1);       break;
            default: return -1;
        }
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_ID_EC_PUBKEY));
        memcpy(inner + inner_off, OID_ID_EC_PUBKEY, sizeof(OID_ID_EC_PUBKEY));
        inner_off += sizeof(OID_ID_EC_PUBKEY);
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, curve_oid_len);
        memcpy(inner + inner_off, curve_oid, curve_oid_len);
        inner_off += curve_oid_len;
    }

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, inner_off) != 0) return -1;
    memcpy(buffer + *offset, inner, inner_off); *offset += inner_off;
    return 0;
}

int x509_encode_validity_time(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *time_val) {
    /* CBOR simple value 22 (null) = perpetual: "99991231235959Z" as GeneralizedTime */
    if (time_val->type == CBOR_TYPE_SIMPLE && time_val->val == 22) {
        static const char perpetual[] = "99991231235959Z";
        if (der_write_tag_len(buffer, size, offset, DER_TAG_GEN_TIME, 15) != 0) return -1;
        memcpy(buffer + *offset, perpetual, 15); *offset += 15;
        return 0;
    }

    char ts_str[16];
    int64_t unix_time = (int64_t)time_val->val;
    if (c509_unix_to_utc_string(unix_time, ts_str) != 0) return -1;

    if (unix_time >= UNIX_2050) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ = 15 chars */
        if (der_write_tag_len(buffer, size, offset, DER_TAG_GEN_TIME, 15) != 0) return -1;
        memcpy(buffer + *offset, ts_str, 15); *offset += 15;
    } else {
        /* UTCTime: YYMMDDHHMMSSZ = 13 chars */
        if (der_write_tag_len(buffer, size, offset, DER_TAG_UTC_TIME, 13) != 0) return -1;
        memcpy(buffer + *offset, ts_str, 13); *offset += 13;
    }
    return 0;
}

int x509_encode_name(uint8_t *buffer, size_t size, size_t *offset,
                     const cbor_value_t *name, const cbor_value_t *subject) {
    /* CBOR simple value 22 = same as issuer (use subject instead) */
    const cbor_value_t *actual_name = name;
    if (name->type == CBOR_TYPE_SIMPLE && name->val == 22 && subject != NULL) {
        actual_name = subject;
    }

    uint8_t rdn_seq_buf[1024]; size_t rdn_seq_off = 0;

    if (actual_name->type == CBOR_TYPE_ARRAY) {
        /* Array of [attr_id, attr_val, ...] pairs */
        cbor_context_t sub_ctx;
        cbor_init_sub_context(&sub_ctx, actual_name);
        for (uint64_t i = 0; i < actual_name->val; i += 2) {
            cbor_value_t attr_id, attr_val;
            if (cbor_decode_next(&sub_ctx, &attr_id) != CBOR_ERR_NONE) return -1;
            if (cbor_decode_next(&sub_ctx, &attr_val) != CBOR_ERR_NONE) return -1;

            /* BSTR attr_id = raw OID body; BSTR attr_val = pre-encoded DER TLV.
             * Used by §7 certs with non-standard string types (e.g. IA5String CN). */
            if (attr_id.type == CBOR_TYPE_BSTR) {
                if (attr_val.type != CBOR_TYPE_BSTR) return -1;
                uint8_t atv_inner[256]; size_t atv_inner_off = 0;
                der_write_tag_len(atv_inner, sizeof(atv_inner), &atv_inner_off,
                                  DER_TAG_OID, (size_t)attr_id.val);
                memcpy(atv_inner + atv_inner_off, attr_id.ptr, (size_t)attr_id.val);
                atv_inner_off += (size_t)attr_id.val;
                memcpy(atv_inner + atv_inner_off, attr_val.ptr, (size_t)attr_val.val);
                atv_inner_off += (size_t)attr_val.val;
                size_t seq_size = der_get_tag_len_size(DER_TAG_SEQUENCE, atv_inner_off) + atv_inner_off;
                der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SET, seq_size);
                der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SEQUENCE, atv_inner_off);
                memcpy(rdn_seq_buf + rdn_seq_off, atv_inner, atv_inner_off); rdn_seq_off += atv_inner_off;
                continue;
            }

            int64_t id = (attr_id.type == CBOR_TYPE_UINT)
                         ? (int64_t)attr_id.val
                         : -(int64_t)(attr_id.val + 1);
            /* Negative id = NINT encoding = PrintableString variant (per draft §7.1) */
            int64_t abs_id = (id < 0) ? -id : id;

            const uint8_t *oid = OID_ATT_COMMON_NAME;
            size_t oid_len = sizeof(OID_ATT_COMMON_NAME);
            /* Default: UTF8String for UINT ids, PrintableString for NINT ids */
            uint8_t str_tag = (id < 0) ? DER_TAG_PRINTABLE_STRING : DER_TAG_UTF8_STRING;

            switch (abs_id) {
                case C509_ATT_EMAIL:
                    oid = OID_ATT_EMAIL; oid_len = sizeof(OID_ATT_EMAIL);
                    str_tag = DER_TAG_IA5_STRING;
                    break;
                case C509_ATT_COMMON_NAME:
                    /* default oid; str_tag set above */
                    break;
                case C509_ATT_SUR_NAME:
                    oid = OID_ATT_SUR_NAME; oid_len = sizeof(OID_ATT_SUR_NAME);
                    break;
                case C509_ATT_SERIAL_NUMBER:
                    oid = OID_ATT_SERIAL_NUMBER; oid_len = sizeof(OID_ATT_SERIAL_NUMBER);
                    break;
                case C509_ATT_COUNTRY:
                    oid = OID_ATT_COUNTRY; oid_len = sizeof(OID_ATT_COUNTRY);
                    break;
                case C509_ATT_LOCALITY:
                    oid = OID_ATT_LOCALITY; oid_len = sizeof(OID_ATT_LOCALITY);
                    break;
                case C509_ATT_STATE_OR_PROVINCE:
                    oid = OID_ATT_STATE; oid_len = sizeof(OID_ATT_STATE);
                    break;
                case C509_ATT_STREET_ADDRESS:
                    oid = OID_ATT_STREET; oid_len = sizeof(OID_ATT_STREET);
                    break;
                case C509_ATT_ORGANIZATION:
                    oid = OID_ATT_ORGANIZATION; oid_len = sizeof(OID_ATT_ORGANIZATION);
                    break;
                case C509_ATT_ORGANIZATION_UNIT:
                    oid = OID_ATT_ORG_UNIT; oid_len = sizeof(OID_ATT_ORG_UNIT);
                    break;
                case C509_ATT_TITLE:
                    oid = OID_ATT_TITLE; oid_len = sizeof(OID_ATT_TITLE);
                    break;
                case C509_ATT_BUSINESS_CATEGORY:
                    oid = OID_ATT_BUSINESS_CATEGORY; oid_len = sizeof(OID_ATT_BUSINESS_CATEGORY);
                    break;
                case C509_ATT_POSTAL_CODE:
                    oid = OID_ATT_POSTAL_CODE; oid_len = sizeof(OID_ATT_POSTAL_CODE);
                    break;
                case C509_ATT_GIVEN_NAME:
                    oid = OID_ATT_GIVEN_NAME; oid_len = sizeof(OID_ATT_GIVEN_NAME);
                    break;
                case C509_ATT_INITIALS:
                    oid = OID_ATT_INITIALS; oid_len = sizeof(OID_ATT_INITIALS);
                    break;
                case C509_ATT_GENERATION_QUALIFIER:
                    oid = OID_ATT_GENERATION_QUALIFIER; oid_len = sizeof(OID_ATT_GENERATION_QUALIFIER);
                    break;
                case C509_ATT_DN_QUALIFIER:
                    oid = OID_ATT_DN_QUALIFIER; oid_len = sizeof(OID_ATT_DN_QUALIFIER);
                    break;
                case C509_ATT_PSEUDONYM:
                    oid = OID_ATT_PSEUDONYM; oid_len = sizeof(OID_ATT_PSEUDONYM);
                    break;
                case C509_ATT_ORGANIZATION_IDENTIFIER:
                    oid = OID_ATT_ORG_IDENTIFIER; oid_len = sizeof(OID_ATT_ORG_IDENTIFIER);
                    break;
                case C509_ATT_JURISDICTION_LOCALITY:
                    oid = OID_ATT_JURISDICTION_LOCALITY; oid_len = sizeof(OID_ATT_JURISDICTION_LOCALITY);
                    break;
                case C509_ATT_JURISDICTION_STATE:
                    oid = OID_ATT_JURISDICTION_STATE; oid_len = sizeof(OID_ATT_JURISDICTION_STATE);
                    break;
                case C509_ATT_JURISDICTION_COUNTRY:
                    oid = OID_ATT_JURISDICTION_COUNTRY; oid_len = sizeof(OID_ATT_JURISDICTION_COUNTRY);
                    break;
                case C509_ATT_DOMAIN_COMPONENT:
                    oid = OID_ATT_DC; oid_len = sizeof(OID_ATT_DC);
                    str_tag = DER_TAG_IA5_STRING;
                    break;
                case C509_ATT_NAME:
                    oid = OID_ATT_NAME; oid_len = sizeof(OID_ATT_NAME);
                    break;
                case C509_ATT_TELEPHONE_NUMBER:
                    oid = OID_ATT_TELEPHONE_NUMBER; oid_len = sizeof(OID_ATT_TELEPHONE_NUMBER);
                    break;
                case C509_ATT_DIR_MAN_DOMAIN_NAME:
                    oid = OID_ATT_DIR_MAN_DOMAIN_NAME; oid_len = sizeof(OID_ATT_DIR_MAN_DOMAIN_NAME);
                    break;
                case C509_ATT_USER_ID:
                    oid = OID_ATT_USER_ID; oid_len = sizeof(OID_ATT_USER_ID);
                    break;
                case C509_ATT_UNSTRUCTURED_NAME:
                    oid = OID_ATT_UNSTRUCTURED_NAME; oid_len = sizeof(OID_ATT_UNSTRUCTURED_NAME);
                    break;
                case C509_ATT_UNSTRUCTURED_ADDRESS:
                    oid = OID_ATT_UNSTRUCTURED_ADDR; oid_len = sizeof(OID_ATT_UNSTRUCTURED_ADDR);
                    break;
                default:
                    break;
            }

            uint8_t atv_inner[256]; size_t atv_inner_off = 0;
            der_write_tag_len(atv_inner, sizeof(atv_inner), &atv_inner_off, DER_TAG_OID, oid_len);
            memcpy(atv_inner + atv_inner_off, oid, oid_len); atv_inner_off += oid_len;
            der_write_tag_len(atv_inner, sizeof(atv_inner), &atv_inner_off, str_tag, (size_t)attr_val.val);
            memcpy(atv_inner + atv_inner_off, attr_val.ptr, (size_t)attr_val.val);
            atv_inner_off += (size_t)attr_val.val;

            size_t seq_size = der_get_tag_len_size(DER_TAG_SEQUENCE, atv_inner_off) + atv_inner_off;
            der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SET, seq_size);
            der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SEQUENCE, atv_inner_off);
            memcpy(rdn_seq_buf + rdn_seq_off, atv_inner, atv_inner_off); rdn_seq_off += atv_inner_off;
        }
    } else {
        /* TSTR: single CommonName as UTF-8.
         * BSTR: binary CN — hex-encode to reconstruct the string.
         * TAG 48: EUI-48/64 CN — format as "XX-XX-XX-FF-FE-XX-XX-XX" (EUI-64). */
        char hex_buf[64];
        const uint8_t *name_ptr;
        size_t name_len;
        if (actual_name->type == CBOR_TYPE_TAG && actual_name->val == 48) {
            /* ptr points to the inner bstr header; skip it to get the bytes */
            cbor_context_t tag_ctx;
            cbor_value_t inner;
            tag_ctx.buffer = actual_name->ptr;
            tag_ctx.size   = 65536;
            tag_ctx.offset = 0;
            if (cbor_decode_next(&tag_ctx, &inner) != CBOR_ERR_NONE) return -1;
            const uint8_t *b = inner.ptr;
            size_t blen = (size_t)inner.val;
            /* Format as EUI-64: for 6-byte (EUI-48) input, insert "FF-FE" after byte 3 */
            size_t hoff = 0;
            for (size_t i = 0; i < blen; i++) {
                hoff += (size_t)snprintf(hex_buf + hoff, sizeof(hex_buf) - hoff, "%02X", b[i]);
                if (i == 2 && blen == 6) {
                    hoff += (size_t)snprintf(hex_buf + hoff, sizeof(hex_buf) - hoff, "-FF-FE");
                }
                if (i < blen - 1) hex_buf[hoff++] = '-';
            }
            name_ptr = (const uint8_t *)hex_buf;
            name_len = hoff;
        } else if (actual_name->type == CBOR_TYPE_BSTR) {
            size_t raw_len = (size_t)actual_name->val;
            if (raw_len * 2 > sizeof(hex_buf)) return -1;
            bin_to_hex(actual_name->ptr, raw_len, hex_buf);
            name_ptr = (const uint8_t *)hex_buf;
            name_len = raw_len * 2;
        } else {
            name_ptr = actual_name->ptr;
            name_len = (size_t)actual_name->val;
        }
        uint8_t atv_inner[256]; size_t atv_inner_off = 0;
        der_write_tag_len(atv_inner, sizeof(atv_inner), &atv_inner_off,
                          DER_TAG_OID, sizeof(OID_ATT_COMMON_NAME));
        memcpy(atv_inner + atv_inner_off, OID_ATT_COMMON_NAME, sizeof(OID_ATT_COMMON_NAME));
        atv_inner_off += sizeof(OID_ATT_COMMON_NAME);
        der_write_tag_len(atv_inner, sizeof(atv_inner), &atv_inner_off, DER_TAG_UTF8_STRING, name_len);
        memcpy(atv_inner + atv_inner_off, name_ptr, name_len); atv_inner_off += name_len;

        size_t seq_size = der_get_tag_len_size(DER_TAG_SEQUENCE, atv_inner_off) + atv_inner_off;
        der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SET, seq_size);
        der_write_tag_len(rdn_seq_buf, sizeof(rdn_seq_buf), &rdn_seq_off, DER_TAG_SEQUENCE, atv_inner_off);
        memcpy(rdn_seq_buf + rdn_seq_off, atv_inner, atv_inner_off); rdn_seq_off += atv_inner_off;
    }

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, rdn_seq_off) != 0) return -1;
    memcpy(buffer + *offset, rdn_seq_buf, rdn_seq_off); *offset += rdn_seq_off;
    return 0;
}

/* IssuerAltName OID (2.5.29.18) — not in the main OID block above */
static const uint8_t OID_EXT_ISSUER_ALT_NAME[] = { 0x55, 0x1D, 0x12 };

/* Skip the content of a CBOR value whose header was already consumed by
 * cbor_decode_next.  For ARRAY/MAP the elements remain in ctx; for
 * BSTR/TSTR/UINT/NINT the content was already consumed. */
static void cbor_skip_val_contents(cbor_context_t *ctx, const cbor_value_t *val) {
    if (val->type == CBOR_TYPE_ARRAY) {
        for (uint64_t i = 0; i < val->val; i++) cbor_skip_item(ctx);
    } else if (val->type == CBOR_TYPE_MAP) {
        for (uint64_t i = 0; i < val->val * 2; i++) cbor_skip_item(ctx);
    }
}

/* Encode a single C509 GeneralName (type integer + data cbor_value) into DER.
 * Returns bytes written, or 0 for unsupported/error. */
static size_t encode_general_name(uint8_t *buf, size_t buf_size,
                                   int64_t gn_type, const cbor_value_t *gn_val) {
    size_t off = 0;

    /* rfc822Name [1], dNSName [2], uniformResourceIdentifier [6] — IMPLICIT string */
    if (gn_type == 1 || gn_type == 2 || gn_type == 6) {
        uint8_t tag = (gn_type == 1) ? 0x81 : (gn_type == 2) ? 0x82 : 0x86;
        if (gn_val->type != CBOR_TYPE_BSTR && gn_val->type != CBOR_TYPE_TSTR) return 0;
        size_t len = (size_t)gn_val->val;
        if (der_write_tag_len(buf, buf_size, &off, tag, len) != 0) return 0;
        memcpy(buf + off, gn_val->ptr, len);
        return off + len;
    }

    /* iPAddress [7] IMPLICIT OCTET STRING */
    if (gn_type == 7) {
        if (gn_val->type != CBOR_TYPE_BSTR && gn_val->type != CBOR_TYPE_TSTR) return 0;
        size_t len = (size_t)gn_val->val;
        if (der_write_tag_len(buf, buf_size, &off, 0x87, len) != 0) return 0;
        memcpy(buf + off, gn_val->ptr, len);
        return off + len;
    }

    /* registeredID [8] IMPLICIT OID — gn_val is BSTR of OID value bytes */
    if (gn_type == 8) {
        if (gn_val->type != CBOR_TYPE_BSTR) return 0;
        size_t len = (size_t)gn_val->val;
        if (der_write_tag_len(buf, buf_size, &off, 0x88, len) != 0) return 0;
        memcpy(buf + off, gn_val->ptr, len);
        return off + len;
    }

    /* directoryName [4] EXPLICIT Name — gn_val is C509 name (array or tstr) */
    if (gn_type == 4) {
        if (gn_val->type != CBOR_TYPE_ARRAY && gn_val->type != CBOR_TYPE_TSTR && gn_val->type != CBOR_TYPE_BSTR) return 0;
        uint8_t name_buf[256]; size_t name_off = 0;
        if (x509_encode_name(name_buf, sizeof(name_buf), &name_off, gn_val, NULL) != 0) return 0;
        if (der_write_tag_len(buf, buf_size, &off, 0xA4, name_off) != 0) return 0;
        memcpy(buf + off, name_buf, name_off);
        return off + name_off;
    }

    /* otherName [0] IMPLICIT — gn_val is ARRAY(2)[bstr:OID-bytes, bstr:DER-value] */
    if (gn_type == 0) {
        if (gn_val->type != CBOR_TYPE_ARRAY || gn_val->val < 2) return 0;
        cbor_context_t on_ctx;
        cbor_init_sub_context(&on_ctx, gn_val);
        cbor_value_t oid_val, v_val;
        if (cbor_decode_next(&on_ctx, &oid_val) != CBOR_ERR_NONE) return 0;
        if (cbor_decode_next(&on_ctx, &v_val) != CBOR_ERR_NONE) return 0;
        if (oid_val.type != CBOR_TYPE_BSTR || v_val.type != CBOR_TYPE_BSTR) return 0;
        size_t oid_len = (size_t)oid_val.val;
        size_t v_len   = (size_t)v_val.val;
        uint8_t inner[512]; size_t inner_off = 0;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, oid_len) != 0) return 0;
        memcpy(inner + inner_off, oid_val.ptr, oid_len); inner_off += oid_len;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, 0xA0, v_len) != 0) return 0;
        memcpy(inner + inner_off, v_val.ptr, v_len); inner_off += v_len;
        if (der_write_tag_len(buf, buf_size, &off, 0xA0, inner_off) != 0) return 0;
        memcpy(buf + off, inner, inner_off);
        return off + inner_off;
    }

    /* SmtpUTF8Mailbox compact (NINT -2) — TSTR value
     * → otherName { OID 1.3.6.1.5.5.7.8.9, [0] EXPLICIT UTF8String } */
    if (gn_type == -2) {
        if (gn_val->type != CBOR_TYPE_TSTR) return 0;
        static const uint8_t OID_SMTP[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x08,0x09};
        size_t email_len = (size_t)gn_val->val;
        uint8_t inner[256]; size_t inner_off = 0;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_SMTP)) != 0) return 0;
        memcpy(inner + inner_off, OID_SMTP, sizeof(OID_SMTP)); inner_off += sizeof(OID_SMTP);
        uint8_t utf8_enc[256]; size_t utf8_off = 0;
        if (der_write_tag_len(utf8_enc, sizeof(utf8_enc), &utf8_off, DER_TAG_UTF8_STRING, email_len) != 0) return 0;
        memcpy(utf8_enc + utf8_off, gn_val->ptr, email_len); utf8_off += email_len;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, 0xA0, utf8_off) != 0) return 0;
        memcpy(inner + inner_off, utf8_enc, utf8_off); inner_off += utf8_off;
        if (der_write_tag_len(buf, buf_size, &off, 0xA0, inner_off) != 0) return 0;
        memcpy(buf + off, inner, inner_off);
        return off + inner_off;
    }

    /* hardwareModuleName compact (NINT -1) — ARRAY(2)[bstr:hwType-OID, bstr:hwSerial]
     * → otherName { OID 1.3.6.1.5.5.7.8.4, [0] EXPLICIT SEQUENCE { OID(hwType), OCTET STRING(hwSerial) } } */
    if (gn_type == -1) {
        if (gn_val->type != CBOR_TYPE_ARRAY || gn_val->val < 2) return 0;
        static const uint8_t OID_HW[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x08,0x04};
        cbor_context_t hw_ctx;
        cbor_init_sub_context(&hw_ctx, gn_val);
        cbor_value_t hw_oid_val, hw_ser_val;
        if (cbor_decode_next(&hw_ctx, &hw_oid_val) != CBOR_ERR_NONE) return 0;
        if (cbor_decode_next(&hw_ctx, &hw_ser_val) != CBOR_ERR_NONE) return 0;
        if (hw_oid_val.type != CBOR_TYPE_BSTR || hw_ser_val.type != CBOR_TYPE_BSTR) return 0;
        size_t hoid_len = (size_t)hw_oid_val.val;
        size_t hser_len = (size_t)hw_ser_val.val;
        uint8_t hwseq[256]; size_t hwseq_off = 0;
        if (der_write_tag_len(hwseq, sizeof(hwseq), &hwseq_off, DER_TAG_OID, hoid_len) != 0) return 0;
        memcpy(hwseq + hwseq_off, hw_oid_val.ptr, hoid_len); hwseq_off += hoid_len;
        if (der_write_tag_len(hwseq, sizeof(hwseq), &hwseq_off, DER_TAG_OCTET_STRING, hser_len) != 0) return 0;
        memcpy(hwseq + hwseq_off, hw_ser_val.ptr, hser_len); hwseq_off += hser_len;
        uint8_t inner[512]; size_t inner_off = 0;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_HW)) != 0) return 0;
        memcpy(inner + inner_off, OID_HW, sizeof(OID_HW)); inner_off += sizeof(OID_HW);
        uint8_t a0_seq[256]; size_t a0_seq_off = 0;
        if (der_write_tag_len(a0_seq, sizeof(a0_seq), &a0_seq_off, DER_TAG_SEQUENCE, hwseq_off) != 0) return 0;
        memcpy(a0_seq + a0_seq_off, hwseq, hwseq_off); a0_seq_off += hwseq_off;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, 0xA0, a0_seq_off) != 0) return 0;
        memcpy(inner + inner_off, a0_seq, a0_seq_off); inner_off += a0_seq_off;
        if (der_write_tag_len(buf, buf_size, &off, 0xA0, inner_off) != 0) return 0;
        memcpy(buf + off, inner, inner_off);
        return off + inner_off;
    }

    /* OtherName OID 1.3.6.1.5.5.7.8.12 compact (NINT -3) — TSTR or BSTR value
     * → otherName [0] IMPLICIT { OID 1.3.6.1.5.5.7.8.12, [0] EXPLICIT UTF8String/OCTET_STRING } */
    if (gn_type == -3) {
        static const uint8_t OID_12[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x08,0x0C};
        if (gn_val->type != CBOR_TYPE_TSTR && gn_val->type != CBOR_TYPE_BSTR) return 0;
        size_t vlen = (size_t)gn_val->val;
        uint8_t str_tag = (gn_val->type == CBOR_TYPE_TSTR) ? DER_TAG_UTF8_STRING : DER_TAG_OCTET_STRING;
        uint8_t enc[256]; size_t enc_off = 0;
        if (der_write_tag_len(enc, sizeof(enc), &enc_off, str_tag, vlen) != 0) return 0;
        memcpy(enc + enc_off, gn_val->ptr, vlen); enc_off += vlen;
        uint8_t inner[256]; size_t inner_off = 0;
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_12)) != 0) return 0;
        memcpy(inner + inner_off, OID_12, sizeof(OID_12)); inner_off += sizeof(OID_12);
        if (der_write_tag_len(inner, sizeof(inner), &inner_off, 0xA0, enc_off) != 0) return 0;
        memcpy(inner + inner_off, enc, enc_off); inner_off += enc_off;
        if (der_write_tag_len(buf, buf_size, &off, 0xA0, inner_off) != 0) return 0;
        memcpy(buf + off, inner, inner_off);
        return off + inner_off;
    }

    return 0;
}

/* Map a C509 compact certificate policy int ID to its DER OID value bytes.
 * Returns bytes written to out, or 0 if unknown. */
static size_t cp_policy_oid(int64_t cp_id, uint8_t *out, size_t out_size) {
    static const uint8_t ANY_POL[]  = {0x55,0x1D,0x20,0x00};
    static const uint8_t DV[]       = {0x67,0x81,0x0C,0x01,0x02,0x01};
    static const uint8_t OV[]       = {0x67,0x81,0x0C,0x01,0x02,0x02};
    static const uint8_t IV[]       = {0x67,0x81,0x0C,0x01,0x02,0x03};
    static const uint8_t EV[]       = {0x67,0x81,0x0C,0x01,0x01};
    static const uint8_t RPKI[]     = {0x2B,0x06,0x01,0x05,0x05,0x07,0x0E,0x02};
    static const uint8_t RPKI_ALT[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x0E,0x03};
    const uint8_t *p = NULL; size_t n = 0;
    uint8_t rsp[7] = {0x67,0x81,0x12,0x01,0x02,0x01,0x00};
    switch (cp_id) {
        case 0:  p = ANY_POL;  n = sizeof(ANY_POL);  break;
        case 1:  p = DV;       n = sizeof(DV);        break;
        case 2:  p = OV;       n = sizeof(OV);        break;
        case 3:  p = IV;       n = sizeof(IV);        break;
        case 4:  p = EV;       n = sizeof(EV);        break;
        case 7:  p = RPKI;     n = sizeof(RPKI);      break;
        case 8:  p = RPKI_ALT; n = sizeof(RPKI_ALT);  break;
        case 24: rsp[6]=0x00; p=rsp; n=7; break;
        case 25: rsp[6]=0x01; p=rsp; n=7; break;
        case 27: rsp[6]=0x02; p=rsp; n=7; break;
        case 29: rsp[6]=0x03; p=rsp; n=7; break;
        case 31: rsp[6]=0x04; p=rsp; n=7; break;
        case 33: rsp[6]=0x05; p=rsp; n=7; break;
        case 35: rsp[6]=0x06; p=rsp; n=7; break;
        case 37: rsp[6]=0x07; p=rsp; n=7; break;
        default: return 0;
    }
    if (n > out_size) return 0;
    memcpy(out, p, n);
    return n;
}

/* Encode one C509 DistributionPoint element into DER DistributionPoint SEQUENCE.
 * dp_elem may be tstr/bstr (single URI) or array(1..3)[uri_or_list, reasons_uint?, issuer_name?].
 * Returns bytes written to buf, or 0 on error/unsupported. */
static size_t encode_dist_point(uint8_t *buf, size_t buf_size, const cbor_value_t *dp_elem)
{
    uint8_t fn_gns[600]; size_t fn_gns_off = 0;
    uint8_t reasons_buf[4]; size_t reasons_len = 0;
    uint8_t issuer_der[300]; size_t issuer_der_len = 0;

    if (dp_elem->type == CBOR_TYPE_TSTR || dp_elem->type == CBOR_TYPE_BSTR) {
        /* Simple: single URI GeneralName [6] */
        der_write_tag_len(fn_gns, sizeof(fn_gns), &fn_gns_off, 0x86, (size_t)dp_elem->val);
        memcpy(fn_gns + fn_gns_off, dp_elem->ptr, (size_t)dp_elem->val);
        fn_gns_off += (size_t)dp_elem->val;

    } else if (dp_elem->type == CBOR_TYPE_ARRAY) {
        cbor_context_t dpc;
        cbor_init_sub_context(&dpc, dp_elem);
        uint64_t n = dp_elem->val;

        /* Element 0: single URI or array of URIs */
        cbor_value_t uris_val;
        if (cbor_decode_next(&dpc, &uris_val) != CBOR_ERR_NONE) return 0;
        if (uris_val.type == CBOR_TYPE_TSTR || uris_val.type == CBOR_TYPE_BSTR) {
            der_write_tag_len(fn_gns, sizeof(fn_gns), &fn_gns_off, 0x86, (size_t)uris_val.val);
            memcpy(fn_gns + fn_gns_off, uris_val.ptr, (size_t)uris_val.val);
            fn_gns_off += (size_t)uris_val.val;
        } else if (uris_val.type == CBOR_TYPE_ARRAY) {
            cbor_context_t ulc;
            cbor_init_sub_context(&ulc, &uris_val);
            for (uint64_t k = 0; k < uris_val.val; k++) {
                cbor_value_t u;
                if (cbor_decode_next(&ulc, &u) != CBOR_ERR_NONE) break;
                if (u.type == CBOR_TYPE_TSTR || u.type == CBOR_TYPE_BSTR) {
                    der_write_tag_len(fn_gns, sizeof(fn_gns), &fn_gns_off, 0x86, (size_t)u.val);
                    memcpy(fn_gns + fn_gns_off, u.ptr, (size_t)u.val);
                    fn_gns_off += (size_t)u.val;
                }
            }
            cbor_skip_val_contents(&dpc, &uris_val);
        }

        /* Element 1 (if n >= 2): reasons UINT */
        if (n >= 2) {
            cbor_value_t rv;
            if (cbor_decode_next(&dpc, &rv) == CBOR_ERR_NONE &&
                rv.type == CBOR_TYPE_UINT && rv.val != 0) {
                uint8_t rev = bit_reverse8((uint8_t)(rv.val & 0xFF));
                int unused = 0;
                if (rev != 0) {
                    uint8_t tmp = rev;
                    while ((tmp & 0x01u) == 0) { unused++; tmp >>= 1; }
                }
                reasons_buf[0] = 0x81; /* [1] IMPLICIT */
                reasons_buf[1] = 0x02;
                reasons_buf[2] = (uint8_t)unused;
                reasons_buf[3] = rev;
                reasons_len = 4;
            }
        }

        /* Element 2 (if n >= 3): cRLIssuer Name (C509 Name → directoryName GeneralName) */
        if (n >= 3) {
            cbor_value_t iv;
            if (cbor_decode_next(&dpc, &iv) == CBOR_ERR_NONE) {
                uint8_t name_buf[256]; size_t name_off = 0;
                if (x509_encode_name(name_buf, sizeof(name_buf), &name_off, &iv, NULL) == 0
                    && name_off > 0) {
                    /* directoryName [4] EXPLICIT */
                    uint8_t dn_buf[270]; size_t dn_off = 0;
                    der_write_tag_len(dn_buf, sizeof(dn_buf), &dn_off, 0xA4, name_off);
                    memcpy(dn_buf + dn_off, name_buf, name_off); dn_off += name_off;
                    /* cRLIssuer [2] IMPLICIT GeneralNames */
                    der_write_tag_len(issuer_der, sizeof(issuer_der), &issuer_der_len, 0xA2, dn_off);
                    memcpy(issuer_der + issuer_der_len, dn_buf, dn_off); issuer_der_len += dn_off;
                }
                cbor_skip_val_contents(&dpc, &iv);
            }
        }
    } else {
        return 0;
    }

    if (fn_gns_off == 0) return 0;

    /* Build [0] distributionPoint { [0] fullName { GeneralNames } } */
    uint8_t fn0[640]; size_t fn0_off = 0;
    der_write_tag_len(fn0, sizeof(fn0), &fn0_off, 0xA0, fn_gns_off);
    memcpy(fn0 + fn0_off, fn_gns, fn_gns_off); fn0_off += fn_gns_off;

    uint8_t dp_inner[800]; size_t dp_inner_off = 0;
    der_write_tag_len(dp_inner, sizeof(dp_inner), &dp_inner_off, 0xA0, fn0_off);
    memcpy(dp_inner + dp_inner_off, fn0, fn0_off); dp_inner_off += fn0_off;

    if (reasons_len > 0) {
        memcpy(dp_inner + dp_inner_off, reasons_buf, reasons_len); dp_inner_off += reasons_len;
    }
    if (issuer_der_len > 0) {
        memcpy(dp_inner + dp_inner_off, issuer_der, issuer_der_len); dp_inner_off += issuer_der_len;
    }

    size_t out_off = 0;
    if (der_write_tag_len(buf, buf_size, &out_off, DER_TAG_SEQUENCE, dp_inner_off) != 0) return 0;
    if (out_off + dp_inner_off > buf_size) return 0;
    memcpy(buf + out_off, dp_inner, dp_inner_off);
    return out_off + dp_inner_off;
}

int x509_encode_extensions(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *exts) {
    /* C509 compact form: a single integer encodes KeyUsage bits (UINT=non-critical, NINT=critical). */
    if (exts->type == CBOR_TYPE_UINT || exts->type == CBOR_TYPE_NINT) {
        int64_t ku_bits = (exts->type == CBOR_TYPE_UINT)
                          ? (int64_t)exts->val
                          : (int64_t)(exts->val + 1);
        int critical = (exts->type == CBOR_TYPE_NINT);
        uint8_t ku = bit_reverse8((uint8_t)(ku_bits & 0xFF));
        int unused = 0;
        if (ku == 0) { unused = 8; } else {
            uint8_t tmp = ku;
            while ((tmp & 0x01u) == 0) { unused++; tmp >>= 1; }
        }
        uint8_t val_der[8]; size_t val_der_off = 0;
        der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_BIT_STRING, 2);
        val_der[val_der_off++] = (uint8_t)unused;
        val_der[val_der_off++] = ku;

        uint8_t inner[32]; size_t inner_off = 0;
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_EXT_KEY_USAGE));
        memcpy(inner + inner_off, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE)); inner_off += sizeof(OID_EXT_KEY_USAGE);
        if (critical) {
            inner[inner_off++] = DER_TAG_BOOLEAN;
            inner[inner_off++] = 0x01;
            inner[inner_off++] = 0xFF;
        }
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OCTET_STRING, val_der_off);
        memcpy(inner + inner_off, val_der, val_der_off); inner_off += val_der_off;

        uint8_t ext_seq_buf[64]; size_t ext_seq_off = 0;
        der_write_tag_len(ext_seq_buf, sizeof(ext_seq_buf), &ext_seq_off, DER_TAG_SEQUENCE, inner_off);
        memcpy(ext_seq_buf + ext_seq_off, inner, inner_off); ext_seq_off += inner_off;

        size_t seq_tl = der_get_tag_len_size(DER_TAG_SEQUENCE, ext_seq_off);
        if (der_write_tag_len(buffer, size, offset, 0xA3, seq_tl + ext_seq_off) != 0) return -1;
        if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, ext_seq_off) != 0) return -1;
        memcpy(buffer + *offset, ext_seq_buf, ext_seq_off); *offset += ext_seq_off;
        return 0;
    }
    if (exts->type != CBOR_TYPE_ARRAY) return 0;

    uint8_t ext_seq_buf[4096]; size_t ext_seq_off = 0;
    cbor_context_t ctx;
    cbor_init_sub_context(&ctx, exts);

    for (uint64_t i = 0; i < exts->val; i += 2) {
        cbor_value_t ext_id_val, ext_val;
        if (cbor_decode_next(&ctx, &ext_id_val) != CBOR_ERR_NONE) break;
        if (cbor_decode_next(&ctx, &ext_val) != CBOR_ERR_NONE) break;

        /* Private extension: BSTR key = raw OID bytes, BSTR value = raw DER value */
        if (ext_id_val.type == CBOR_TYPE_BSTR && ext_val.type == CBOR_TYPE_BSTR) {
            size_t priv_oid_len = (size_t)ext_id_val.val;
            uint8_t priv_inner[280]; size_t priv_inner_off = 0;
            der_write_tag_len(priv_inner, sizeof(priv_inner), &priv_inner_off, DER_TAG_OID, priv_oid_len);
            memcpy(priv_inner + priv_inner_off, ext_id_val.ptr, priv_oid_len);
            priv_inner_off += priv_oid_len;
            der_write_tag_len(priv_inner, sizeof(priv_inner), &priv_inner_off, DER_TAG_OCTET_STRING, (size_t)ext_val.val);
            memcpy(priv_inner + priv_inner_off, ext_val.ptr, (size_t)ext_val.val);
            priv_inner_off += (size_t)ext_val.val;
            der_write_tag_len(ext_seq_buf, sizeof(ext_seq_buf), &ext_seq_off, DER_TAG_SEQUENCE, priv_inner_off);
            memcpy(ext_seq_buf + ext_seq_off, priv_inner, priv_inner_off);
            ext_seq_off += priv_inner_off;
            continue;
        }

        int64_t wire_id = (ext_id_val.type == CBOR_TYPE_UINT)
                          ? (int64_t)ext_id_val.val
                          : -(int64_t)(ext_id_val.val + 1);
        int abs_id = (int)C509_EXT_ABS_ID(wire_id);

        const uint8_t *oid = NULL; size_t oid_len = 0;
        switch (abs_id) {
            case C509_EXT_SUBJECT_KEY_ID:      oid = OID_EXT_SUBJECT_KEY_ID;      oid_len = sizeof(OID_EXT_SUBJECT_KEY_ID);      break;
            case C509_EXT_KEY_USAGE:           oid = OID_EXT_KEY_USAGE;           oid_len = sizeof(OID_EXT_KEY_USAGE);           break;
            case C509_EXT_SUBJECT_ALT_NAME:    oid = OID_EXT_SUBJECT_ALT_NAME;    oid_len = sizeof(OID_EXT_SUBJECT_ALT_NAME);    break;
            case C509_EXT_BASIC_CONSTRAINTS:   oid = OID_EXT_BASIC_CONSTRAINTS;   oid_len = sizeof(OID_EXT_BASIC_CONSTRAINTS);   break;
            case C509_EXT_CRL_DIST_POINTS:     oid = OID_EXT_CRL_DIST_POINTS;     oid_len = sizeof(OID_EXT_CRL_DIST_POINTS);     break;
            case C509_EXT_CERT_POLICIES:       oid = OID_EXT_CERT_POLICIES;       oid_len = sizeof(OID_EXT_CERT_POLICIES);       break;
            case C509_EXT_AUTHORITY_KEY_ID:    oid = OID_EXT_AUTHORITY_KEY_ID;    oid_len = sizeof(OID_EXT_AUTHORITY_KEY_ID);    break;
            case C509_EXT_EXT_KEY_USAGE:       oid = OID_EXT_EXT_KEY_USAGE;       oid_len = sizeof(OID_EXT_EXT_KEY_USAGE);       break;
            case C509_EXT_AUTHORITY_INFO_ACCESS: oid = OID_EXT_AIA;               oid_len = sizeof(OID_EXT_AIA);                 break;
            case C509_EXT_SUBJECT_DIRECTORY_ATTR: oid = OID_EXT_SUBJECT_DIR_ATTR; oid_len = sizeof(OID_EXT_SUBJECT_DIR_ATTR);   break;
            case C509_EXT_NAME_CONSTRAINTS:    oid = OID_EXT_NAME_CONSTRAINTS;    oid_len = sizeof(OID_EXT_NAME_CONSTRAINTS);    break;
            case C509_EXT_POLICY_MAPPINGS:     oid = OID_EXT_POLICY_MAPPINGS;     oid_len = sizeof(OID_EXT_POLICY_MAPPINGS);     break;
            case C509_EXT_POLICY_CONSTRAINTS:  oid = OID_EXT_POLICY_CONSTRAINTS;  oid_len = sizeof(OID_EXT_POLICY_CONSTRAINTS);  break;
            case C509_EXT_INHIBIT_ANY_POLICY:  oid = OID_EXT_INHIBIT_ANY;         oid_len = sizeof(OID_EXT_INHIBIT_ANY);         break;
            case C509_EXT_ISSUER_ALT_NAME:     oid = OID_EXT_ISSUER_ALT_NAME;     oid_len = sizeof(OID_EXT_ISSUER_ALT_NAME);     break;
            case C509_EXT_FRESHEST_CRL:        oid = OID_EXT_FRESHEST_CRL;        oid_len = sizeof(OID_EXT_FRESHEST_CRL);        break;
            case C509_EXT_SUBJECT_INFO_ACCESS: oid = OID_EXT_SUBJECT_INFO_ACCESS; oid_len = sizeof(OID_EXT_SUBJECT_INFO_ACCESS); break;
            case C509_EXT_IP_ADDR_BLOCKS:      oid = OID_EXT_IP_ADDR_BLOCKS;      oid_len = sizeof(OID_EXT_IP_ADDR_BLOCKS);      break;
            case C509_EXT_AS_IDENTIFIERS:      oid = OID_EXT_AS_IDENTIFIERS;      oid_len = sizeof(OID_EXT_AS_IDENTIFIERS);      break;
            case C509_EXT_IP_ADDR_BLOCKS_V2:   oid = OID_EXT_IP_ADDR_BLOCKS_V2;   oid_len = sizeof(OID_EXT_IP_ADDR_BLOCKS_V2);   break;
            case C509_EXT_AS_IDENTIFIERS_V2:   oid = OID_EXT_AS_IDENTIFIERS_V2;   oid_len = sizeof(OID_EXT_AS_IDENTIFIERS_V2);   break;
            case C509_EXT_OCSP_NO_CHECK:       oid = OID_EXT_OCSP_NO_CHECK;       oid_len = sizeof(OID_EXT_OCSP_NO_CHECK);       break;
            case C509_EXT_TLS_FEATURES:        oid = OID_EXT_TLS_FEATURES;        oid_len = sizeof(OID_EXT_TLS_FEATURES);        break;
            default:
                /* Unknown extension — must skip array/map contents left in ctx */
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
        }

        uint8_t val_der[2048]; size_t val_der_off = 0;

        if (abs_id == C509_EXT_BASIC_CONSTRAINTS) {
            int64_t bc_val = (ext_val.type == CBOR_TYPE_UINT)
                             ? (int64_t)ext_val.val
                             : -(int64_t)(ext_val.val + 1);
            uint8_t bc_content[32]; size_t bc_off = 0;
            if (bc_val == -1 || bc_val >= 0) {
                bc_content[bc_off++] = DER_TAG_BOOLEAN;
                bc_content[bc_off++] = 0x01;
                bc_content[bc_off++] = 0xFF;
                if (bc_val >= 0) {
                    bc_content[bc_off++] = DER_TAG_INTEGER;
                    bc_content[bc_off++] = 0x01;
                    bc_content[bc_off++] = (uint8_t)bc_val;
                }
            }
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, bc_off);
            memcpy(val_der + val_der_off, bc_content, bc_off); val_der_off += bc_off;

        } else if (abs_id == C509_EXT_SUBJECT_KEY_ID) {
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_OCTET_STRING, (size_t)ext_val.val);
            memcpy(val_der + val_der_off, ext_val.ptr, (size_t)ext_val.val); val_der_off += (size_t)ext_val.val;

        } else if (abs_id == C509_EXT_CRL_DIST_POINTS || abs_id == C509_EXT_FRESHEST_CRL) {
            /* C509 CRL DP / FreshestCRL:
             * tstr  → single URI (no array wrapper)
             * array → each element is a DP (tstr, or array(1..3)[uris, reasons?, issuer?])
             * bstr  → raw DER passthrough */
            if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else if (ext_val.type == CBOR_TYPE_TSTR) {
                uint8_t dp_buf[300]; size_t dp_off = 0;
                dp_off = encode_dist_point(dp_buf, sizeof(dp_buf), &ext_val);
                if (dp_off > 0) {
                    der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, dp_off);
                    memcpy(val_der + val_der_off, dp_buf, dp_off); val_der_off += dp_off;
                } else {
                    continue;
                }
            } else if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t dp_ctx;
                cbor_init_sub_context(&dp_ctx, &ext_val);
                uint8_t dp_buf[1024]; size_t dp_off = 0;
                for (uint64_t j = 0; j < ext_val.val; j++) {
                    cbor_value_t dp_elem;
                    if (cbor_decode_next(&dp_ctx, &dp_elem) != CBOR_ERR_NONE) break;
                    size_t dlen = encode_dist_point(dp_buf + dp_off, sizeof(dp_buf) - dp_off, &dp_elem);
                    dp_off += dlen;
                    cbor_skip_val_contents(&dp_ctx, &dp_elem);
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, dp_off);
                memcpy(val_der + val_der_off, dp_buf, dp_off); val_der_off += dp_off;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_AUTHORITY_KEY_ID) {
            /* C509 AKI:
             * bstr → keyid only: SEQUENCE { [0] keyid }
             * array(3) → full form: SEQUENCE { [0] keyid?, [1] GeneralNames?, [2] serial? } */
            if (ext_val.type == CBOR_TYPE_ARRAY && ext_val.val >= 3) {
                cbor_context_t aki_ctx;
                cbor_init_sub_context(&aki_ctx, &ext_val);
                cbor_value_t aki_kid, aki_iss, aki_ser;
                if (cbor_decode_next(&aki_ctx, &aki_kid) != CBOR_ERR_NONE) { cbor_skip_val_contents(&ctx, &ext_val); continue; }
                if (cbor_decode_next(&aki_ctx, &aki_iss) != CBOR_ERR_NONE) { cbor_skip_val_contents(&ctx, &ext_val); continue; }
                /* Advance aki_ctx past issuer array contents before reading serial */
                cbor_skip_val_contents(&aki_ctx, &aki_iss);
                if (cbor_decode_next(&aki_ctx, &aki_ser) != CBOR_ERR_NONE) { cbor_skip_val_contents(&ctx, &ext_val); continue; }
                cbor_skip_val_contents(&ctx, &ext_val);
                uint8_t aki_inner[300]; size_t aki_inner_off = 0;
                /* [0] keyIdentifier */
                if (aki_kid.type == CBOR_TYPE_BSTR) {
                    size_t klen = (size_t)aki_kid.val;
                    aki_inner[aki_inner_off++] = 0x80;
                    aki_inner[aki_inner_off++] = (uint8_t)klen;
                    memcpy(aki_inner + aki_inner_off, aki_kid.ptr, klen); aki_inner_off += klen;
                }
                /* [1] authorityCertIssuer GeneralNames */
                if (aki_iss.type == CBOR_TYPE_ARRAY) {
                    cbor_context_t iss_ctx;
                    cbor_init_sub_context(&iss_ctx, &aki_iss);
                    uint8_t gns_buf[256]; size_t gns_off = 0;
                    for (uint64_t j = 0; j + 1 < aki_iss.val; j += 2) {
                        cbor_value_t gn_t, gn_v;
                        if (cbor_decode_next(&iss_ctx, &gn_t) != CBOR_ERR_NONE) break;
                        if (cbor_decode_next(&iss_ctx, &gn_v) != CBOR_ERR_NONE) break;
                        int64_t gn_type2 = (gn_t.type == CBOR_TYPE_UINT) ? (int64_t)gn_t.val : -(int64_t)(gn_t.val + 1);
                        uint8_t gn_buf[128];
                        size_t gn_len = encode_general_name(gn_buf, sizeof(gn_buf), gn_type2, &gn_v);
                        if (gn_len > 0) { memcpy(gns_buf + gns_off, gn_buf, gn_len); gns_off += gn_len; }
                        cbor_skip_val_contents(&iss_ctx, &gn_v);
                    }
                    if (gns_off > 0) {
                        der_write_tag_len(aki_inner, sizeof(aki_inner), &aki_inner_off, 0xA1, gns_off);
                        memcpy(aki_inner + aki_inner_off, gns_buf, gns_off); aki_inner_off += gns_off;
                    }
                }
                /* [2] authorityCertSerialNumber */
                if (aki_ser.type == CBOR_TYPE_BSTR) {
                    size_t slen = (size_t)aki_ser.val;
                    aki_inner[aki_inner_off++] = 0x82;
                    aki_inner[aki_inner_off++] = (uint8_t)slen;
                    memcpy(aki_inner + aki_inner_off, aki_ser.ptr, slen); aki_inner_off += slen;
                } else if (aki_ser.type == CBOR_TYPE_UINT) {
                    uint8_t ibuf[8]; int ilen = 0;
                    uint64_t sv = aki_ser.val;
                    do { ibuf[ilen++] = (uint8_t)(sv & 0xFF); sv >>= 8; } while (sv);
                    uint8_t int_buf[9]; int int_len = 0;
                    if (ibuf[ilen-1] & 0x80) int_buf[int_len++] = 0x00;
                    for (int k = ilen-1; k >= 0; k--) int_buf[int_len++] = ibuf[k];
                    aki_inner[aki_inner_off++] = 0x82;
                    aki_inner[aki_inner_off++] = (uint8_t)int_len;
                    memcpy(aki_inner + aki_inner_off, int_buf, int_len); aki_inner_off += int_len;
                }
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, aki_inner_off);
                memcpy(val_der + val_der_off, aki_inner, aki_inner_off); val_der_off += aki_inner_off;
            } else {
                /* array(1) or bstr: keyid only */
                const uint8_t *keyid_ptr; size_t keyid_len;
                if (ext_val.type == CBOR_TYPE_ARRAY) {
                    cbor_context_t aki_ctx;
                    cbor_value_t keyid_val;
                    cbor_init_sub_context(&aki_ctx, &ext_val);
                    if (cbor_decode_next(&aki_ctx, &keyid_val) != CBOR_ERR_NONE) { cbor_skip_val_contents(&ctx, &ext_val); continue; }
                    keyid_ptr = keyid_val.ptr; keyid_len = (size_t)keyid_val.val;
                    cbor_skip_val_contents(&ctx, &ext_val);
                } else {
                    keyid_ptr = ext_val.ptr; keyid_len = (size_t)ext_val.val;
                }
                uint8_t akid_inner[34]; size_t akid_inner_off = 0;
                akid_inner[akid_inner_off++] = 0x80;
                akid_inner[akid_inner_off++] = (uint8_t)keyid_len;
                memcpy(akid_inner + akid_inner_off, keyid_ptr, keyid_len); akid_inner_off += keyid_len;
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, akid_inner_off);
                memcpy(val_der + val_der_off, akid_inner, akid_inner_off); val_der_off += akid_inner_off;
            }

        } else if (abs_id == C509_EXT_KEY_USAGE) {
            if (ext_val.type == CBOR_TYPE_UINT) {
                uint8_t ku = bit_reverse8((uint8_t)(ext_val.val & 0xFF));
                int unused = 0;
                if (ku == 0) { unused = 8; } else {
                    uint8_t tmp = ku;
                    while ((tmp & 0x01u) == 0) { unused++; tmp >>= 1; }
                }
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_BIT_STRING, 2);
                val_der[val_der_off++] = (uint8_t)unused;
                val_der[val_der_off++] = ku;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_BIT_STRING, (size_t)ext_val.val + 1);
                val_der[val_der_off++] = 0x00;
                memcpy(val_der + val_der_off, ext_val.ptr, (size_t)ext_val.val); val_der_off += (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_EXT_KEY_USAGE) {
            /* EKU: SEQUENCE of OIDs; C509 value is UINT (one EKU) or ARRAY of UINTs/BSTRs. */
            uint8_t eku_inner[256]; size_t eku_inner_off = 0;
#define EKU_APPEND_OID(id_val) do { \
    const uint8_t *_o = NULL; size_t _ol = 0; \
    switch ((id_val)) { \
        case C509_EKU_TLS_SERVER:      _o = OID_EKU_TLS_SERVER;      _ol = sizeof(OID_EKU_TLS_SERVER);      break; \
        case C509_EKU_TLS_CLIENT:      _o = OID_EKU_TLS_CLIENT;      _ol = sizeof(OID_EKU_TLS_CLIENT);      break; \
        case C509_EKU_CODE_SIGNING:    _o = OID_EKU_CODE_SIGNING;    _ol = sizeof(OID_EKU_CODE_SIGNING);    break; \
        case C509_EKU_EMAIL_PROTECTION:_o = OID_EKU_EMAIL_PROTECTION;_ol = sizeof(OID_EKU_EMAIL_PROTECTION);break; \
        case C509_EKU_TIME_STAMPING:   _o = OID_EKU_TIME_STAMPING;   _ol = sizeof(OID_EKU_TIME_STAMPING);   break; \
        case C509_EKU_OCSP_SIGNING:    _o = OID_EKU_OCSP_SIGNING;    _ol = sizeof(OID_EKU_OCSP_SIGNING);    break; \
        default: break; \
    } \
    if (_o) { \
        der_write_tag_len(eku_inner, sizeof(eku_inner), &eku_inner_off, DER_TAG_OID, _ol); \
        memcpy(eku_inner + eku_inner_off, _o, _ol); eku_inner_off += _ol; \
    } \
} while(0)
            if (ext_val.type == CBOR_TYPE_UINT) {
                EKU_APPEND_OID(ext_val.val);
            } else if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t eku_ctx;
                cbor_init_sub_context(&eku_ctx, &ext_val);
                for (uint64_t j = 0; j < ext_val.val; j++) {
                    cbor_value_t eku_id;
                    if (cbor_decode_next(&eku_ctx, &eku_id) != CBOR_ERR_NONE) break;
                    if (eku_id.type == CBOR_TYPE_BSTR) {
                        /* Private EKU: raw OID bytes */
                        der_write_tag_len(eku_inner, sizeof(eku_inner), &eku_inner_off, DER_TAG_OID, (size_t)eku_id.val);
                        memcpy(eku_inner + eku_inner_off, eku_id.ptr, (size_t)eku_id.val);
                        eku_inner_off += (size_t)eku_id.val;
                    } else {
                        EKU_APPEND_OID(eku_id.val);
                    }
                }
                cbor_skip_val_contents(&ctx, &ext_val);
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                /* Single private EKU OID: raw OID bytes directly */
                der_write_tag_len(eku_inner, sizeof(eku_inner), &eku_inner_off, DER_TAG_OID, (size_t)ext_val.val);
                memcpy(eku_inner + eku_inner_off, ext_val.ptr, (size_t)ext_val.val);
                eku_inner_off += (size_t)ext_val.val;
            }
#undef EKU_APPEND_OID
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, eku_inner_off);
            memcpy(val_der + val_der_off, eku_inner, eku_inner_off); val_der_off += eku_inner_off;

        } else if (abs_id == C509_EXT_SUBJECT_ALT_NAME || abs_id == C509_EXT_ISSUER_ALT_NAME) {
            /* C509 SAN/IAN: ARRAY of (type_int, value) pairs */
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t san_ctx;
                cbor_init_sub_context(&san_ctx, &ext_val);
                uint8_t san_buf[512]; size_t san_off = 0;
                for (uint64_t j = 0; j + 1 < ext_val.val; j += 2) {
                    cbor_value_t gn_type_val, gn_data_val;
                    if (cbor_decode_next(&san_ctx, &gn_type_val) != CBOR_ERR_NONE) break;
                    if (cbor_decode_next(&san_ctx, &gn_data_val) != CBOR_ERR_NONE) break;
                    int64_t gn_type = (gn_type_val.type == CBOR_TYPE_UINT)
                                      ? (int64_t)gn_type_val.val
                                      : -(int64_t)(gn_type_val.val + 1);
                    uint8_t gn_buf[256];
                    size_t gn_len = encode_general_name(gn_buf, sizeof(gn_buf), gn_type, &gn_data_val);
                    if (gn_len > 0 && san_off + gn_len <= sizeof(san_buf)) {
                        memcpy(san_buf + san_off, gn_buf, gn_len);
                        san_off += gn_len;
                    }
                    cbor_skip_val_contents(&san_ctx, &gn_data_val);
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, san_off);
                memcpy(val_der + val_der_off, san_buf, san_off); val_der_off += san_off;
            } else if (ext_val.type == CBOR_TYPE_TSTR) {
                /* Compact form: bare TSTR = single dNSName (type 2) */
                uint8_t gn_buf[256]; size_t gn_len = 0;
                der_write_tag_len(gn_buf, sizeof(gn_buf), &gn_len, 0x82, (size_t)ext_val.val);
                memcpy(gn_buf + gn_len, ext_val.ptr, (size_t)ext_val.val);
                gn_len += (size_t)ext_val.val;
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, gn_len);
                memcpy(val_der + val_der_off, gn_buf, gn_len); val_der_off += gn_len;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_AUTHORITY_INFO_ACCESS || abs_id == C509_EXT_SUBJECT_INFO_ACCESS) {
            /* C509 AIA/SIA: ARRAY of (type_uint, uri_tstr) pairs.
             * type 1 = OCSP, type 2 = caIssuers → OID 1.3.6.1.5.5.7.48.N */
            static const uint8_t AIA_OID_PFX[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30 };
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t aia_ctx;
                cbor_init_sub_context(&aia_ctx, &ext_val);
                uint8_t aia_buf[512]; size_t aia_off = 0;
                for (uint64_t j = 0; j + 1 < ext_val.val; j += 2) {
                    cbor_value_t aia_type, aia_loc;
                    if (cbor_decode_next(&aia_ctx, &aia_type) != CBOR_ERR_NONE) break;
                    if (cbor_decode_next(&aia_ctx, &aia_loc) != CBOR_ERR_NONE) break;
                    const uint8_t *aia_oid_ptr;
                    size_t aia_oid_len;
                    uint8_t aia_oid_buf[16];
                    if (aia_type.type == CBOR_TYPE_UINT) {
                        memcpy(aia_oid_buf, AIA_OID_PFX, sizeof(AIA_OID_PFX));
                        aia_oid_buf[sizeof(AIA_OID_PFX)] = (uint8_t)aia_type.val;
                        aia_oid_ptr = aia_oid_buf;
                        aia_oid_len = sizeof(AIA_OID_PFX) + 1;
                    } else if (aia_type.type == CBOR_TYPE_BSTR) {
                        /* Private OID: raw DER OID value bytes */
                        aia_oid_ptr = aia_type.ptr;
                        aia_oid_len = (size_t)aia_type.val;
                    } else {
                        continue;
                    }
                    size_t uri_len = (size_t)aia_loc.val;
                    uint8_t loc_der[256]; size_t loc_off = 0;
                    der_write_tag_len(loc_der, sizeof(loc_der), &loc_off, 0x86, uri_len);
                    memcpy(loc_der + loc_off, aia_loc.ptr, uri_len); loc_off += uri_len;
                    uint8_t adesc_inner[280]; size_t adesc_off = 0;
                    der_write_tag_len(adesc_inner, sizeof(adesc_inner), &adesc_off, DER_TAG_OID, aia_oid_len);
                    memcpy(adesc_inner + adesc_off, aia_oid_ptr, aia_oid_len); adesc_off += aia_oid_len;
                    memcpy(adesc_inner + adesc_off, loc_der, loc_off); adesc_off += loc_off;
                    der_write_tag_len(aia_buf, sizeof(aia_buf), &aia_off, DER_TAG_SEQUENCE, adesc_off);
                    memcpy(aia_buf + aia_off, adesc_inner, adesc_off); aia_off += adesc_off;
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, aia_off);
                memcpy(val_der + val_der_off, aia_buf, aia_off); val_der_off += aia_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_SUBJECT_DIRECTORY_ATTR) {
            /* C509: flat array [attr_type_code, attr_value_or_array, ...]
             * attr_value may be ARRAY (multi-value SET) or a scalar.
             * DER: SEQUENCE OF Attribute { SEQUENCE { OID, SET OF values } } */
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t sda_ctx;
                cbor_init_sub_context(&sda_ctx, &ext_val);
                uint8_t sda_buf[512]; size_t sda_off = 0;
                for (uint64_t j = 0; j + 1 < ext_val.val; j += 2) {
                    cbor_value_t at_id, at_v;
                    if (cbor_decode_next(&sda_ctx, &at_id) != CBOR_ERR_NONE) break;
                    if (cbor_decode_next(&sda_ctx, &at_v) != CBOR_ERR_NONE) break;
                    int64_t id = (at_id.type == CBOR_TYPE_UINT) ? (int64_t)at_id.val : -(int64_t)(at_id.val + 1);
                    int64_t abs_at = (id < 0) ? -id : id;
                    uint8_t str_tag = (id < 0) ? DER_TAG_PRINTABLE_STRING : DER_TAG_UTF8_STRING;
                    const uint8_t *aoid = OID_ATT_COMMON_NAME; size_t aoid_len = sizeof(OID_ATT_COMMON_NAME);
                    switch (abs_at) {
                        case C509_ATT_EMAIL:                   aoid = OID_ATT_EMAIL;                  aoid_len = sizeof(OID_ATT_EMAIL);                  str_tag = DER_TAG_IA5_STRING; break;
                        case C509_ATT_COMMON_NAME:             break;
                        case C509_ATT_SUR_NAME:                aoid = OID_ATT_SUR_NAME;               aoid_len = sizeof(OID_ATT_SUR_NAME);               break;
                        case C509_ATT_SERIAL_NUMBER:           aoid = OID_ATT_SERIAL_NUMBER;          aoid_len = sizeof(OID_ATT_SERIAL_NUMBER);          break;
                        case C509_ATT_COUNTRY:                 aoid = OID_ATT_COUNTRY;                aoid_len = sizeof(OID_ATT_COUNTRY);                break;
                        case C509_ATT_LOCALITY:                aoid = OID_ATT_LOCALITY;               aoid_len = sizeof(OID_ATT_LOCALITY);               break;
                        case C509_ATT_STATE_OR_PROVINCE:       aoid = OID_ATT_STATE;                  aoid_len = sizeof(OID_ATT_STATE);                  break;
                        case C509_ATT_STREET_ADDRESS:          aoid = OID_ATT_STREET;                 aoid_len = sizeof(OID_ATT_STREET);                 break;
                        case C509_ATT_ORGANIZATION:            aoid = OID_ATT_ORGANIZATION;           aoid_len = sizeof(OID_ATT_ORGANIZATION);           break;
                        case C509_ATT_ORGANIZATION_UNIT:       aoid = OID_ATT_ORG_UNIT;               aoid_len = sizeof(OID_ATT_ORG_UNIT);               break;
                        case C509_ATT_TITLE:                   aoid = OID_ATT_TITLE;                  aoid_len = sizeof(OID_ATT_TITLE);                  break;
                        case C509_ATT_BUSINESS_CATEGORY:       aoid = OID_ATT_BUSINESS_CATEGORY;      aoid_len = sizeof(OID_ATT_BUSINESS_CATEGORY);      break;
                        case C509_ATT_POSTAL_CODE:             aoid = OID_ATT_POSTAL_CODE;            aoid_len = sizeof(OID_ATT_POSTAL_CODE);            break;
                        case C509_ATT_GIVEN_NAME:              aoid = OID_ATT_GIVEN_NAME;             aoid_len = sizeof(OID_ATT_GIVEN_NAME);             break;
                        case C509_ATT_INITIALS:                aoid = OID_ATT_INITIALS;               aoid_len = sizeof(OID_ATT_INITIALS);               break;
                        case C509_ATT_GENERATION_QUALIFIER:    aoid = OID_ATT_GENERATION_QUALIFIER;   aoid_len = sizeof(OID_ATT_GENERATION_QUALIFIER);   break;
                        case C509_ATT_DN_QUALIFIER:            aoid = OID_ATT_DN_QUALIFIER;           aoid_len = sizeof(OID_ATT_DN_QUALIFIER);           break;
                        case C509_ATT_PSEUDONYM:               aoid = OID_ATT_PSEUDONYM;              aoid_len = sizeof(OID_ATT_PSEUDONYM);              break;
                        case C509_ATT_ORGANIZATION_IDENTIFIER: aoid = OID_ATT_ORG_IDENTIFIER;         aoid_len = sizeof(OID_ATT_ORG_IDENTIFIER);         break;
                        case C509_ATT_JURISDICTION_LOCALITY:   aoid = OID_ATT_JURISDICTION_LOCALITY;  aoid_len = sizeof(OID_ATT_JURISDICTION_LOCALITY);  break;
                        case C509_ATT_JURISDICTION_STATE:      aoid = OID_ATT_JURISDICTION_STATE;     aoid_len = sizeof(OID_ATT_JURISDICTION_STATE);     break;
                        case C509_ATT_JURISDICTION_COUNTRY:    aoid = OID_ATT_JURISDICTION_COUNTRY;   aoid_len = sizeof(OID_ATT_JURISDICTION_COUNTRY);   break;
                        case C509_ATT_DOMAIN_COMPONENT:        aoid = OID_ATT_DC;                     aoid_len = sizeof(OID_ATT_DC);                     str_tag = DER_TAG_IA5_STRING; break;
                        case C509_ATT_NAME:                    aoid = OID_ATT_NAME;                   aoid_len = sizeof(OID_ATT_NAME);                   break;
                        case C509_ATT_TELEPHONE_NUMBER:        aoid = OID_ATT_TELEPHONE_NUMBER;       aoid_len = sizeof(OID_ATT_TELEPHONE_NUMBER);       break;
                        default: break;
                    }
                    uint8_t setv[256]; size_t setv_off = 0;
                    if (at_v.type == CBOR_TYPE_ARRAY) {
                        cbor_context_t av_ctx;
                        cbor_init_sub_context(&av_ctx, &at_v);
                        for (uint64_t k = 0; k < at_v.val; k++) {
                            cbor_value_t v;
                            if (cbor_decode_next(&av_ctx, &v) != CBOR_ERR_NONE) break;
                            size_t vlen = (size_t)v.val;
                            der_write_tag_len(setv, sizeof(setv), &setv_off, str_tag, vlen);
                            memcpy(setv + setv_off, v.ptr, vlen); setv_off += vlen;
                        }
                        cbor_skip_val_contents(&sda_ctx, &at_v);
                    } else {
                        size_t vlen = (size_t)at_v.val;
                        der_write_tag_len(setv, sizeof(setv), &setv_off, str_tag, vlen);
                        memcpy(setv + setv_off, at_v.ptr, vlen); setv_off += vlen;
                    }
                    uint8_t attr_inner[320]; size_t attr_inner_off = 0;
                    der_write_tag_len(attr_inner, sizeof(attr_inner), &attr_inner_off, DER_TAG_OID, aoid_len);
                    memcpy(attr_inner + attr_inner_off, aoid, aoid_len); attr_inner_off += aoid_len;
                    der_write_tag_len(attr_inner, sizeof(attr_inner), &attr_inner_off, DER_TAG_SET, setv_off);
                    memcpy(attr_inner + attr_inner_off, setv, setv_off); attr_inner_off += setv_off;
                    der_write_tag_len(sda_buf, sizeof(sda_buf), &sda_off, DER_TAG_SEQUENCE, attr_inner_off);
                    memcpy(sda_buf + sda_off, attr_inner, attr_inner_off); sda_off += attr_inner_off;
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, sda_off);
                memcpy(val_der + val_der_off, sda_buf, sda_off); val_der_off += sda_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_POLICY_MAPPINGS) {
            /* C509: flat array [issuerPolicy, subjectPolicy, ...]
             * UINT/NINT=compact policy ID, BSTR=raw OID bytes.
             * DER: SEQUENCE OF PolicyMapping { SEQUENCE { issuerDomainPolicy OID, subjectDomainPolicy OID } } */
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t pm_ctx;
                cbor_init_sub_context(&pm_ctx, &ext_val);
                uint8_t pm_buf[512]; size_t pm_off = 0;
                for (uint64_t j = 0; j + 1 < ext_val.val; j += 2) {
                    cbor_value_t pm_iss, pm_sub;
                    if (cbor_decode_next(&pm_ctx, &pm_iss) != CBOR_ERR_NONE) break;
                    if (cbor_decode_next(&pm_ctx, &pm_sub) != CBOR_ERR_NONE) break;
                    uint8_t iss_oid[16]; size_t iss_len = 0;
                    uint8_t sub_oid[16]; size_t sub_len = 0;
                    const uint8_t *iss_ptr = NULL, *sub_ptr = NULL;
                    if (pm_iss.type == CBOR_TYPE_UINT || pm_iss.type == CBOR_TYPE_NINT) {
                        int64_t id = (pm_iss.type == CBOR_TYPE_UINT) ? (int64_t)pm_iss.val : -(int64_t)(pm_iss.val + 1);
                        iss_len = cp_policy_oid(id, iss_oid, sizeof(iss_oid));
                        iss_ptr = iss_oid;
                    } else if (pm_iss.type == CBOR_TYPE_BSTR) {
                        iss_len = (size_t)pm_iss.val;
                        iss_ptr = pm_iss.ptr;
                    }
                    if (pm_sub.type == CBOR_TYPE_UINT || pm_sub.type == CBOR_TYPE_NINT) {
                        int64_t id = (pm_sub.type == CBOR_TYPE_UINT) ? (int64_t)pm_sub.val : -(int64_t)(pm_sub.val + 1);
                        sub_len = cp_policy_oid(id, sub_oid, sizeof(sub_oid));
                        sub_ptr = sub_oid;
                    } else if (pm_sub.type == CBOR_TYPE_BSTR) {
                        sub_len = (size_t)pm_sub.val;
                        sub_ptr = pm_sub.ptr;
                    }
                    if (iss_len == 0 || sub_len == 0 || iss_ptr == NULL || sub_ptr == NULL) continue;
                    uint8_t pair_inner[48]; size_t pair_inner_off = 0;
                    der_write_tag_len(pair_inner, sizeof(pair_inner), &pair_inner_off, DER_TAG_OID, iss_len);
                    memcpy(pair_inner + pair_inner_off, iss_ptr, iss_len); pair_inner_off += iss_len;
                    der_write_tag_len(pair_inner, sizeof(pair_inner), &pair_inner_off, DER_TAG_OID, sub_len);
                    memcpy(pair_inner + pair_inner_off, sub_ptr, sub_len); pair_inner_off += sub_len;
                    der_write_tag_len(pm_buf, sizeof(pm_buf), &pm_off, DER_TAG_SEQUENCE, pair_inner_off);
                    memcpy(pm_buf + pm_off, pair_inner, pair_inner_off); pm_off += pair_inner_off;
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, pm_off);
                memcpy(val_der + val_der_off, pm_buf, pm_off); val_der_off += pm_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_NAME_CONSTRAINTS) {
            /* C509: [permits_or_null, excludes_or_null], each is null or ARRAY of (type,value) pairs.
             * DER: SEQUENCE { [0] permittedSubtrees OPT, [1] excludedSubtrees OPT } */
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t nc_ctx;
                cbor_init_sub_context(&nc_ctx, &ext_val);
                uint8_t nc_content[512]; size_t nc_off = 0;
                for (int slot = 0; slot < 2; slot++) {
                    cbor_value_t sub_val;
                    if (cbor_decode_next(&nc_ctx, &sub_val) != CBOR_ERR_NONE) break;
                    /* CBOR null = SIMPLE type, value 22 */
                    if (sub_val.type == CBOR_TYPE_SIMPLE && sub_val.val == 22) continue;
                    if (sub_val.type != CBOR_TYPE_ARRAY) {
                        cbor_skip_val_contents(&nc_ctx, &sub_val);
                        continue;
                    }
                    cbor_context_t subtrees_ctx;
                    cbor_init_sub_context(&subtrees_ctx, &sub_val);
                    uint8_t subtrees_buf[256]; size_t subtrees_off = 0;
                    for (uint64_t k = 0; k + 1 < sub_val.val; k += 2) {
                        cbor_value_t gn_t, gn_v;
                        if (cbor_decode_next(&subtrees_ctx, &gn_t) != CBOR_ERR_NONE) break;
                        if (cbor_decode_next(&subtrees_ctx, &gn_v) != CBOR_ERR_NONE) break;
                        int64_t gn_type = (gn_t.type == CBOR_TYPE_UINT)
                                          ? (int64_t)gn_t.val
                                          : -(int64_t)(gn_t.val + 1);
                        uint8_t gn_buf[128];
                        size_t gn_len = encode_general_name(gn_buf, sizeof(gn_buf), gn_type, &gn_v);
                        if (gn_len > 0) {
                            der_write_tag_len(subtrees_buf, sizeof(subtrees_buf), &subtrees_off, DER_TAG_SEQUENCE, gn_len);
                            memcpy(subtrees_buf + subtrees_off, gn_buf, gn_len);
                            subtrees_off += gn_len;
                        }
                        cbor_skip_val_contents(&subtrees_ctx, &gn_v);
                    }
                    uint8_t ctx_tag = (slot == 0) ? 0xA0 : 0xA1;
                    der_write_tag_len(nc_content, sizeof(nc_content), &nc_off, ctx_tag, subtrees_off);
                    memcpy(nc_content + nc_off, subtrees_buf, subtrees_off); nc_off += subtrees_off;
                    /* Advance nc_ctx past this slot's array elements */
                    cbor_skip_val_contents(&nc_ctx, &sub_val);
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, nc_off);
                memcpy(val_der + val_der_off, nc_content, nc_off); val_der_off += nc_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_POLICY_CONSTRAINTS) {
            /* C509: [requireExplicit_or_null, inhibitMapping_or_null]
             * DER: SEQUENCE { [0] IMPLICIT INTEGER OPT, [1] IMPLICIT INTEGER OPT } */
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t pc_ctx;
                cbor_init_sub_context(&pc_ctx, &ext_val);
                uint8_t pc_content[16]; size_t pc_off = 0;
                for (int slot = 0; slot < 2; slot++) {
                    cbor_value_t pc_val;
                    if (cbor_decode_next(&pc_ctx, &pc_val) != CBOR_ERR_NONE) break;
                    if (pc_val.type == CBOR_TYPE_SIMPLE && pc_val.val == 22) continue;
                    if (pc_val.type == CBOR_TYPE_UINT) {
                        uint8_t ctx_tag = (slot == 0) ? 0x80 : 0x81;
                        pc_content[pc_off++] = ctx_tag;
                        pc_content[pc_off++] = 0x01;
                        pc_content[pc_off++] = (uint8_t)pc_val.val;
                    }
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, pc_off);
                memcpy(val_der + val_der_off, pc_content, pc_off); val_der_off += pc_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_INHIBIT_ANY_POLICY) {
            if (ext_val.type == CBOR_TYPE_UINT) {
                uint8_t n = (uint8_t)ext_val.val;
                der_write_integer(val_der, sizeof(val_der), &val_der_off, &n, 1);
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_OCSP_NO_CHECK) {
            if (ext_val.type == CBOR_TYPE_SIMPLE && ext_val.val == 22) {
                /* NULL → DER NULL */
                val_der[val_der_off++] = 0x05;
                val_der[val_der_off++] = 0x00;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_TLS_FEATURES) {
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t tf_ctx;
                cbor_init_sub_context(&tf_ctx, &ext_val);
                uint8_t tf_inner[128]; size_t tf_inner_off = 0;
                for (uint64_t j = 0; j < ext_val.val; j++) {
                    cbor_value_t tf_id;
                    if (cbor_decode_next(&tf_ctx, &tf_id) != CBOR_ERR_NONE) break;
                    if (tf_id.type == CBOR_TYPE_UINT) {
                        uint8_t n = (uint8_t)tf_id.val;
                        der_write_integer(tf_inner, sizeof(tf_inner), &tf_inner_off, &n, 1);
                    }
                }
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, tf_inner_off);
                memcpy(val_der + val_der_off, tf_inner, tf_inner_off); val_der_off += tf_inner_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (abs_id == C509_EXT_CERT_POLICIES) {
            /* C509 CertPolicies: flat interleaved array [policyId, policyId, quals, ...]
             * An ARRAY element is the qualifier list for the preceding policyId.
             * policyId: UINT/NINT=compact code, BSTR=raw OID bytes.
             * qualifiers array: [type, val, ...] where type 1=CPS (IA5String), 2=UserNotice (SEQUENCE{UTF8String}) */
            static const uint8_t OID_PQ_CPS[]     = {0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x01};
            static const uint8_t OID_PQ_UNOTICE[] = {0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x02};
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t cp_ctx;
                cbor_init_sub_context(&cp_ctx, &ext_val);
                uint8_t cp_buf[1024]; size_t cp_off = 0;
                uint8_t pol_oid[16]; size_t pol_oid_len = 0;
                int pol_pending = 0;

                /* Helper lambda inline: emit pending policyId without qualifiers */
#define EMIT_PENDING_NO_QUALS() do { \
    if (pol_pending) { \
        uint8_t pi_buf[32]; size_t pi_off = 0; \
        der_write_tag_len(pi_buf, sizeof(pi_buf), &pi_off, DER_TAG_OID, pol_oid_len); \
        memcpy(pi_buf + pi_off, pol_oid, pol_oid_len); pi_off += pol_oid_len; \
        der_write_tag_len(cp_buf, sizeof(cp_buf), &cp_off, DER_TAG_SEQUENCE, pi_off); \
        memcpy(cp_buf + cp_off, pi_buf, pi_off); cp_off += pi_off; \
        pol_pending = 0; \
    } \
} while (0)

                for (uint64_t j = 0; j < ext_val.val; j++) {
                    cbor_value_t cp_item;
                    if (cbor_decode_next(&cp_ctx, &cp_item) != CBOR_ERR_NONE) break;

                    if (cp_item.type == CBOR_TYPE_UINT || cp_item.type == CBOR_TYPE_NINT) {
                        EMIT_PENDING_NO_QUALS();
                        int64_t cp_id = (cp_item.type == CBOR_TYPE_UINT)
                                        ? (int64_t)cp_item.val
                                        : -(int64_t)(cp_item.val + 1);
                        pol_oid_len = cp_policy_oid(cp_id, pol_oid, sizeof(pol_oid));
                        pol_pending = (pol_oid_len > 0) ? 1 : 0;
                    } else if (cp_item.type == CBOR_TYPE_BSTR) {
                        EMIT_PENDING_NO_QUALS();
                        pol_oid_len = (size_t)cp_item.val;
                        if (pol_oid_len <= sizeof(pol_oid)) {
                            memcpy(pol_oid, cp_item.ptr, pol_oid_len);
                            pol_pending = 1;
                        }
                    } else if (cp_item.type == CBOR_TYPE_ARRAY && pol_pending) {
                        /* Qualifier list for the pending policyId */
                        cbor_context_t q_ctx;
                        cbor_init_sub_context(&q_ctx, &cp_item);
                        uint8_t quals_buf[512]; size_t quals_off = 0;
                        for (uint64_t k = 0; k + 1 < cp_item.val; k += 2) {
                            cbor_value_t q_type, q_val;
                            if (cbor_decode_next(&q_ctx, &q_type) != CBOR_ERR_NONE) break;
                            if (cbor_decode_next(&q_ctx, &q_val) != CBOR_ERR_NONE) break;
                            if (q_type.type == CBOR_TYPE_UINT && (q_val.type == CBOR_TYPE_TSTR || q_val.type == CBOR_TYPE_BSTR)) {
                                uint8_t pqi[256]; size_t pqi_off = 0;
                                size_t vlen = (size_t)q_val.val;
                                if (q_type.val == 1) {
                                    /* CPS: OID + IA5String */
                                    der_write_tag_len(pqi, sizeof(pqi), &pqi_off, DER_TAG_OID, sizeof(OID_PQ_CPS));
                                    memcpy(pqi + pqi_off, OID_PQ_CPS, sizeof(OID_PQ_CPS)); pqi_off += sizeof(OID_PQ_CPS);
                                    der_write_tag_len(pqi, sizeof(pqi), &pqi_off, DER_TAG_IA5_STRING, vlen);
                                    memcpy(pqi + pqi_off, q_val.ptr, vlen); pqi_off += vlen;
                                } else if (q_type.val == 2) {
                                    /* UserNotice: OID + SEQUENCE { UTF8String } */
                                    uint8_t un[256]; size_t un_off = 0;
                                    der_write_tag_len(un, sizeof(un), &un_off, DER_TAG_UTF8_STRING, vlen);
                                    memcpy(un + un_off, q_val.ptr, vlen); un_off += vlen;
                                    der_write_tag_len(pqi, sizeof(pqi), &pqi_off, DER_TAG_OID, sizeof(OID_PQ_UNOTICE));
                                    memcpy(pqi + pqi_off, OID_PQ_UNOTICE, sizeof(OID_PQ_UNOTICE)); pqi_off += sizeof(OID_PQ_UNOTICE);
                                    der_write_tag_len(pqi, sizeof(pqi), &pqi_off, DER_TAG_SEQUENCE, un_off);
                                    memcpy(pqi + pqi_off, un, un_off); pqi_off += un_off;
                                }
                                if (pqi_off > 0) {
                                    der_write_tag_len(quals_buf, sizeof(quals_buf), &quals_off, DER_TAG_SEQUENCE, pqi_off);
                                    memcpy(quals_buf + quals_off, pqi, pqi_off); quals_off += pqi_off;
                                }
                            }
                        }
                        /* Emit PolicyInformation { OID, [SEQUENCE OF qualifiers] } */
                        uint8_t pi_buf[512]; size_t pi_off = 0;
                        der_write_tag_len(pi_buf, sizeof(pi_buf), &pi_off, DER_TAG_OID, pol_oid_len);
                        memcpy(pi_buf + pi_off, pol_oid, pol_oid_len); pi_off += pol_oid_len;
                        if (quals_off > 0) {
                            der_write_tag_len(pi_buf, sizeof(pi_buf), &pi_off, DER_TAG_SEQUENCE, quals_off);
                            memcpy(pi_buf + pi_off, quals_buf, quals_off); pi_off += quals_off;
                        }
                        der_write_tag_len(cp_buf, sizeof(cp_buf), &cp_off, DER_TAG_SEQUENCE, pi_off);
                        memcpy(cp_buf + cp_off, pi_buf, pi_off); cp_off += pi_off;
                        pol_pending = 0;
                        cbor_skip_val_contents(&cp_ctx, &cp_item);
                    } else {
                        cbor_skip_val_contents(&cp_ctx, &cp_item);
                    }
                }
                EMIT_PENDING_NO_QUALS();
#undef EMIT_PENDING_NO_QUALS
                cbor_skip_val_contents(&ctx, &ext_val);
                der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, cp_off);
                memcpy(val_der + val_der_off, cp_buf, cp_off); val_der_off += cp_off;
            } else if (ext_val.type == CBOR_TYPE_BSTR) {
                memcpy(val_der, ext_val.ptr, (size_t)ext_val.val);
                val_der_off = (size_t)ext_val.val;
            } else {
                cbor_skip_val_contents(&ctx, &ext_val);
                continue;
            }

        } else if (ext_val.type == CBOR_TYPE_BSTR) {
            /* Pass raw DER bytes through for unhandled extensions. */
            memcpy(val_der, ext_val.ptr, (size_t)ext_val.val); val_der_off = (size_t)ext_val.val;
        } else {
            /* ARRAY/MAP value for an unhandled extension — skip and move on. */
            cbor_skip_val_contents(&ctx, &ext_val);
            continue;
        }

        /* Wrap: SEQUENCE { OID, [BOOLEAN critical,] OCTET STRING { val_der } } */
        uint8_t inner[2048]; size_t inner_off = 0;
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, oid_len);
        memcpy(inner + inner_off, oid, oid_len); inner_off += oid_len;
        if (C509_EXT_IS_CRITICAL(wire_id)) {
            inner[inner_off++] = DER_TAG_BOOLEAN;
            inner[inner_off++] = 0x01;
            inner[inner_off++] = 0xFF;
        }
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OCTET_STRING, val_der_off);
        memcpy(inner + inner_off, val_der, val_der_off); inner_off += val_der_off;

        der_write_tag_len(ext_seq_buf, sizeof(ext_seq_buf), &ext_seq_off, DER_TAG_SEQUENCE, inner_off);
        memcpy(ext_seq_buf + ext_seq_off, inner, inner_off); ext_seq_off += inner_off;
    }

    if (ext_seq_off > 0) {
        /* [3] EXPLICIT wrapper around SEQUENCE OF Extension */
        size_t seq_tl = der_get_tag_len_size(DER_TAG_SEQUENCE, ext_seq_off);
        if (der_write_tag_len(buffer, size, offset, 0xA3, seq_tl + ext_seq_off) != 0) return -1;
        if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, ext_seq_off) != 0) return -1;
        memcpy(buffer + *offset, ext_seq_buf, ext_seq_off); *offset += ext_seq_off;
    }
    return 0;
}

int x509_encode_tbs(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert) {
    uint8_t fields[2048]; size_t fields_off = 0;

    /* version v3 [0] EXPLICIT INTEGER 2 */
    fields[fields_off++] = 0xA0; fields[fields_off++] = 0x03;
    fields[fields_off++] = 0x02; fields[fields_off++] = 0x01; fields[fields_off++] = 0x02;

    int64_t alg_id = (cert->issuer_alg.type == CBOR_TYPE_NINT)
                     ? -(int64_t)(cert->issuer_alg.val + 1)
                     : (int64_t)cert->issuer_alg.val;

    der_write_integer(fields, sizeof(fields), &fields_off, cert->serial.ptr, (size_t)cert->serial.val);
    x509_encode_algorithm_identifier(fields, sizeof(fields), &fields_off, alg_id);
    x509_encode_name(fields, sizeof(fields), &fields_off, &cert->issuer, &cert->subject);

    /* Validity SEQUENCE { notBefore, notAfter } */
    uint8_t val_buf[64]; size_t val_off = 0;
    x509_encode_validity_time(val_buf, sizeof(val_buf), &val_off, &cert->not_before);
    x509_encode_validity_time(val_buf, sizeof(val_buf), &val_off, &cert->not_after);
    der_write_tag_len(fields, sizeof(fields), &fields_off, DER_TAG_SEQUENCE, val_off);
    memcpy(fields + fields_off, val_buf, val_off); fields_off += val_off;

    x509_encode_name(fields, sizeof(fields), &fields_off, &cert->subject, NULL);

    /* SubjectPublicKeyInfo */
    uint8_t spki_inner[600]; size_t spki_inner_off = 0;
    int64_t pk_alg_id;

    if (cert->pk_alg.type == CBOR_TYPE_ARRAY) {
        /* Raw algorithm: array(2)[alg_oid_body_bstr, params_der_bstr]
         * Used by §7 certs with curves not in the C509 algorithm table. */
        cbor_context_t alg_ctx;
        cbor_value_t alg_oid_v, params_v;
        cbor_init_sub_context(&alg_ctx, &cert->pk_alg);
        if (cbor_decode_next(&alg_ctx, &alg_oid_v) != CBOR_ERR_NONE) return -1;
        if (cbor_decode_next(&alg_ctx, &params_v) != CBOR_ERR_NONE) return -1;
        uint8_t alg_inner[64]; size_t alg_inner_off = 0;
        der_write_tag_len(alg_inner, sizeof(alg_inner), &alg_inner_off,
                          DER_TAG_OID, (size_t)alg_oid_v.val);
        memcpy(alg_inner + alg_inner_off, alg_oid_v.ptr, (size_t)alg_oid_v.val);
        alg_inner_off += (size_t)alg_oid_v.val;
        memcpy(alg_inner + alg_inner_off, params_v.ptr, (size_t)params_v.val);
        alg_inner_off += (size_t)params_v.val;
        der_write_tag_len(spki_inner, sizeof(spki_inner), &spki_inner_off,
                          DER_TAG_SEQUENCE, alg_inner_off);
        memcpy(spki_inner + spki_inner_off, alg_inner, alg_inner_off);
        spki_inner_off += alg_inner_off;
        pk_alg_id = -1; /* not RSA; public key is raw EC point, no decompression */
    } else {
        pk_alg_id = (int64_t)cert->pk_alg.val;
        if (x509_encode_ec_public_key_alg(spki_inner, sizeof(spki_inner), &spki_inner_off, pk_alg_id) != 0)
            return -1;
    }

    uint8_t pk_bit_str[512]; size_t pk_bit_str_off = 0;

    if (pk_alg_id == C509_PK_RSA) {
        /* RSA public key: C509 stores modulus as BSTR (with e=65537 implicit)
         * or as CBOR ARRAY [modulus_bstr, exponent_bstr].
         * Reconstruct DER: BIT_STRING { SEQUENCE { INTEGER n, INTEGER e } } */
        const uint8_t *mod_ptr;
        size_t mod_len;
        uint8_t exp_der[8]; size_t exp_der_off = 0;

        if (cert->subject_pk.type == CBOR_TYPE_ARRAY) {
            cbor_context_t rsa_ctx;
            cbor_value_t n_val, e_val;
            cbor_init_sub_context(&rsa_ctx, &cert->subject_pk);
            if (cbor_decode_next(&rsa_ctx, &n_val) != CBOR_ERR_NONE) return -1;
            if (cbor_decode_next(&rsa_ctx, &e_val) != CBOR_ERR_NONE) return -1;
            mod_ptr = n_val.ptr; mod_len = (size_t)n_val.val;
            /* Encode exponent as DER INTEGER from raw bytes */
            der_write_integer(exp_der, sizeof(exp_der), &exp_der_off, e_val.ptr, (size_t)e_val.val);
        } else {
            /* BSTR: just the modulus; exponent = 65537 = 0x010001 */
            mod_ptr = cert->subject_pk.ptr; mod_len = (size_t)cert->subject_pk.val;
            static const uint8_t e65537[] = { 0x01, 0x00, 0x01 };
            der_write_integer(exp_der, sizeof(exp_der), &exp_der_off, e65537, sizeof(e65537));
        }

        uint8_t rsa_seq[512]; size_t rsa_seq_off = 0;
        der_write_integer(rsa_seq, sizeof(rsa_seq), &rsa_seq_off, mod_ptr, mod_len);
        memcpy(rsa_seq + rsa_seq_off, exp_der, exp_der_off); rsa_seq_off += exp_der_off;

        uint8_t rsa_inner[520]; size_t rsa_inner_off = 0;
        der_write_tag_len(rsa_inner, sizeof(rsa_inner), &rsa_inner_off, DER_TAG_SEQUENCE, rsa_seq_off);
        memcpy(rsa_inner + rsa_inner_off, rsa_seq, rsa_seq_off); rsa_inner_off += rsa_seq_off;

        der_write_tag_len(pk_bit_str, sizeof(pk_bit_str), &pk_bit_str_off,
                          DER_TAG_BIT_STRING, rsa_inner_off + 1);
        pk_bit_str[pk_bit_str_off++] = 0x00; /* unused bits */
        memcpy(pk_bit_str + pk_bit_str_off, rsa_inner, rsa_inner_off); pk_bit_str_off += rsa_inner_off;
    } else {
        const uint8_t *pk_ptr = cert->subject_pk.ptr;
        size_t pk_len = (size_t)cert->subject_pk.val;
        uint8_t decompressed[133];

        if (pk_len > 0 && (pk_ptr[0] == 0xFE || pk_ptr[0] == 0xFD)) {
            mbedtls_ecp_group grp; mbedtls_ecp_point Q;
            mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&Q);
            mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
            switch ((int)cert->pk_alg.val) {
                case C509_PK_SECP256R1:      gid = MBEDTLS_ECP_DP_SECP256R1; break;
                case C509_PK_SECP384R1:      gid = MBEDTLS_ECP_DP_SECP384R1; break;
                case C509_PK_SECP521R1:      gid = MBEDTLS_ECP_DP_SECP521R1; break;
                case C509_PK_BRAINPOOLP256R1:gid = MBEDTLS_ECP_DP_BP256R1;   break;
                case C509_PK_BRAINPOOLP384R1:gid = MBEDTLS_ECP_DP_BP384R1;   break;
                case C509_PK_BRAINPOOLP512R1:gid = MBEDTLS_ECP_DP_BP512R1;   break;
                default: break;
            }
            if (gid != MBEDTLS_ECP_DP_NONE && mbedtls_ecp_group_load(&grp, gid) == 0) {
                uint8_t tmp_pk[128]; memcpy(tmp_pk, pk_ptr, pk_len);
                tmp_pk[0] = (pk_ptr[0] == 0xFE) ? 0x02 : 0x03;
                if (mbedtls_ecp_point_read_binary(&grp, &Q, tmp_pk, pk_len) == 0) {
                    size_t out_len = 0;
                    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                       &out_len, decompressed, sizeof(decompressed)) == 0) {
                        pk_ptr = decompressed; pk_len = out_len;
                    }
                }
            }
            mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&Q);
        }

        der_write_tag_len(pk_bit_str, sizeof(pk_bit_str), &pk_bit_str_off, DER_TAG_BIT_STRING, pk_len + 1);
        pk_bit_str[pk_bit_str_off++] = 0x00; /* unused bits */
        memcpy(pk_bit_str + pk_bit_str_off, pk_ptr, pk_len); pk_bit_str_off += pk_len;
    }

    memcpy(spki_inner + spki_inner_off, pk_bit_str, pk_bit_str_off); spki_inner_off += pk_bit_str_off;
    der_write_tag_len(fields, sizeof(fields), &fields_off, DER_TAG_SEQUENCE, spki_inner_off);
    memcpy(fields + fields_off, spki_inner, spki_inner_off); fields_off += spki_inner_off;

    x509_encode_extensions(fields, sizeof(fields), &fields_off, &cert->extensions);

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, fields_off) != 0) return -1;
    memcpy(buffer + *offset, fields, fields_off); *offset += fields_off;
    return 0;
}

/* Returns 1 if alg_id uses ECDSA-style r||s signature encoding. */
static int is_ecdsa_alg(int64_t alg_id) {
    switch (alg_id) {
        case C509_SIG_ECDSA_SHA256:
        case C509_SIG_ECDSA_SHA384:
        case C509_SIG_ECDSA_SHA512:
        case C509_SIG_ECDSA_SHAKE128:
        case C509_SIG_ECDSA_SHAKE256:
        case C509_SIG_ECDSA_SHA1:
        case C509_SIG_SM2_SM3:
            return 1;
        default:
            return 0;
    }
}

int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert) {
    uint8_t tbs_and_rest[4096]; size_t tbs_and_rest_off = 0;
    if (x509_encode_tbs(tbs_and_rest, sizeof(tbs_and_rest), &tbs_and_rest_off, cert) != 0) return -1;
    int64_t alg_id = (cert->issuer_alg.type == CBOR_TYPE_NINT)
                     ? -(int64_t)(cert->issuer_alg.val + 1)
                     : (int64_t)cert->issuer_alg.val;
    if (x509_encode_algorithm_identifier(tbs_and_rest, sizeof(tbs_and_rest), &tbs_and_rest_off,
                                         alg_id) != 0) return -1;

    /* Signature BIT STRING — ECDSA/SM2 need r||s → DER SEQUENCE { INTEGER r, INTEGER s };
     * Ed25519, Ed448, RSA and others go in raw. */
    uint8_t sig_der[300]; size_t sig_der_off = 0;
    size_t sig_len = (size_t)cert->signature.val;

    if (is_ecdsa_alg(alg_id) && sig_len > 0) {
        size_t coord = sig_len / 2;
        uint8_t rs[160]; size_t rs_off = 0;
        der_write_integer(rs, sizeof(rs), &rs_off, cert->signature.ptr, coord);
        der_write_integer(rs, sizeof(rs), &rs_off, cert->signature.ptr + coord, coord);
        uint8_t seq[170]; size_t seq_off = 0;
        der_write_tag_len(seq, sizeof(seq), &seq_off, DER_TAG_SEQUENCE, rs_off);
        memcpy(seq + seq_off, rs, rs_off); seq_off += rs_off;
        der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, seq_off + 1);
        sig_der[sig_der_off++] = 0x00;
        memcpy(sig_der + sig_der_off, seq, seq_off); sig_der_off += seq_off;
    } else {
        der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, sig_len + 1);
        sig_der[sig_der_off++] = 0x00;
        memcpy(sig_der + sig_der_off, cert->signature.ptr, sig_len);
        sig_der_off += sig_len;
    }
    memcpy(tbs_and_rest + tbs_and_rest_off, sig_der, sig_der_off); tbs_and_rest_off += sig_der_off;

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, tbs_and_rest_off) != 0) return -1;
    memcpy(buffer + *offset, tbs_and_rest, tbs_and_rest_off); *offset += tbs_and_rest_off;
    return 0;
}

int x509_encode_csr(uint8_t *buffer, size_t size, size_t *offset,
                    const uint8_t *cbor, size_t cbor_len) {
    cbor_context_t ctx;
    cbor_init(&ctx, cbor, cbor_len);

    /* The CSR may be wrapped in a CBOR array (e.g. when read straight from a
     * .cbor test vector); if so, step into it before reading the 7 fields. */
    cbor_major_type_t next_type;
    if (cbor_peek_type(&ctx, &next_type) != CBOR_ERR_NONE) return -1;
    if (next_type == CBOR_TYPE_ARRAY) {
        cbor_value_t outer;
        if (cbor_decode_next(&ctx, &outer) != CBOR_ERR_NONE) return -1;
    }

    /* Read the 7 flat C509 Type-3 CSR fields:
     * [type, sigAlg, subject, pkAlg, pkKey, attrs, sigValue]
     * (draft-ietf-cose-cbor-encoded-cert §8). CSR_CONSUME decodes each item
     * and then re-skips it so `ctx.offset` advances past the item without
     * needing separate decode/skip bookkeeping at each call site. */
    #define CSR_CONSUME(f) do { \
        size_t _s = ctx.offset; \
        if (cbor_decode_next(&ctx, &(f)) != CBOR_ERR_NONE) return -1; \
        ctx.offset = _s; \
        if (cbor_skip_item(&ctx) != CBOR_ERR_NONE) return -1; \
    } while(0)

    cbor_value_t type_v, sig_alg_v, subject_v, pk_alg_v, pk_key_v, attrs_v, sig_v;
    CSR_CONSUME(type_v);
    CSR_CONSUME(sig_alg_v);
    CSR_CONSUME(subject_v);
    CSR_CONSUME(pk_alg_v);
    CSR_CONSUME(pk_key_v);
    CSR_CONSUME(attrs_v);
    CSR_CONSUME(sig_v);
    #undef CSR_CONSUME

    int64_t sig_alg_id = (sig_alg_v.type == CBOR_TYPE_NINT)
                         ? -(int64_t)(sig_alg_v.val + 1)
                         : (int64_t)sig_alg_v.val;
    int64_t pk_alg_id  = (int64_t)pk_alg_v.val;

    /* ── CertificationRequestInfo (CRI) ──────────────────────────────────────
     * Builds: SEQUENCE { version=0, subject Name, SubjectPublicKeyInfo,
     *                    [0] IMPLICIT attributes }
     * per PKCS#10 (RFC 2986). This SEQUENCE is later wrapped together with
     * the signatureAlgorithm and signature into the outer
     * CertificationRequest SEQUENCE below. */
    uint8_t cri[4096]; size_t cri_off = 0;

    /* version INTEGER 0 */
    cri[cri_off++] = 0x02; cri[cri_off++] = 0x01; cri[cri_off++] = 0x00;

    /* subject Name */
    if (x509_encode_name(cri, sizeof(cri), &cri_off, &subject_v, NULL) != 0) return -1;

    /* SubjectPublicKeyInfo — reuse same logic as x509_encode_tbs */
    uint8_t spki_inner[600]; size_t spki_inner_off = 0;
    if (x509_encode_ec_public_key_alg(spki_inner, sizeof(spki_inner), &spki_inner_off, pk_alg_id) != 0) return -1;

    uint8_t pk_bit[512]; size_t pk_bit_off = 0;
    const uint8_t *pk_ptr = pk_key_v.ptr;
    size_t pk_len = (size_t)pk_key_v.val;
    uint8_t pk_decompressed[133];
    /* C509 may carry the public key as a compressed EC point (0xFE/0xFD
     * prefix); decompress to standard uncompressed (0x04) form for DER, same
     * convention as used elsewhere for certificate SubjectPublicKeyInfo. */
    if (pk_len > 0 && (pk_ptr[0] == 0xFE || pk_ptr[0] == 0xFD)) {
        mbedtls_ecp_group grp; mbedtls_ecp_point Q;
        mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&Q);
        mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
        switch ((int)pk_alg_id) {
            case C509_PK_SECP256R1:      gid = MBEDTLS_ECP_DP_SECP256R1; break;
            case C509_PK_SECP384R1:      gid = MBEDTLS_ECP_DP_SECP384R1; break;
            case C509_PK_SECP521R1:      gid = MBEDTLS_ECP_DP_SECP521R1; break;
            case C509_PK_BRAINPOOLP256R1:gid = MBEDTLS_ECP_DP_BP256R1;   break;
            case C509_PK_BRAINPOOLP384R1:gid = MBEDTLS_ECP_DP_BP384R1;   break;
            case C509_PK_BRAINPOOLP512R1:gid = MBEDTLS_ECP_DP_BP512R1;   break;
            default: break;
        }
        if (gid != MBEDTLS_ECP_DP_NONE && mbedtls_ecp_group_load(&grp, gid) == 0) {
            uint8_t tmp_pk[128]; memcpy(tmp_pk, pk_ptr, pk_len);
            tmp_pk[0] = (pk_ptr[0] == 0xFE) ? 0x02 : 0x03;
            if (mbedtls_ecp_point_read_binary(&grp, &Q, tmp_pk, pk_len) == 0) {
                size_t out_len = 0;
                if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &out_len, pk_decompressed, sizeof(pk_decompressed)) == 0) {
                    pk_ptr = pk_decompressed; pk_len = out_len;
                }
            }
        }
        mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&Q);
    }
    der_write_tag_len(pk_bit, sizeof(pk_bit), &pk_bit_off, DER_TAG_BIT_STRING, pk_len + 1);
    pk_bit[pk_bit_off++] = 0x00;
    memcpy(pk_bit + pk_bit_off, pk_ptr, pk_len); pk_bit_off += pk_len;
    memcpy(spki_inner + spki_inner_off, pk_bit, pk_bit_off); spki_inner_off += pk_bit_off;
    der_write_tag_len(cri, sizeof(cri), &cri_off, DER_TAG_SEQUENCE, spki_inner_off);
    memcpy(cri + cri_off, spki_inner, spki_inner_off); cri_off += spki_inner_off;

    /* attributes [0] IMPLICIT SET OF Attribute
     *
     * The C509 `attrs` field is a flat CBOR array of (type, item) pairs.
     * Each pair is encoded as a PKCS#10 Attribute SEQUENCE { OID, SET { ... } }
     * and concatenated into attrs_der. Three attribute types are supported:
     *   0 = extensionRequest (PKCS#9, OID_PKCS9_EXT_REQ)   — wraps the C509
     *       extensions array as a PKCS#10 "requested extensions" SET.
     *   1 = challengePassword (PKCS#9, OID_PKCS9_CHAL_PWD) — a UTF8String or
     *       (via CBOR tag 121) PrintableString password.
     *   2 = PrivKeyPossession (OID_PKCS9_PKS_STMT)         — proof-of-
     *       possession statement: issuer Name + serial number, plus an
     *       optional embedded certificate.
     * Any other attribute type is skipped (unsupported). */
    uint8_t attrs_der[2048]; size_t attrs_der_off = 0;
    if (attrs_v.type == CBOR_TYPE_ARRAY && attrs_v.val >= 2) {
        cbor_context_t attrs_ctx;
        cbor_init_sub_context(&attrs_ctx, &attrs_v);

        for (uint64_t k = 0; k + 1 < attrs_v.val; k += 2) {
            cbor_value_t atype, aitem;
            size_t _sa = attrs_ctx.offset;
            if (cbor_decode_next(&attrs_ctx, &atype) != CBOR_ERR_NONE) return -1;
            attrs_ctx.offset = _sa;
            if (cbor_skip_item(&attrs_ctx) != CBOR_ERR_NONE) return -1;

            size_t _sb = attrs_ctx.offset;
            if (cbor_decode_next(&attrs_ctx, &aitem) != CBOR_ERR_NONE) return -1;
            attrs_ctx.offset = _sb;
            if (cbor_skip_item(&attrs_ctx) != CBOR_ERR_NONE) return -1;

            if (atype.type != CBOR_TYPE_UINT) continue;
            int64_t at = (int64_t)atype.val;

            uint8_t attr_oid_and_set[2048]; size_t attr_off = 0;
            const uint8_t *attr_oid; size_t attr_oid_len;
            uint8_t set_val[2048]; size_t set_val_off = 0;

            if (at == 0) {
                /* extensionRequest: aitem is the C509 extensions array.
                 * x509_encode_extensions produces A3{30{exts}}; strip A3 to get 30{exts}. */
                uint8_t ext_tmp[2048]; size_t ext_tmp_off = 0;
                x509_encode_extensions(ext_tmp, sizeof(ext_tmp), &ext_tmp_off, &aitem);
                if (ext_tmp_off < 2) return -1;
                size_t a3_skip = (ext_tmp[1] < 0x80) ? 2 : (ext_tmp[1] == 0x81) ? 3 : 4;
                size_t inner_len = ext_tmp_off - a3_skip;
                der_write_tag_len(set_val, sizeof(set_val), &set_val_off, DER_TAG_SET, inner_len);
                memcpy(set_val + set_val_off, ext_tmp + a3_skip, inner_len); set_val_off += inner_len;
                attr_oid = OID_PKCS9_EXT_REQ; attr_oid_len = sizeof(OID_PKCS9_EXT_REQ);

            } else if (at == 1) {
                /* challengePassword: tstr (UTF8) or tag(121, tstr) (PrintableString) */
                uint8_t cp_tag;
                const uint8_t *cp_ptr; size_t cp_len;
                if (aitem.type == CBOR_TYPE_TSTR) {
                    cp_tag = DER_TAG_UTF8_STRING;
                    cp_ptr = aitem.ptr; cp_len = (size_t)aitem.val;
                } else if (aitem.type == CBOR_TYPE_TAG && aitem.val == 121) {
                    /* aitem.ptr points to the inner TSTR in the cbor buffer */
                    cbor_context_t tag_ctx;
                    cbor_init(&tag_ctx, aitem.ptr, cbor_len);
                    cbor_value_t inner;
                    if (cbor_decode_next(&tag_ctx, &inner) != CBOR_ERR_NONE) return -1;
                    cp_tag = DER_TAG_PRINTABLE_STRING;
                    cp_ptr = inner.ptr; cp_len = (size_t)inner.val;
                } else { return -1; }
                uint8_t cp_der[256]; size_t cp_der_off = 0;
                der_write_tag_len(cp_der, sizeof(cp_der), &cp_der_off, cp_tag, cp_len);
                memcpy(cp_der + cp_der_off, cp_ptr, cp_len); cp_der_off += cp_len;
                der_write_tag_len(set_val, sizeof(set_val), &set_val_off, DER_TAG_SET, cp_der_off);
                memcpy(set_val + set_val_off, cp_der, cp_der_off); set_val_off += cp_der_off;
                attr_oid = OID_PKCS9_CHAL_PWD; attr_oid_len = sizeof(OID_PKCS9_CHAL_PWD);

            } else if (at == 2) {
                /* PrivKeyPossession: aitem = array[issuer, serial, cert_or_null] */
                if (aitem.type != CBOR_TYPE_ARRAY || aitem.val < 2) return -1;
                cbor_context_t pks_ctx;
                cbor_init_sub_context(&pks_ctx, &aitem);

                cbor_value_t pks_issuer, pks_serial;
                size_t _pi = pks_ctx.offset;
                if (cbor_decode_next(&pks_ctx, &pks_issuer) != CBOR_ERR_NONE) return -1;
                pks_ctx.offset = _pi;
                if (cbor_skip_item(&pks_ctx) != CBOR_ERR_NONE) return -1;

                size_t _pj = pks_ctx.offset;
                if (cbor_decode_next(&pks_ctx, &pks_serial) != CBOR_ERR_NONE) return -1;
                pks_ctx.offset = _pj;
                if (cbor_skip_item(&pks_ctx) != CBOR_ERR_NONE) return -1;

                uint8_t iss_der[512]; size_t iss_der_off = 0;
                if (x509_encode_name(iss_der, sizeof(iss_der), &iss_der_off, &pks_issuer, NULL) != 0) return -1;
                uint8_t ser_der[32]; size_t ser_der_off = 0;
                der_write_integer(ser_der, sizeof(ser_der), &ser_der_off,
                                  pks_serial.ptr, (size_t)pks_serial.val);

                /* SEQUENCE { issuer_name, serial_integer } */
                uint8_t iss_ser_seq[560]; size_t iss_ser_off = 0;
                memcpy(iss_ser_seq, iss_der, iss_der_off); iss_ser_off += iss_der_off;
                memcpy(iss_ser_seq + iss_ser_off, ser_der, ser_der_off); iss_ser_off += ser_der_off;
                uint8_t iss_ser_der[576]; size_t isd_off = 0;
                der_write_tag_len(iss_ser_der, sizeof(iss_ser_der), &isd_off, DER_TAG_SEQUENCE, iss_ser_off);
                memcpy(iss_ser_der + isd_off, iss_ser_seq, iss_ser_off); isd_off += iss_ser_off;

                uint8_t pks_outer[2048]; size_t pks_outer_off = 0;
                memcpy(pks_outer, iss_ser_der, isd_off); pks_outer_off += isd_off;

                /* Optional embedded cert */
                if (aitem.val >= 3) {
                    size_t cert_start = pks_ctx.offset;
                    cbor_value_t cert_v;
                    if (cbor_decode_next(&pks_ctx, &cert_v) != CBOR_ERR_NONE) return -1;
                    if (!(cert_v.type == CBOR_TYPE_SIMPLE && cert_v.val == 22)) {
                        /* Non-null: re-parse and encode embedded cert */
                        pks_ctx.offset = cert_start;
                        if (cbor_skip_item(&pks_ctx) != CBOR_ERR_NONE) return -1;
                        const uint8_t *cert_bytes = pks_ctx.buffer + cert_start;
                        size_t cert_bytes_len = pks_ctx.offset - cert_start;
                        c509_cert_t emb_cert;
                        if (c509_parse_cert(&emb_cert, cert_bytes, cert_bytes_len) == CBOR_ERR_NONE) {
                            if (x509_encode_full_cert(pks_outer, sizeof(pks_outer), &pks_outer_off, &emb_cert) != 0)
                                return -1;
                        }
                    }
                }

                /* SET { SEQUENCE { pks_outer } } */
                uint8_t pks_seq[2070]; size_t pks_seq_off = 0;
                der_write_tag_len(pks_seq, sizeof(pks_seq), &pks_seq_off, DER_TAG_SEQUENCE, pks_outer_off);
                memcpy(pks_seq + pks_seq_off, pks_outer, pks_outer_off); pks_seq_off += pks_outer_off;
                der_write_tag_len(set_val, sizeof(set_val), &set_val_off, DER_TAG_SET, pks_seq_off);
                memcpy(set_val + set_val_off, pks_seq, pks_seq_off); set_val_off += pks_seq_off;
                attr_oid = OID_PKCS9_PKS_STMT; attr_oid_len = sizeof(OID_PKCS9_PKS_STMT);
            } else {
                continue; /* unknown attr type */
            }

            /* Build: SEQUENCE { OID, SET_VAL } */
            der_write_tag_len(attr_oid_and_set, sizeof(attr_oid_and_set), &attr_off,
                              DER_TAG_OID, attr_oid_len);
            memcpy(attr_oid_and_set + attr_off, attr_oid, attr_oid_len); attr_off += attr_oid_len;
            memcpy(attr_oid_and_set + attr_off, set_val, set_val_off); attr_off += set_val_off;
            der_write_tag_len(attrs_der, sizeof(attrs_der), &attrs_der_off,
                              DER_TAG_SEQUENCE, attr_off);
            memcpy(attrs_der + attrs_der_off, attr_oid_and_set, attr_off); attrs_der_off += attr_off;
        }
    }
    /* [0] IMPLICIT attributes wrapper */
    der_write_tag_len(cri, sizeof(cri), &cri_off, 0xA0, attrs_der_off);
    memcpy(cri + cri_off, attrs_der, attrs_der_off); cri_off += attrs_der_off;

    /* ── Outer CertificationRequest ──────────────────────────────────────────
     * PKCS#10: SEQUENCE { CertificationRequestInfo, signatureAlgorithm,
     *                     signature BIT STRING } */
    uint8_t outer[8192]; size_t outer_off = 0;

    der_write_tag_len(outer, sizeof(outer), &outer_off, DER_TAG_SEQUENCE, cri_off);
    memcpy(outer + outer_off, cri, cri_off); outer_off += cri_off;

    if (x509_encode_algorithm_identifier(outer, sizeof(outer), &outer_off, sig_alg_id) != 0) return -1;

    /* signature BIT STRING — encoding depends on sig_alg_id / sig_v shape:
     *  - BSTR + ECDHPOP (no key reference): MAC wrapped as
     *    SEQUENCE { OCTET STRING(mac) }.
     *  - BSTR + ECDSA/SM2 (is_ecdsa_alg): raw r||s split in half and
     *    re-encoded as SEQUENCE { INTEGER r, INTEGER s }.
     *  - BSTR + everything else (Ed25519, Ed448, RSA, UNSIGNED): copied
     *    through as a raw octet string inside the BIT STRING.
     *  - ARRAY: ECDHPOP with an explicit key reference (handled below). */
    uint8_t sig_der[1024]; size_t sig_der_off = 0;

    if (sig_v.type == CBOR_TYPE_BSTR) {
        size_t sig_len = (size_t)sig_v.val;
        if (sig_alg_id == C509_SIG_ECDHPOP_SHA256 ||
            sig_alg_id == C509_SIG_ECDHPOP_SHA384 ||
            sig_alg_id == C509_SIG_ECDHPOP_SHA512) {
            /* No-keyRef ECDHPOP: BIT STRING { SEQUENCE { OCTET STRING(mac) } } */
            uint8_t mac_os[300]; size_t mac_os_off = 0;
            der_write_tag_len(mac_os, sizeof(mac_os), &mac_os_off, DER_TAG_OCTET_STRING, sig_len);
            memcpy(mac_os + mac_os_off, sig_v.ptr, sig_len); mac_os_off += sig_len;
            uint8_t mac_seq[312]; size_t mac_seq_off = 0;
            der_write_tag_len(mac_seq, sizeof(mac_seq), &mac_seq_off, DER_TAG_SEQUENCE, mac_os_off);
            memcpy(mac_seq + mac_seq_off, mac_os, mac_os_off); mac_seq_off += mac_os_off;
            der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, mac_seq_off + 1);
            sig_der[sig_der_off++] = 0x00;
            memcpy(sig_der + sig_der_off, mac_seq, mac_seq_off); sig_der_off += mac_seq_off;
        } else if (is_ecdsa_alg(sig_alg_id) && sig_len > 0) {
            /* ECDSA r||s → SEQUENCE { INTEGER r, INTEGER s } */
            size_t coord = sig_len / 2;
            uint8_t rs[160]; size_t rs_off = 0;
            der_write_integer(rs, sizeof(rs), &rs_off, sig_v.ptr, coord);
            der_write_integer(rs, sizeof(rs), &rs_off, sig_v.ptr + coord, coord);
            uint8_t rs_seq[172]; size_t rs_seq_off = 0;
            der_write_tag_len(rs_seq, sizeof(rs_seq), &rs_seq_off, DER_TAG_SEQUENCE, rs_off);
            memcpy(rs_seq + rs_seq_off, rs, rs_off); rs_seq_off += rs_off;
            der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, rs_seq_off + 1);
            sig_der[sig_der_off++] = 0x00;
            memcpy(sig_der + sig_der_off, rs_seq, rs_seq_off); sig_der_off += rs_seq_off;
        } else {
            /* Ed25519, Ed448, RSA, UNSIGNED (may be empty) */
            der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, sig_len + 1);
            sig_der[sig_der_off++] = 0x00;
            memcpy(sig_der + sig_der_off, sig_v.ptr, sig_len); sig_der_off += sig_len;
        }
    } else if (sig_v.type == CBOR_TYPE_ARRAY) {
        /* ECDHPOP with keyRef: [issuer, serial, mac] */
        cbor_context_t sa_ctx;
        cbor_init_sub_context(&sa_ctx, &sig_v);
        cbor_value_t s_iss, s_ser, s_mac;
        size_t _a = sa_ctx.offset;
        if (cbor_decode_next(&sa_ctx, &s_iss) != CBOR_ERR_NONE) return -1;
        sa_ctx.offset = _a; if (cbor_skip_item(&sa_ctx) != CBOR_ERR_NONE) return -1;
        size_t _b = sa_ctx.offset;
        if (cbor_decode_next(&sa_ctx, &s_ser) != CBOR_ERR_NONE) return -1;
        sa_ctx.offset = _b; if (cbor_skip_item(&sa_ctx) != CBOR_ERR_NONE) return -1;
        size_t _c = sa_ctx.offset;
        if (cbor_decode_next(&sa_ctx, &s_mac) != CBOR_ERR_NONE) return -1;
        sa_ctx.offset = _c; if (cbor_skip_item(&sa_ctx) != CBOR_ERR_NONE) return -1;

        uint8_t s_iss_der[512]; size_t s_iss_off = 0;
        x509_encode_name(s_iss_der, sizeof(s_iss_der), &s_iss_off, &s_iss, NULL);
        uint8_t s_ser_der[32]; size_t s_ser_off = 0;
        der_write_integer(s_ser_der, sizeof(s_ser_der), &s_ser_off,
                          s_ser.ptr, (size_t)s_ser.val);
        uint8_t kref_inner[550]; size_t kref_inner_off = 0;
        memcpy(kref_inner, s_iss_der, s_iss_off); kref_inner_off += s_iss_off;
        memcpy(kref_inner + kref_inner_off, s_ser_der, s_ser_off); kref_inner_off += s_ser_off;
        uint8_t kref_seq[566]; size_t kref_off = 0;
        der_write_tag_len(kref_seq, sizeof(kref_seq), &kref_off, DER_TAG_SEQUENCE, kref_inner_off);
        memcpy(kref_seq + kref_off, kref_inner, kref_inner_off); kref_off += kref_inner_off;

        size_t mac_len = (size_t)s_mac.val;
        uint8_t mac_os[80]; size_t mac_os_off = 0;
        der_write_tag_len(mac_os, sizeof(mac_os), &mac_os_off, DER_TAG_OCTET_STRING, mac_len);
        memcpy(mac_os + mac_os_off, s_mac.ptr, mac_len); mac_os_off += mac_len;

        uint8_t dhs_inner[660]; size_t dhs_off = 0;
        memcpy(dhs_inner, kref_seq, kref_off); dhs_off += kref_off;
        memcpy(dhs_inner + dhs_off, mac_os, mac_os_off); dhs_off += mac_os_off;
        uint8_t dhs_seq[676]; size_t dhs_seq_off = 0;
        der_write_tag_len(dhs_seq, sizeof(dhs_seq), &dhs_seq_off, DER_TAG_SEQUENCE, dhs_off);
        memcpy(dhs_seq + dhs_seq_off, dhs_inner, dhs_off); dhs_seq_off += dhs_off;

        der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, dhs_seq_off + 1);
        sig_der[sig_der_off++] = 0x00;
        memcpy(sig_der + sig_der_off, dhs_seq, dhs_seq_off); sig_der_off += dhs_seq_off;
    }
    memcpy(outer + outer_off, sig_der, sig_der_off); outer_off += sig_der_off;

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, outer_off) != 0) return -1;
    memcpy(buffer + *offset, outer, outer_off); *offset += outer_off;
    return 0;
}

/* x509_encode_csr_build() / x509_csr_sign() now live in c509-csr-build.c —
 * a self-contained module (no os/services/c509/cbor.h or c509.h dependency)
 * so it can be linked into EDHOC/OSCORE apps without conflicting with
 * os/lib/cbor.h. See c509-csr-build.h. */
