/**
 * @file x509_encode.c
 * @brief Implementation of X.509 DER encoding for C509 certificates.
 */

#include "x509_encode.h"
#include "der.h"
#include "validity.h"
#include "c509_registry.h"
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
static const uint8_t OID_EXT_NAME_CONSTRAINTS[]  = { 0x55, 0x1D, 0x1E };
static const uint8_t OID_EXT_POLICY_MAPPINGS[]   = { 0x55, 0x1D, 0x21 };
static const uint8_t OID_EXT_POLICY_CONSTRAINTS[]= { 0x55, 0x1D, 0x24 };
static const uint8_t OID_EXT_INHIBIT_ANY[]       = { 0x55, 0x1D, 0x36 };
static const uint8_t OID_EXT_OCSP_NO_CHECK[]     = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05 };
static const uint8_t OID_EXT_TLS_FEATURES[]      = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 };

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

int x509_encode_algorithm_identifier(uint8_t *buffer, size_t size, size_t *offset, int alg_id) {
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
        /* RSA-PSS variants share the same OID; parameters would differ but are
         * omitted here as the current use-case is verification only. */
        case C509_SIG_RSA_PSS_SHA256:
        case C509_SIG_RSA_PSS_SHA384:
        case C509_SIG_RSA_PSS_SHA512:
        case C509_SIG_RSA_PSS_SHAKE128:
        case C509_SIG_RSA_PSS_SHAKE256: oid = OID_RSA_PSS; oid_len = sizeof(OID_RSA_PSS); break;
        default: return -1;
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

int x509_encode_ec_public_key_alg(uint8_t *buffer, size_t size, size_t *offset, int pk_alg_id) {
    uint8_t inner[64]; size_t inner_off = 0;
    printf("[x509_encode] ec_pk_alg entry pk_alg_id=%d RSA=%d ED25519=%d SECP256R1=%d\n",
           pk_alg_id, C509_PK_RSA, C509_PK_ED25519, C509_PK_SECP256R1);

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
            default:
                printf("[x509_encode] ec_pk_alg switch default hit pk_alg_id=%d\n", pk_alg_id);
                return -1;
        }
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, sizeof(OID_ID_EC_PUBKEY));
        memcpy(inner + inner_off, OID_ID_EC_PUBKEY, sizeof(OID_ID_EC_PUBKEY));
        inner_off += sizeof(OID_ID_EC_PUBKEY);
        der_write_tag_len(inner, sizeof(inner), &inner_off, DER_TAG_OID, curve_oid_len);
        memcpy(inner + inner_off, curve_oid, curve_oid_len);
        inner_off += curve_oid_len;
    }

    printf("[x509_encode] ec_pk_alg before outer seq inner_off=%u size=%u off=%u\n",
           (unsigned)inner_off, (unsigned)size, (unsigned)*offset);
    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, inner_off) != 0) {
        printf("[x509_encode] ec_pk_alg outer seq der_write_tag_len failed\n");
        return -1;
    }
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

int x509_encode_extensions(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *exts) {
    if (exts->type != CBOR_TYPE_ARRAY) return 0;

    uint8_t ext_seq_buf[1024]; size_t ext_seq_off = 0;
    cbor_context_t ctx;
    cbor_init_sub_context(&ctx, exts);

    for (uint64_t i = 0; i < exts->val; i += 2) {
        cbor_value_t ext_id_val, ext_val;
        if (cbor_decode_next(&ctx, &ext_id_val) != CBOR_ERR_NONE) break;
        if (cbor_decode_next(&ctx, &ext_val) != CBOR_ERR_NONE) break;

        int64_t wire_id = (ext_id_val.type == CBOR_TYPE_UINT)
                          ? (int64_t)ext_id_val.val
                          : -(int64_t)(ext_id_val.val + 1);
        int abs_id = (int)C509_EXT_ABS_ID(wire_id);

        const uint8_t *oid = NULL; size_t oid_len = 0;
        switch (abs_id) {
            case C509_EXT_SUBJECT_KEY_ID:   oid = OID_EXT_SUBJECT_KEY_ID;    oid_len = sizeof(OID_EXT_SUBJECT_KEY_ID);    break;
            case C509_EXT_KEY_USAGE:        oid = OID_EXT_KEY_USAGE;         oid_len = sizeof(OID_EXT_KEY_USAGE);         break;
            case C509_EXT_SUBJECT_ALT_NAME: oid = OID_EXT_SUBJECT_ALT_NAME;  oid_len = sizeof(OID_EXT_SUBJECT_ALT_NAME);  break;
            case C509_EXT_BASIC_CONSTRAINTS:oid = OID_EXT_BASIC_CONSTRAINTS; oid_len = sizeof(OID_EXT_BASIC_CONSTRAINTS); break;
            case C509_EXT_CRL_DIST_POINTS:  oid = OID_EXT_CRL_DIST_POINTS;   oid_len = sizeof(OID_EXT_CRL_DIST_POINTS);   break;
            case C509_EXT_CERT_POLICIES:    oid = OID_EXT_CERT_POLICIES;     oid_len = sizeof(OID_EXT_CERT_POLICIES);     break;
            case C509_EXT_AUTHORITY_KEY_ID: oid = OID_EXT_AUTHORITY_KEY_ID;  oid_len = sizeof(OID_EXT_AUTHORITY_KEY_ID);  break;
            case C509_EXT_EXT_KEY_USAGE:    oid = OID_EXT_EXT_KEY_USAGE;     oid_len = sizeof(OID_EXT_EXT_KEY_USAGE);     break;
            case C509_EXT_AUTHORITY_INFO_ACCESS: oid = OID_EXT_AIA;          oid_len = sizeof(OID_EXT_AIA);               break;
            case C509_EXT_NAME_CONSTRAINTS: oid = OID_EXT_NAME_CONSTRAINTS;  oid_len = sizeof(OID_EXT_NAME_CONSTRAINTS);  break;
            case C509_EXT_POLICY_MAPPINGS:  oid = OID_EXT_POLICY_MAPPINGS;   oid_len = sizeof(OID_EXT_POLICY_MAPPINGS);   break;
            case C509_EXT_POLICY_CONSTRAINTS:oid = OID_EXT_POLICY_CONSTRAINTS;oid_len = sizeof(OID_EXT_POLICY_CONSTRAINTS);break;
            case C509_EXT_INHIBIT_ANY_POLICY:oid = OID_EXT_INHIBIT_ANY;      oid_len = sizeof(OID_EXT_INHIBIT_ANY);       break;
            case C509_EXT_OCSP_NO_CHECK:    oid = OID_EXT_OCSP_NO_CHECK;     oid_len = sizeof(OID_EXT_OCSP_NO_CHECK);     break;
            case C509_EXT_TLS_FEATURES:     oid = OID_EXT_TLS_FEATURES;      oid_len = sizeof(OID_EXT_TLS_FEATURES);      break;
            default: cbor_skip_item(&ctx); continue;
        }

        uint8_t val_der[256]; size_t val_der_off = 0;

        if (abs_id == C509_EXT_BASIC_CONSTRAINTS) {
            /* C509 encodes: NINT(-1) = CA/no-limit, UINT(N) = CA/pathLen N */
            int64_t bc_val = (ext_val.type == CBOR_TYPE_UINT)
                             ? (int64_t)ext_val.val
                             : -(int64_t)(ext_val.val + 1);
            uint8_t bc_content[32]; size_t bc_off = 0;
            if (bc_val == -1 || bc_val >= 0) {
                bc_content[bc_off++] = DER_TAG_BOOLEAN;
                bc_content[bc_off++] = 0x01;
                bc_content[bc_off++] = 0xFF; /* cA = TRUE */
                if (bc_val >= 0) {
                    bc_content[bc_off++] = DER_TAG_INTEGER;
                    bc_content[bc_off++] = 0x01;
                    bc_content[bc_off++] = (uint8_t)bc_val;
                }
            }
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, bc_off);
            memcpy(val_der + val_der_off, bc_content, bc_off); val_der_off += bc_off;
        } else if (abs_id == C509_EXT_SUBJECT_KEY_ID) {
            /* SKID: OCTET STRING wrapping the key identifier bytes */
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_OCTET_STRING, (size_t)ext_val.val);
            memcpy(val_der + val_der_off, ext_val.ptr, (size_t)ext_val.val); val_der_off += (size_t)ext_val.val;
        } else if (abs_id == C509_EXT_AUTHORITY_KEY_ID) {
            /* C509 §7.3: two AKI encodings exist:
             *   bstr         keyid-only  (07 54 <20 bytes>)
             *   array[3]     keyid+issuer+serial  (07 83 54 <20 bytes> ...)
             * In both cases we extract only the keyIdentifier and encode it as
             * SEQUENCE { [0] IMPLICIT keyIdentifier }. */
            const uint8_t *keyid_ptr;
            size_t keyid_len;
            cbor_value_t keyid_val;
            if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t aki_ctx;
                cbor_init_sub_context(&aki_ctx, &ext_val);
                if (cbor_decode_next(&aki_ctx, &keyid_val) != CBOR_ERR_NONE) continue;
                keyid_ptr = keyid_val.ptr;
                keyid_len = (size_t)keyid_val.val;
            } else {
                keyid_ptr = ext_val.ptr;
                keyid_len = (size_t)ext_val.val;
            }
            uint8_t akid_inner[34]; size_t akid_inner_off = 0;
            akid_inner[akid_inner_off++] = 0x80; /* [0] IMPLICIT */
            akid_inner[akid_inner_off++] = (uint8_t)keyid_len;
            memcpy(akid_inner + akid_inner_off, keyid_ptr, keyid_len);
            akid_inner_off += keyid_len;
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, akid_inner_off);
            memcpy(val_der + val_der_off, akid_inner, akid_inner_off); val_der_off += akid_inner_off;
        } else if (abs_id == C509_EXT_KEY_USAGE) {
            /* C509 encodes KeyUsage as a CBOR UINT where bit N maps to KeyUsage
             * bit N (RFC 5280).  DER BIT STRING is MSB-first, so bit N occupies
             * byte position (7-N), which is the reverse of the UINT bit order. */
            if (ext_val.type == CBOR_TYPE_UINT) {
                uint8_t ku = bit_reverse8((uint8_t)(ext_val.val & 0xFF));
                int unused = 0;
                if (ku == 0) {
                    unused = 8;
                } else {
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
                continue;
            }
        } else if (abs_id == C509_EXT_EXT_KEY_USAGE) {
            /* EKU: SEQUENCE of OIDs from integer IDs.
             * C509 value is either a single UINT (one EKU) or an ARRAY of UINTs. */
            uint8_t eku_inner[128]; size_t eku_inner_off = 0;

            /* Helper lambda via local function pointer not available in C99 —
             * inline the OID lookup twice instead. */
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
                    EKU_APPEND_OID(eku_id.val);
                }
            }
#undef EKU_APPEND_OID
            der_write_tag_len(val_der, sizeof(val_der), &val_der_off, DER_TAG_SEQUENCE, eku_inner_off);
            memcpy(val_der + val_der_off, eku_inner, eku_inner_off); val_der_off += eku_inner_off;
        } else if (ext_val.type == CBOR_TYPE_BSTR) {
            /* Pass raw bytes through as extension value DER. */
            memcpy(val_der, ext_val.ptr, (size_t)ext_val.val); val_der_off = (size_t)ext_val.val;
        } else {
            continue;
        }

        /* Wrap: SEQUENCE { OID, [BOOLEAN critical DEFAULT FALSE,] OCTET STRING value } */
        uint8_t inner[512]; size_t inner_off = 0;
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

    int alg_id = (cert->issuer_alg.type == CBOR_TYPE_NINT)
                 ? -(int)(cert->issuer_alg.val + 1)
                 : (int)cert->issuer_alg.val;

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
    int pk_alg_id = (int)cert->pk_alg.val;
    if (x509_encode_ec_public_key_alg(spki_inner, sizeof(spki_inner), &spki_inner_off, pk_alg_id) != 0) {
        printf("[x509_encode] ec_public_key_alg failed for pk_alg=%d\n", pk_alg_id);
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

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, fields_off) != 0) {
        printf("[x509_encode] tbs der_write_tag_len failed: fields_off=%u size=%u\n", (unsigned)fields_off, (unsigned)size);
        return -1;
    }
    memcpy(buffer + *offset, fields, fields_off); *offset += fields_off;
    return 0;
}

int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert) {
    uint8_t tbs_and_rest[4096]; size_t tbs_and_rest_off = 0;
    printf("[x509_encode] calling x509_encode_tbs type=%d pk_alg=%d\n", (int)cert->type.val, (int)cert->pk_alg.val);
    int tbs_ret = x509_encode_tbs(tbs_and_rest, sizeof(tbs_and_rest), &tbs_and_rest_off, cert);
    if (tbs_ret != 0) {
        printf("[x509_encode] x509_encode_tbs failed: %d\n", tbs_ret);
        return -1;
    }
    printf("[x509_encode] tbs ok off=%u\n", (unsigned)tbs_and_rest_off);
    int alg_id = (cert->issuer_alg.type == CBOR_TYPE_NINT)
               ? -(int)(cert->issuer_alg.val + 1)
               : (int)cert->issuer_alg.val;
    if (x509_encode_algorithm_identifier(tbs_and_rest, sizeof(tbs_and_rest), &tbs_and_rest_off,
                                         alg_id) != 0) {
        printf("[x509_encode] algorithm_identifier failed for alg_id=%d\n", (int)alg_id);
        return -1;
    }

    /* Signature BIT STRING */
    uint8_t sig_der[256]; size_t sig_der_off = 0;
    if (cert->signature.val == 64) {
        /* Raw ECDSA (r||s, 32+32) → DER SEQUENCE { INTEGER r, INTEGER s } */
        uint8_t rs[128]; size_t rs_off = 0;
        der_write_integer(rs, sizeof(rs), &rs_off, cert->signature.ptr, 32);
        der_write_integer(rs, sizeof(rs), &rs_off, cert->signature.ptr + 32, 32);
        uint8_t seq[140]; size_t seq_off = 0;
        der_write_tag_len(seq, sizeof(seq), &seq_off, DER_TAG_SEQUENCE, rs_off);
        memcpy(seq + seq_off, rs, rs_off); seq_off += rs_off;
        der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off, DER_TAG_BIT_STRING, seq_off + 1);
        sig_der[sig_der_off++] = 0x00;
        memcpy(sig_der + sig_der_off, seq, seq_off); sig_der_off += seq_off;
    } else {
        der_write_tag_len(sig_der, sizeof(sig_der), &sig_der_off,
                          DER_TAG_BIT_STRING, (size_t)cert->signature.val + 1);
        sig_der[sig_der_off++] = 0x00;
        memcpy(sig_der + sig_der_off, cert->signature.ptr, (size_t)cert->signature.val);
        sig_der_off += (size_t)cert->signature.val;
    }
    memcpy(tbs_and_rest + tbs_and_rest_off, sig_der, sig_der_off); tbs_and_rest_off += sig_der_off;

    if (der_write_tag_len(buffer, size, offset, DER_TAG_SEQUENCE, tbs_and_rest_off) != 0) {
        printf("[x509_encode] full_cert der_write_tag_len failed: tbs_and_rest_off=%u size=%u\n", (unsigned)tbs_and_rest_off, (unsigned)size);
        return -1;
    }
    memcpy(buffer + *offset, tbs_and_rest, tbs_and_rest_off); *offset += tbs_and_rest_off;
    return 0;
}
