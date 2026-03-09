/**
 * @file c509.h
 * @brief Structural parser for C509 certificates.
 */

#ifndef C509_C509_H
#define C509_C509_H

#include "cbor.h"

/**
 * @brief Represents a parsed C509 certificate.
 * 
 * This structure holds pointers and lengths to the original CBOR buffer
 * for efficient, zero-copy access to certificate fields.
 */
typedef struct {
    // TBS (To-Be-Signed) Fields
    cbor_value_t type;
    cbor_value_t serial;
    cbor_value_t issuer_alg;
    cbor_value_t issuer;
    cbor_value_t not_before;
    cbor_value_t not_after;
    cbor_value_t subject;
    cbor_value_t pk_alg;
    cbor_value_t subject_pk;
    cbor_value_t extensions;

    // Signature
    cbor_value_t signature;

    // Pointers for Hashing
    const uint8_t *tbs_ptr;  ///< Pointer to the start of the TBS content in CBOR
    size_t tbs_len;          ///< Length of the TBS content
} c509_cert_t;

/**
 * @brief Parses a C509 certificate from a CBOR buffer.
 * 
 * @param cert Pointer to the structure to fill.
 * @param buffer Source CBOR data.
 * @param size Size of the source data.
 * @return CBOR_ERR_NONE on success, or an error code.
 */
cbor_error_t c509_parse_cert(c509_cert_t *cert, const uint8_t *buffer, size_t size);

#endif // C509_C509_H
