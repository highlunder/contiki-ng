/**
 * @file x509_encode.h
 * @brief Functions for encoding C509 structures to X.509 DER.
 */

#ifndef C509_X509_ENCODE_H
#define C509_X509_ENCODE_H

#include "c509.h"
#include "der.h"

/**
 * @brief Encodes a C509 algorithm identifier to DER OID.
 */
int x509_encode_algorithm_identifier(uint8_t *buffer, size_t size, size_t *offset, int64_t alg_id);

/**
 * @brief Encodes a C509 subject/issuer name to DER.
 */
int x509_encode_name(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *name);

/**
 * @brief Encodes a C509 timestamp to DER UTCTime.
 */
int x509_encode_validity(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *time_val);

/**
 * @brief Reconstructs the X.509 TBS (To-Be-Signed) structure from a C509 cert.
 */
int x509_encode_tbs(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert);

/**
 * @brief Assembles the full X.509 DER certificate.
 */
int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert);

#endif // C509_X509_ENCODE_H
