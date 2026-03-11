/**
 * @file x509_encode.h
 * @brief Functions for encoding C509 structures to X.509 DER.
 */

#ifndef C509_X509_ENCODE_H
#define C509_X509_ENCODE_H

#include "c509/c509.h"
#include "c509/der.h"

/**
 * @brief Encodes a C509 AlgorithmIdentifier to X.509 DER.
 */
int x509_encode_algorithm_identifier(uint8_t *buffer, size_t size, size_t *offset, int64_t alg_id);

/**
 * @brief Encodes a C509 Name to X.509 DER.
 */
int x509_encode_name(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *name, const cbor_value_t *subject);

/**
 * @brief Encodes a C509 Validity to X.509 DER.
 */
int x509_encode_validity(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *time_val);

/**
 * @brief Assembles the full X.509 DER certificate.
 */
int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert);

#endif // C509_X509_ENCODE_H
