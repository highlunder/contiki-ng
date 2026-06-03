/**
 * @file x509_encode.h
 * @brief Functions for encoding C509 structures to X.509 DER.
 */

#ifndef C509_X509_ENCODE_H
#define C509_X509_ENCODE_H

#include "c509.h"
#include "der.h"

/**
 * @brief Encodes a C509 algorithm identifier to a DER AlgorithmIdentifier SEQUENCE.
 */
int x509_encode_algorithm_identifier(uint8_t *buffer, size_t size, size_t *offset, int alg_id);

/**
 * @brief Encodes a C509 EC public-key algorithm identifier to DER.
 *
 * Produces the SubjectPublicKeyInfo AlgorithmIdentifier SEQUENCE containing
 * the id-ecPublicKey OID (or id-EdDSA for EdDSA keys) and the curve OID.
 */
int x509_encode_ec_public_key_alg(uint8_t *buffer, size_t size, size_t *offset, int pk_alg_id);

/**
 * @brief Encodes a C509 Unix timestamp to a DER UTCTime or GeneralizedTime.
 *
 * Uses GeneralizedTime for timestamps >= 2050-01-01 (Unix >= 2524608000),
 * UTCTime otherwise.
 */
int x509_encode_validity_time(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *time_val);

/**
 * @brief Encodes a C509 subject/issuer name to a DER Name SEQUENCE.
 *
 * @param name    The decoded name value from the C509 certificate.
 * @param subject The decoded subject value (used when name is the "same as issuer"
 *                sentinel value 22); may be NULL when encoding the subject field.
 */
int x509_encode_name(uint8_t *buffer, size_t size, size_t *offset,
                     const cbor_value_t *name, const cbor_value_t *subject);

/**
 * @brief Encodes C509 extensions to DER Extensions (the [3] EXPLICIT wrapper).
 */
int x509_encode_extensions(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *exts);

/**
 * @brief Reconstructs the X.509 TBSCertificate SEQUENCE from a C509 cert.
 */
int x509_encode_tbs(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert);

/**
 * @brief Assembles the full X.509 DER Certificate SEQUENCE.
 */
int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert);

#endif // C509_X509_ENCODE_H
