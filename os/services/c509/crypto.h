/**
 * @file crypto.h
 * @brief Crypto abstraction layer for C509 verification.
 */

#ifndef C509_CRYPTO_H
#define C509_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "c509.h"

/**
 * @brief Error codes for crypto operations.
 */
typedef enum {
    CRYPTO_ERR_NONE = 0,
    CRYPTO_ERR_HASH_FAILED,
    CRYPTO_ERR_SIG_INVALID,
    CRYPTO_ERR_UNSUPPORTED_ALG,
    CRYPTO_ERR_MALFORMED,
    CRYPTO_ERR_INTERNAL
} crypto_error_t;

/**
 * @brief Verifies the signature of a C509 certificate.
 * 
 * @param cert The parsed certificate.
 * @param issuer_pk The public key of the issuer (raw bytes).
 * @param issuer_pk_len Length of the issuer public key.
 * @return CRYPTO_ERR_NONE on successful verification, or an error code.
 */
crypto_error_t c509_verify_signature(const c509_cert_t *cert, 
                                    const uint8_t *issuer_pk, 
                                    size_t issuer_pk_len);

#endif // C509_CRYPTO_H
