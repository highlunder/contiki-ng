/**
 * @file validator.h
 * @brief High-level C509 certificate chain validator.
 */

#ifndef C509_VALIDATOR_H
#define C509_VALIDATOR_H

#include "c509.h"
#include "crypto.h"
#include "validity.h"

/**
 * @brief Error codes for chain validation.
 */
typedef enum {
    VALIDATOR_OK = 0,
    VALIDATOR_ERR_PARSE,
    VALIDATOR_ERR_SIG,
    VALIDATOR_ERR_TIME,
    VALIDATOR_ERR_NOT_CA,
    VALIDATOR_ERR_CHAIN_BROKEN,
    VALIDATOR_ERR_INTERNAL
} validator_error_t;

/**
 * @brief Verifies a chain of C509 certificates.
 * 
 * The chain should be ordered from leaf to intermediate. 
 * The root_pk is the trust anchor used to verify the last certificate in the chain.
 * 
 * @param chain Array of buffers containing C509 certificates.
 * @param chain_lens Array of lengths for each buffer in the chain.
 * @param chain_len Number of certificates in the chain.
 * @param root_pk The trusted root public key.
 * @param root_pk_len Length of the root public key.
 * @param current_time Current Unix timestamp for validity checks.
 * @return VALIDATOR_OK on success, or an error code.
 */
validator_error_t c509_verify_chain(const uint8_t **chain, 
                                   const size_t *chain_lens, 
                                   size_t chain_count,
                                   const uint8_t *root_pk, 
                                   size_t root_pk_len,
                                   int64_t current_time);

#endif // C509_VALIDATOR_H
