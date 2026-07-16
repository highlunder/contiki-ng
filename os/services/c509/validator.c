/**
 * @file validator.c
 * @brief Chain validation implementation.
 */

#include "validator.h"
#include "c509-crl.h"
#include <string.h>

validator_error_t c509_verify_chain(const uint8_t **chain,
                                   const size_t *chain_lens,
                                   size_t chain_count,
                                   const uint8_t *root_pk,
                                   size_t root_pk_len,
                                   int64_t root_pk_alg,
                                   int64_t current_time) {
    if (chain_count == 0) return VALIDATOR_ERR_CHAIN_BROKEN;

    const uint8_t *current_issuer_pk = root_pk;
    size_t current_issuer_pk_len = root_pk_len;
    int64_t current_issuer_pk_alg = root_pk_alg;

    // Verify chain from last (intermediate signed by root) to first (leaf).
    // Note: This logic assumes the chain is ordered leaf index 0, intermediate index N-1.
    // So we iterate backwards to propagate the public keys correctly.
    for (int i = (int)chain_count - 1; i >= 0; i--) {
        c509_cert_t cert;
        if (c509_parse_cert(&cert, chain[i], chain_lens[i]) != CBOR_ERR_NONE) {
            return VALIDATOR_ERR_PARSE;
        }

        // 1. Verify Signature using current issuer public key
        if (c509_verify_signature(&cert, current_issuer_pk, current_issuer_pk_len, current_issuer_pk_alg) != CRYPTO_ERR_NONE) {
            return VALIDATOR_ERR_SIG;
        }

        // 2. Check Time Validity
        if (c509_check_time(&cert, current_time) != VALIDITY_ERR_NONE) {
            return VALIDATOR_ERR_TIME;
        }

        // 3. Check Basic Constraints (if not leaf)
        if (i > 0) {
            bool is_ca;
            int32_t path_len;
            if (c509_get_basic_constraints(&cert, &is_ca, &path_len) != VALIDITY_ERR_NONE) {
                return VALIDATOR_ERR_NOT_CA;
            }
            if (!is_ca) return VALIDATOR_ERR_NOT_CA;
        }

        // 4. Update issuer public key (and its algorithm) for the next
        // certificate in the chain.
        current_issuer_pk = cert.subject_pk.ptr;
        current_issuer_pk_len = (size_t)cert.subject_pk.val;
        current_issuer_pk_alg = cert.pk_alg.val;
    }

    return VALIDATOR_OK;
}

validator_error_t
c509_verify_chain_with_revocation(const uint8_t **chain,
                                  const size_t *chain_lens,
                                  size_t chain_count,
                                  const uint8_t *root_pk,
                                  size_t root_pk_len,
                                  int64_t root_pk_alg,
                                  int64_t current_time,
                                  const uint8_t *crl,
                                  size_t crl_len)
{
    validator_error_t rc = c509_verify_chain(chain, chain_lens, chain_count,
                                             root_pk, root_pk_len, root_pk_alg,
                                             current_time);
    if(rc != VALIDATOR_OK) {
        return rc;
    }
    if(crl == NULL || crl_len == 0 || chain_count == 0) {
        return VALIDATOR_OK;   /* no CRL supplied: chain-only result */
    }

    c509_crl_t parsed;
    if(c509_crl_parse(crl, crl_len, &parsed) != 0) {
        return VALIDATOR_ERR_PARSE;
    }
    /* Check the leaf (chain[0]); revoked -> reject. */
    int revoked = c509_crl_is_cert_revoked(chain[0], chain_lens[0], &parsed);
    if(revoked < 0) {
        return VALIDATOR_ERR_PARSE;
    }
    return revoked ? VALIDATOR_ERR_REVOKED : VALIDATOR_OK;
}
