/**
 * @file validity.h
 * @brief Validity and basic constraints checking for C509.
 */

#ifndef C509_VALIDITY_H
#define C509_VALIDITY_H

#include <stdint.h>
#include <stdbool.h>
#include "c509.h"

/**
 * @brief Error codes for validity checks.
 */
typedef enum {
    VALIDITY_ERR_NONE = 0,
    VALIDITY_ERR_EXPIRED,
    VALIDITY_ERR_NOT_YET_VALID,
    VALIDITY_ERR_BASIC_CONSTRAINTS_FAILED,
    VALIDITY_ERR_UNSUPPORTED_FORMAT
} validity_error_t;

/**
 * @brief Checks if the certificate is valid at the given time.
 *
 * @param cert The parsed certificate.
 * @param current_time Unix timestamp (seconds since epoch).
 * @return VALIDITY_ERR_NONE on success, or an error code.
 */
validity_error_t c509_check_time(const c509_cert_t *cert, int64_t current_time);

/**
 * @brief Checks basic constraints of the certificate.
 *
 * @param cert The parsed certificate.
 * @param is_ca Pointer to store CA flag.
 * @param path_len Pointer to store path length constraint (-1 = unconstrained).
 * @return VALIDITY_ERR_NONE on success, or an error code.
 */
validity_error_t c509_get_basic_constraints(const c509_cert_t *cert, bool *is_ca, int32_t *path_len);

/**
 * @brief Converts a Unix timestamp to an X.509 UTCTime string (YYMMDDHHMMSSZ).
 *
 * For timestamps on or after 2050-01-01 (Unix >= 2524608000) the output is
 * GeneralizedTime format (YYYYMMDDHHMMSSZ, 15 chars + NUL).  For earlier dates
 * UTCTime format is used (13 chars + NUL).  The caller must provide a buffer of
 * at least 16 bytes.
 *
 * @param unix_time Seconds since 1970-01-01T00:00:00Z.
 * @param output    Buffer to write the null-terminated string into (>= 16 bytes).
 * @return 0 on success, -1 if output is NULL.
 */
int c509_unix_to_utc_string(int64_t unix_time, char *output);

#endif // C509_VALIDITY_H
