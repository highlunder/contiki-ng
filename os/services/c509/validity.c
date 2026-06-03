/**
 * @file validity.c
 * @brief Validity checking implementation.
 */

#include "validity.h"
#include "c509_registry.h"
#include <stdio.h>

/* Unix timestamp of 2050-01-01T00:00:00Z — use GeneralizedTime at or beyond. */
#define UNIX_2050 2524608000LL

validity_error_t c509_check_time(const c509_cert_t *cert, int64_t current_time) {
    if (cert->not_before.type != CBOR_TYPE_UINT && cert->not_before.type != CBOR_TYPE_NINT) {
        return VALIDITY_ERR_UNSUPPORTED_FORMAT;
    }

    int64_t nb = (int64_t)cert->not_before.val;
    int64_t na = (int64_t)cert->not_after.val;

    if (current_time < nb) {
        return VALIDITY_ERR_NOT_YET_VALID;
    }
    if (current_time > na) {
        return VALIDITY_ERR_EXPIRED;
    }

    return VALIDITY_ERR_NONE;
}

validity_error_t c509_get_basic_constraints(const c509_cert_t *cert, bool *is_ca, int32_t *path_len) {
    *is_ca = false;
    *path_len = -1;

    if (cert->extensions.type != CBOR_TYPE_ARRAY) {
        return VALIDITY_ERR_NONE;
    }

    cbor_context_t ext_ctx;
    size_t ext_byte_size = (size_t)(cert->signature.ptr - cert->extensions.ptr - cert->signature.header_size);
    cbor_init(&ext_ctx, cert->extensions.ptr, ext_byte_size);

    for (uint64_t i = 0; i < cert->extensions.val; ) {
        cbor_value_t ext_id_val;
        cbor_value_t ext_content;

        if (cbor_decode_next(&ext_ctx, &ext_id_val) != CBOR_ERR_NONE) break;
        i++;
        if (cbor_decode_next(&ext_ctx, &ext_content) != CBOR_ERR_NONE) break;
        i++;

        /* Decode wire id to signed integer. */
        int64_t wire_id;
        if (ext_id_val.type == CBOR_TYPE_NINT) {
            wire_id = -(int64_t)(ext_id_val.val + 1);
        } else {
            wire_id = (int64_t)ext_id_val.val;
        }

        if (C509_EXT_ABS_ID(wire_id) != C509_EXT_BASIC_CONSTRAINTS) {
            continue;
        }

        /* BasicConstraints value: true (CA, no path limit), array [true], or
         * array [true, pathLenConstraint]. */
        if (ext_content.type == CBOR_TYPE_SIMPLE) {
            /* CBOR true = major 7, value 21 (0xf5). */
            *is_ca = (ext_content.val == 21);
        } else if (ext_content.type == CBOR_TYPE_ARRAY) {
            cbor_context_t bc_ctx;
            cbor_init_sub_context(&bc_ctx, &ext_content);
            cbor_value_t bc_ca, bc_pl;
            if (cbor_decode_next(&bc_ctx, &bc_ca) == CBOR_ERR_NONE) {
                *is_ca = (bc_ca.val == 21);
            }
            if (cbor_decode_next(&bc_ctx, &bc_pl) == CBOR_ERR_NONE) {
                *path_len = (int32_t)bc_pl.val;
            }
        }
        return VALIDITY_ERR_NONE;
    }

    return VALIDITY_ERR_NONE;
}

int c509_unix_to_utc_string(int64_t unix_time, char *output) {
    if (output == NULL) return -1;

    int64_t seconds  = unix_time % 60;
    int64_t rem      = unix_time / 60;
    int64_t minutes  = rem % 60;
    rem             /= 60;
    int64_t hours    = rem % 24;
    int64_t days     = rem / 24;

    int year = 1970;
    while (1) {
        int days_in_year = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        if (days < (int64_t)days_in_year) break;
        days -= days_in_year;
        year++;
    }

    int months[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) months[1] = 29;

    int month = 0;
    while (days >= (int64_t)months[month]) {
        days -= months[month];
        month++;
    }
    month++;
    int day = (int)days + 1;

    if (unix_time >= UNIX_2050) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        sprintf(output, "%04d%02d%02d%02d%02d%02dZ",
                year, month, day,
                (int)hours, (int)minutes, (int)seconds);
    } else {
        /* UTCTime: YYMMDDHHMMSSZ */
        sprintf(output, "%02d%02d%02d%02d%02d%02dZ",
                year % 100, month, day,
                (int)hours, (int)minutes, (int)seconds);
    }
    return 0;
}
