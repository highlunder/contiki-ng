/**
 * @file c509.c
 * @brief Structural parser for C509 certificates.
 */

#include "c509/c509.h"

#include <stdio.h>

cbor_error_t c509_parse_cert(c509_cert_t *cert, const uint8_t *buffer, size_t size) {
    cbor_context_t ctx;
    cbor_init(&ctx, buffer, size);

    cbor_major_type_t next_type;
    cbor_error_t err = cbor_peek_type(&ctx, &next_type);
    if (err != CBOR_ERR_NONE) return err;

    if (next_type == CBOR_TYPE_ARRAY) {
        cbor_value_t outer_array;
        if ((err = cbor_decode_next(&ctx, &outer_array)) != CBOR_ERR_NONE) return err;
    }

    // The To-Be-Signed (TBS) content starts at the first field (index 0).
    cert->tbs_ptr = &buffer[ctx.offset];

    #define CONSUME_FIELD(f) do { \
        size_t _start = ctx.offset; \
        cbor_error_t _err = cbor_decode_next(&ctx, &(f)); \
        if (_err != CBOR_ERR_NONE) return _err; \
        ctx.offset = _start; \
        _err = cbor_skip_item(&ctx); \
        if (_err != CBOR_ERR_NONE) return _err; \
        printf("DEBUG: Consumed Field %s: type=%d, val=%llu, next_offset=%zu\n", #f, (f).type, (unsigned long long)(f).val, ctx.offset); \
    } while(0)

    CONSUME_FIELD(cert->type);
    CONSUME_FIELD(cert->serial);
    CONSUME_FIELD(cert->issuer_alg);
    CONSUME_FIELD(cert->issuer);
    CONSUME_FIELD(cert->not_before);
    CONSUME_FIELD(cert->not_after);
    CONSUME_FIELD(cert->subject);
    CONSUME_FIELD(cert->pk_alg);
    CONSUME_FIELD(cert->subject_pk);
    CONSUME_FIELD(cert->extensions);

    // TBS ends exactly after the 10th field.
    cert->tbs_len = (size_t)(&buffer[ctx.offset] - cert->tbs_ptr);

    CONSUME_FIELD(cert->signature);
    #undef CONSUME_FIELD

    return CBOR_ERR_NONE;
}
