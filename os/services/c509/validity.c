/**
 * @file validity.c
 * @brief Validity checking implementation.
 */

#include "validity.h"

// C509 Extension OID Mappings (Draft Section 9.4)
#define C509_EXT_BASIC_CONSTRAINTS -4

validity_error_t c509_check_time(const c509_cert_t *cert, int64_t current_time) {
    // C509 encodes validity as Unix timestamps (integers)
    if (cert->not_before.type != CBOR_TYPE_UINT && cert->not_before.type != CBOR_TYPE_NINT) {
        return VALIDITY_ERR_UNSUPPORTED_FORMAT;
    }
    
    // For simplicity, we assume positive UINT for now (standard for future dates)
    // Note: NINT handling would be needed for pre-1970 if supported by C509
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
    *path_len = -1; // -1 means no constraint

    if (cert->extensions.type != CBOR_TYPE_ARRAY) {
        return VALIDITY_ERR_NONE; // No extensions
    }

    cbor_context_t ext_ctx;
    // The byte size of the extensions content is the distance to the signature field.
    size_t ext_byte_size = (size_t)(cert->signature.ptr - cert->extensions.ptr - cert->signature.header_size);
    // Actually, cert->signature.ptr points to the content of the signature.
    // We want the start of the signature item (its header).
    // So ptr - header_size.
    cbor_init(&ext_ctx, cert->extensions.ptr, ext_byte_size); 
    
    // We need to iterate through the array elements.
    // The array has cert->extensions.val elements.
    for (uint64_t i = 0; i < cert->extensions.val; ) {
        cbor_value_t ext_id;
        cbor_value_t ext_val;
        
        if (cbor_decode_next(&ext_ctx, &ext_id) != CBOR_ERR_NONE) break;
        i++;
        if (cbor_decode_next(&ext_ctx, &ext_val) != CBOR_ERR_NONE) break;
        i++;

        if (ext_id.type == CBOR_TYPE_NINT && (int64_t)ext_id.val == (C509_EXT_BASIC_CONSTRAINTS * -1 - 1)) {
            // Found Basic Constraints.
            if (ext_val.type == CBOR_TYPE_SIMPLE) {
                *is_ca = (ext_val.val == 21); // 21 is CBOR True
            } else if (ext_val.type == CBOR_TYPE_ARRAY) {
                cbor_context_t bc_ctx;
                // For simplicity in this mock-heavy function, use a large enough size or track it.
                // Here we can use the remaining size in ext_ctx.
                cbor_init(&bc_ctx, ext_val.ptr, (size_t)(ext_ctx.size - ext_ctx.offset));
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
    }

    return VALIDITY_ERR_NONE;
}
