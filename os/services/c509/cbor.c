/**
 * @file cbor.c
 * @brief Implementation of the low-footprint CBOR decoder.
 */

#include "c509/cbor.h"

void cbor_init(cbor_context_t *ctx, const uint8_t *buffer, size_t size) {
    ctx->buffer = buffer;
    ctx->size = size;
    ctx->offset = 0;
}

/**
 * @brief Helper to read 16-bit big-endian value.
 */
static uint16_t read_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

/**
 * @brief Helper to read 32-bit big-endian value.
 */
static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | 
           ((uint32_t)p[2] << 8)  | p[3];
}

/**
 * @brief Helper to read 64-bit big-endian value.
 */
static uint64_t read_u64(const uint8_t *p) {
    return ((uint64_t)read_u32(p) << 32) | read_u32(p + 4);
}

cbor_error_t cbor_peek_type(const cbor_context_t *ctx, cbor_major_type_t *type) {
    if (ctx->offset >= ctx->size) {
        return CBOR_ERR_END_OF_BUFFER;
    }
    *type = (cbor_major_type_t)(ctx->buffer[ctx->offset] >> 5);
    return CBOR_ERR_NONE;
}

#include <stdio.h>

cbor_error_t cbor_skip_item(cbor_context_t *ctx) {
    cbor_value_t val;
    cbor_error_t err = cbor_decode_next(ctx, &val);
    if (err != CBOR_ERR_NONE) return err;

    // printf("DEBUG: SKIP item at %zu: type=%d, val=%llu, new_offset=%zu\n", start, val.type, (unsigned long long)val.val, ctx->offset);

    if (val.type == CBOR_TYPE_ARRAY) {
        for (uint64_t i = 0; i < val.val; i++) {
            err = cbor_skip_item(ctx);
            if (err != CBOR_ERR_NONE) return err;
        }
    } else if (val.type == CBOR_TYPE_MAP) {
        for (uint64_t i = 0; i < val.val * 2; i++) {
            err = cbor_skip_item(ctx);
            if (err != CBOR_ERR_NONE) return err;
        }
    } else if (val.type == CBOR_TYPE_TAG) {
        err = cbor_skip_item(ctx);
        if (err != CBOR_ERR_NONE) return err;
    }
    return CBOR_ERR_NONE;
}

cbor_error_t cbor_decode_next(cbor_context_t *ctx, cbor_value_t *value) {
    if (ctx->offset >= ctx->size) {
        return CBOR_ERR_END_OF_BUFFER;
    }

    size_t start_offset = ctx->offset;
    uint8_t head = ctx->buffer[ctx->offset++];
    cbor_major_type_t type = (cbor_major_type_t)(head >> 5);
    uint8_t add_info = head & 0x1F;

    uint64_t val = 0;

    // Determine the value/length based on the additional information
    if (add_info < 24) {
        val = add_info;
    } else if (add_info == 24) { // 1-byte value
        if (ctx->offset + 1 > ctx->size) return CBOR_ERR_END_OF_BUFFER;
        val = ctx->buffer[ctx->offset++];
    } else if (add_info == 25) { // 2-byte value
        if (ctx->offset + 2 > ctx->size) return CBOR_ERR_END_OF_BUFFER;
        val = read_u16(&ctx->buffer[ctx->offset]);
        ctx->offset += 2;
    } else if (add_info == 26) { // 4-byte value
        if (ctx->offset + 4 > ctx->size) return CBOR_ERR_END_OF_BUFFER;
        val = read_u32(&ctx->buffer[ctx->offset]);
        ctx->offset += 4;
    } else if (add_info == 27) { // 8-byte value
        if (ctx->offset + 8 > ctx->size) return CBOR_ERR_END_OF_BUFFER;
        val = read_u64(&ctx->buffer[ctx->offset]);
        ctx->offset += 8;
    } else if (add_info == 31) { // Indefinite length (not supported for now)
        return CBOR_ERR_UNSUPPORTED;
    } else {
        return CBOR_ERR_MALFORMED;
    }

    value->type = type;
    value->val = val;
    value->header_size = ctx->offset - start_offset;
    value->ptr = &ctx->buffer[ctx->offset]; // Default to start of content

    // For strings, skip the offset forward
    if (type == CBOR_TYPE_BSTR || type == CBOR_TYPE_TSTR) {
        if (ctx->offset + val > ctx->size) {
            return CBOR_ERR_END_OF_BUFFER;
        }
        ctx->offset += (size_t)val;
    }

    return CBOR_ERR_NONE;
}
