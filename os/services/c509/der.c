/**
 * @file der.c
 * @brief Lightweight DER encoder implementation.
 */

#include "c509/der.h"
#include <string.h>

int der_write_tag_len(uint8_t *buffer, size_t size, size_t *offset, uint8_t tag, size_t len) {
    size_t off = *offset;

    if (off >= size) return -1;
    buffer[off++] = tag;

    if (len < 128) {
        if (off >= size) return -1;
        buffer[off++] = (uint8_t)len;
    } else {
        // Multi-byte length encoding
        uint8_t len_bytes[8];
        int num_bytes = 0;
        size_t temp_len = len;
        while (temp_len > 0) {
            len_bytes[num_bytes++] = (uint8_t)(temp_len & 0xFF);
            temp_len >>= 8;
        }
        if (off + num_bytes >= size) return -1;
        buffer[off++] = (uint8_t)(0x80 | num_bytes);
        for (int i = num_bytes - 1; i >= 0; i--) {
            buffer[off++] = len_bytes[i];
        }
    }

    *offset = off;
    return 0;
}

int der_write_integer(uint8_t *buffer, size_t size, size_t *offset, const uint8_t *val, size_t val_len) {
    if (val_len == 0) return -1;

    // Determine if we need an extra padding byte (if high bit is set)
    // to ensure the DER integer remains positive.
    int padding = (val[0] & 0x80) ? 1 : 0;
    size_t total_len = val_len + padding;

    if (der_write_tag_len(buffer, size, offset, DER_TAG_INTEGER, total_len) != 0) {
        return -1;
    }

    size_t off = *offset;
    if (off + total_len > size) return -1;

    if (padding) {
        buffer[off++] = 0x00;
    }
    memcpy(&buffer[off], val, val_len);
    *offset = off + val_len;

    return 0;
}
