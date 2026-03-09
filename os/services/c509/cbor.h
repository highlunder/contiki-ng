/**
 * @file cbor.h
 * @brief Low-footprint, zero-copy CBOR decoder for C509.
 * 
 * This decoder is designed for resource-constrained environments. 
 * It avoids dynamic memory allocation and minimizes memory copying 
 * by providing pointers directly into the source buffer.
 */

#ifndef C509_CBOR_H
#define C509_CBOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief CBOR Major Types (as defined in RFC 8949).
 */
typedef enum {
    CBOR_TYPE_UINT = 0,      ///< Unsigned integer
    CBOR_TYPE_NINT = 1,      ///< Negative integer
    CBOR_TYPE_BSTR = 2,      ///< Byte string
    CBOR_TYPE_TSTR = 3,      ///< Text string
    CBOR_TYPE_ARRAY = 4,     ///< Array of data items
    CBOR_TYPE_MAP = 5,       ///< Map of pairs of data items
    CBOR_TYPE_TAG = 6,       ///< Semantic tag
    CBOR_TYPE_SIMPLE = 7     ///< Floating-point numbers and simple control types
} cbor_major_type_t;

/**
 * @brief Error codes for CBOR decoding.
 */
typedef enum {
    CBOR_ERR_NONE = 0,
    CBOR_ERR_END_OF_BUFFER,  ///< Attempted to read past the end of the buffer
    CBOR_ERR_MALFORMED,      ///< CBOR structure is invalid
    CBOR_ERR_UNSUPPORTED     ///< Encountered a feature not supported (e.g. indefinite length)
} cbor_error_t;

/**
 * @brief Represents a decoded CBOR data item.
 * 
 * For strings (BSTR, TSTR), 'ptr' points to the start of the string 
 * in the source buffer and 'val' contains the length.
 * For integers, 'val' contains the value.
 * For arrays/maps, 'val' contains the number of elements/pairs.
 */
typedef struct {
    cbor_major_type_t type;
    uint64_t val;            ///< Integer value or length of string/container
    const uint8_t *ptr;      ///< Pointer to data (for strings/containers)
    size_t header_size;      ///< Size of the CBOR header for this item
} cbor_value_t;

/**
 * @brief Context for the CBOR decoder.
 */
typedef struct {
    const uint8_t *buffer;   ///< Start of the CBOR buffer
    size_t size;             ///< Total size of the buffer
    size_t offset;           ///< Current read position
} cbor_context_t;

/**
 * @brief Initializes a CBOR decoding context.
 * 
 * @param ctx Context to initialize.
 * @param buffer Source CBOR data.
 * @param size Size of the source data.
 */
void cbor_init(cbor_context_t *ctx, const uint8_t *buffer, size_t size);

/**
 * @brief Decodes the next data item from the context.
 * 
 * @param ctx The decoding context.
 * @param value Pointer to a struct where the result will be stored.
 * @return CBOR_ERR_NONE on success, or an error code.
 */
cbor_error_t cbor_decode_next(cbor_context_t *ctx, cbor_value_t *value);

/**
 * @brief Skips the next data item entirely (including container children).
 * 
 * @param ctx The decoding context.
 * @return CBOR_ERR_NONE on success, or an error code.
 */
cbor_error_t cbor_skip_item(cbor_context_t *ctx);

/**
 * @brief Peeks at the major type of the next item without advancing the offset.
 * 
 * @param ctx The decoding context.
 * @param type Pointer to store the peeked type.
 * @return CBOR_ERR_NONE on success, or an error code.
 */
cbor_error_t cbor_peek_type(const cbor_context_t *ctx, cbor_major_type_t *type);

#endif // C509_CBOR_H
