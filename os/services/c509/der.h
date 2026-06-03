/**
 * @file der.h
 * @brief Lightweight DER (Distinguished Encoding Rules) encoder for C509 to X.509 conversion.
 */

#ifndef C509_DER_H
#define C509_DER_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief ASN.1 Universal Tags.
 */
#define DER_TAG_BOOLEAN          0x01
#define DER_TAG_INTEGER          0x02
#define DER_TAG_BIT_STRING       0x03
#define DER_TAG_OCTET_STRING     0x04
#define DER_TAG_NULL             0x05
#define DER_TAG_OID              0x06
#define DER_TAG_UTF8_STRING      0x0C
#define DER_TAG_PRINTABLE_STRING 0x13
#define DER_TAG_IA5_STRING       0x16
#define DER_TAG_UTC_TIME         0x17
#define DER_TAG_GEN_TIME         0x18
#define DER_TAG_SEQUENCE         0x30
#define DER_TAG_SET              0x31

/**
 * @brief Returns the byte size of a DER tag+length header for a given content length.
 */
size_t der_get_tag_len_size(uint8_t tag, size_t len);

/**
 * @brief Writes a DER tag and length to the buffer.
 * 
 * @param buffer Buffer to write to.
 * @param size Total size of the buffer.
 * @param offset Current offset in the buffer. Updated on success.
 * @param tag ASN.1 tag to write.
 * @param len Length of the content to follow.
 * @return 0 on success, -1 on buffer overflow.
 */
int der_write_tag_len(uint8_t *buffer, size_t size, size_t *offset, uint8_t tag, size_t len);

/**
 * @brief Writes a DER integer to the buffer.
 * 
 * @param buffer Buffer to write to.
 * @param size Total size of the buffer.
 * @param offset Current offset in the buffer. Updated on success.
 * @param val Pointer to the integer bytes (big-endian).
 * @param val_len Length of the integer bytes.
 * @return 0 on success, -1 on failure.
 */
int der_write_integer(uint8_t *buffer, size_t size, size_t *offset, const uint8_t *val, size_t val_len);

#endif // C509_DER_H
