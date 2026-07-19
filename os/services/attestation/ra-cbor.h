/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Deterministic CBOR write helpers for the Remote-Attestation-over-EDHOC
 *   service (draft-ietf-lake-ra). Mirrors os/services/c509/c509-cbor-writer.h
 *   but as a proper compilation unit so the attestation module is self-contained;
 *   reading uses os/services/c509/c509-cbor-lite.c (c509_cbor_head).
 *
 *   All writers append to \p buf (capacity \p sz) at \p *off, advance \p *off,
 *   and return 0 on success or -1 if there is not enough space. Output is
 *   definite-length, shortest-form (RFC 8949 §4.2.1), matching the Rust
 *   reference impl (lake-ra-impl) and the draft's Appendix A byte-for-byte.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_CBOR_H
#define RA_CBOR_H

#include <stdint.h>
#include <stddef.h>

/* CBOR major types (high 3 bits of the initial byte). */
#define RA_CBOR_UINT   0
#define RA_CBOR_NINT   1
#define RA_CBOR_BSTR   2
#define RA_CBOR_TSTR   3
#define RA_CBOR_ARRAY  4
#define RA_CBOR_MAP    5
#define RA_CBOR_SIMPLE 7

/** Write a CBOR head for major type \p major (0..7) with argument \p arg. */
int ra_cbor_head(uint8_t *buf, size_t sz, size_t *off, uint8_t major, uint64_t arg);
/** Unsigned integer (major 0). */
int ra_cbor_uint(uint8_t *buf, size_t sz, size_t *off, uint64_t v);
/** Signed integer (major 0 for >=0, major 1 for <0). */
int ra_cbor_int(uint8_t *buf, size_t sz, size_t *off, int64_t v);
/** Byte string (major 2): head + bytes. */
int ra_cbor_bstr(uint8_t *buf, size_t sz, size_t *off, const uint8_t *b, size_t len);
/** Text string (major 3): head + bytes. */
int ra_cbor_tstr(uint8_t *buf, size_t sz, size_t *off, const char *s, size_t len);
/** Array head (major 4) for \p n elements. */
int ra_cbor_array(uint8_t *buf, size_t sz, size_t *off, uint64_t n);
/** Map head (major 5) for \p n pairs. */
int ra_cbor_map(uint8_t *buf, size_t sz, size_t *off, uint64_t n);
/** Tag (major 6). */
int ra_cbor_tag(uint8_t *buf, size_t sz, size_t *off, uint64_t tag);
/** Splice pre-encoded CBOR bytes in verbatim. */
int ra_cbor_raw(uint8_t *buf, size_t sz, size_t *off, const uint8_t *b, size_t len);

/* --- reader (vendored from os/services/c509/c509-cbor-lite; keeps this module
 *     self-contained, i.e. no mbedTLS-dependent c509 module needed) --- */

/**
 * \brief Read one CBOR item head at \p p: \p major type, \p arg argument, and
 *        \p body (just past the head). \return 0 on success, -1 on truncation /
 *        unsupported (indefinite) encoding.
 */
int ra_cbor_read_head(const uint8_t *p, const uint8_t *end,
                      uint8_t *major, uint64_t *arg, const uint8_t **body);

/** \brief Advance \p *pp past exactly one complete CBOR item (recursing into
 *         arrays/maps). \return 0 on success, -1 on malformed input. */
int ra_cbor_read_skip(const uint8_t **pp, const uint8_t *end);

#endif /* RA_CBOR_H */
