/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   On-device C509 CRL parsing + revocation lookup (draft-liao-cose-c509-
 *   revocation, "C509 CRL"). Parses the flat 11-element `C509CRL` CBOR array
 *   and answers "is this serial revoked?" via a binary search over the
 *   fixed-width `revokedCerts` entries — the draft's exact, binary-searchable
 *   CRL, as opposed to a lossy Bloom-filter CCRL.
 *
 *   Self-contained: stdint/stddef only, no ASN.1/CBOR library and no
 *   os/services/c509/cbor.h dependency, so it links into an EDHOC/OSCORE/DTLS
 *   client without the os/lib/cbor.h `cbor_major_type_t` collision — same
 *   rationale as c509-chain.h/.c, c509-csr-*.h/.c and x509-csr-parse.h/.c.
 *
 *   v1 scope: parses the single per-issuer group whose issuer is `null` (i.e.
 *   the CRL's own `authoritySubject`), which covers the direct and delta CRL
 *   examples. Indirect multi-issuer CRLs (more than one group) are parsed for
 *   the first group only; \ref c509_crl_group_count reports how many groups
 *   are present. Signature verification is a separate concern (see
 *   c509_csr_verify_pop() / the ECDSA path) — this module is the list codec
 *   + lookup.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CRL_H
#define C509_CRL_H

#include <stdint.h>
#include <stddef.h>

/** Parsed view of one per-issuer revoked-cert group (points into the CRL bytes). */
typedef struct {
  const uint8_t *revoked;   /**< first byte of the `revokedCerts` fixed-width entries, or NULL */
  size_t revoked_len;       /**< total length of the entries region in bytes */
  uint32_t serial_len;      /**< `serialNumberLength` */
  uint32_t date_len;        /**< `dateLength` */
  uint32_t entry_len;       /**< bytes per entry = serial_len + date_len + (reason ? 1 : 0) */
  uint32_t n_entries;       /**< revoked_len / entry_len */
  uint8_t sorted;           /**< control flag bit 0: entries sorted ascending by serial */
  uint8_t has_reason;       /**< control flag bit 1: each entry carries a trailing reason byte */
  uint64_t base_date;       /**< reference time; entry dates are offsets from it */
  uint32_t group_count;     /**< number of per-issuer groups in revokedCertsList */
} c509_crl_t;

/**
 * \brief Parse a C509 CRL and locate the first per-issuer revoked-cert group.
 *
 * \param buf  C509CRL bytes (the full 11-element CBOR array).
 * \param len  length of \p buf.
 * \param crl  out: parsed control parameters + a pointer to the entries.
 * \return 0 on success (including the "no revocations" case, where
 *         \p crl->revoked is NULL and n_entries is 0), -1 on malformed input.
 */
int c509_crl_parse(const uint8_t *buf, size_t len, c509_crl_t *crl);

/**
 * \brief Test whether a certificate serial is revoked, per a parsed CRL group.
 *
 * Left-pads \p serial to `serial_len` and, if the group is sorted, binary-
 * searches the fixed-width entries (else linear-scans).
 *
 * \param crl         a group from c509_crl_parse().
 * \param serial      big-endian serial number bytes.
 * \param serial_len  length of \p serial (must be <= crl->serial_len).
 * \return 1 if revoked, 0 if not revoked, -1 on error (serial too wide, etc.).
 */
int c509_crl_is_revoked(const c509_crl_t *crl,
                        const uint8_t *serial, size_t serial_len);

/**
 * \brief Read the reason byte for a serial, if present (has_reason set).
 * \return the reason code (>=0) if the serial is revoked and reasons are
 *         carried, -1 if not revoked or no reason byte.
 */
int c509_crl_reason(const c509_crl_t *crl,
                    const uint8_t *serial, size_t serial_len);

/**
 * \brief Extract a C509 certificate's serialNumber (flat-array element 1, a
 *        byte string). Points into \p cert; nothing is copied.
 * \return 0 on success, -1 on malformed input.
 */
int c509_cert_serial(const uint8_t *cert, size_t cert_len,
                     const uint8_t **serial, size_t *serial_len);

/**
 * \brief Is a C509 certificate revoked according to a parsed CRL?
 *
 * Extracts the cert's serialNumber and looks it up (\ref c509_crl_is_revoked).
 * The caller is responsible for verifying the CRL's signature and scope (issuer,
 * thisUpdate/nextUpdate) first; this only answers the list-membership question.
 *
 * \return 1 revoked, 0 not revoked, -1 on error.
 */
int c509_crl_is_cert_revoked(const uint8_t *cert, size_t cert_len,
                             const c509_crl_t *crl);

#endif /* C509_CRL_H */
