/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 */

/**
 * \file
 *   Compiles MbedTLS's library/ecdh.c under a distinct object name.
 *
 *   os/net/security/edhoc/ecdh.c (EDHOC's ecdh_generate_ikm()) and
 *   os/net/security/mbedtls/library/ecdh.c (mbedtls_ecdh_init/free/...)
 *   share the basename "ecdh.c". When both os/net/security/edhoc and the
 *   MbedTLS library sources are part of the same build (EDHOC app pulling
 *   in MbedTLS via MAKE_WITH_DTLS for ed25519_verify's mbedtls_sha512),
 *   only one "ecdh.o" can exist and the EDHOC module's ecdh.c wins,
 *   leaving mbedtls_ecdh_init/free undefined. Including the MbedTLS source
 *   here compiles it to "mbedtls-ecdh-wrapper.o" instead.
 *
 *   This file lives in its own subdirectory (not directly in
 *   os/services/c509/) so that Makefile.include's MODULES_SOURCES wildcard
 *   (a non-recursive "$(d)/wildcard-star.c" glob) does not pull it into
 *   builds that add os/services/c509 as a MODULE but already compile
 *   MbedTLS's real ecdh.c (e.g. DTLS+C509 apps) -- that would cause a
 *   "multiple definition of mbedtls_ecdh_*" link error. Apps that need this
 *   wrapper (the ed25519 EDHOC c5t apps) pull it in explicitly via vpath.
 */
#include "../../../net/security/mbedtls/library/ecdh.c"
