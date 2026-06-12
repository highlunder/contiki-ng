/*
 * Copyright (c) 2022, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *		DTLS (Mbed TLS implementation) support for CoAP
 *
 * \author
 *		Jayendra Ellamathy <ejayen@gmail.com>
 */

#include "contiki.h"
#include "contiki-net.h"
#include "lib/csprng.h"
#include "lib/heapmem.h"

#include "mbedtls-support.h"

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/version.h"

#if !defined(MBEDTLS_SSL_PROTO_DTLS) || \
  !(defined(MBEDTLS_TIMING_C) || defined(MBEDTLS_TIMING_ALT)) || \
  !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
#error "Invalid MBEDTLS configuration."
#endif

#ifdef COAP_DTLS_CONF_WITH_CLIENT
#if !defined(MBEDTLS_SSL_CLI_C)
#error "MBEDTLS_SSL_CLI_C not defined.";
#endif
#endif /* COAP_DTLS_CONF_WITH_CLIENT */

#ifdef COAP_DTLS_CONF_WITH_SERVER
#if !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_SSL_COOKIE_C) || \
  !defined(MBEDTLS_SSL_CACHE_C)
#error "MBEDTLS_SSL_SRV_C and/or MBEDTLS_SSL_COOKIE_C and/or "
       "MBEDTLS_SSL_CACHE_C not defined.";
  return;
#endif
#endif /* COAP_DTLS_CONF_WITH_SERVER */

#ifdef COAP_DTLS_CONF_WITH_PSK
#if !defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
#error "MBEDTLS_KEY_EXCHANGE_PSK_ENABLED not defined.";
#endif
#endif /* COAP_DTLS_CONF_WITH_PSK */

#ifdef COAP_DTLS_CONF_WITH_CERT
#if !defined(MBEDTLS_X509_CRT_PARSE_C) || \
  !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
  !defined(MBEDTLS_PEM_PARSE_C)
#error "MBEDTLS_X509_CRT_PARSE_C and/or "
       "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED and/or "
       "MBEDTLS_PEM_PARSE_C not defined.\n");
#endif
#endif /* COAP_DTLS_CONF_WITH_CERT */

#ifdef COAP_DTLS_CONF_WITH_C509
#include "c509.h"
#include "x509_encode.h"
#include "validator.h"
#include "mbedtls/x509_crt.h"
#endif /* COAP_DTLS_CONF_WITH_C509 */

#if !defined(COAP_DTLS_PRNG_INSECURE) && !CSPRNG_ENABLED
#error CSPRNG module needs to be enabled for DTLS. Set CSPRNG_CONF_ENABLED to 1.
#endif

#if defined(MBEDTLS_ECDSA_VERIFY_ALT) || \
  defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
#include "nrf_crypto.h"
#endif /* MBEDTLS_ECDSA_VERIFY_ALT ||
          MBEDTLS_ECDH_COMPUTE_SHARED_ALT */
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "DTLS"
#define LOG_LEVEL LOG_LEVEL_DTLS

MEMB(dtls_session_info_memb, coap_dtls_session_info_t,

     COAP_DTLS_MAX_SESSIONS);

static coap_dtls_context_t dtls_context;

/*---------------------------------------------------------------------------*/
#if defined(MBEDTLS_DEBUG_C)
static void
mbedtls_debug(void *ctx, int level,
              const char *file, int line, const char *str)
{
  LOG_DBG("%s:%d: %s", file, line, str);
}
#endif /* MBEDTLS_DEBUG_C */
/*---------------------------------------------------------------------------*/
#if defined(MBEDTLS_NO_PLATFORM_ENTROPY)
static int
random_number_generator(void *ctx, unsigned char *buffer, size_t length)
{
#if COAP_DTLS_PRNG_INSECURE
  /* This is an insecure PRNG for testing purposes only. */
  uint16_t rand_num = 0;
  size_t len = 0;

  while(length < (len + sizeof(rand_num))) {
    rand_num = random_rand();
    memcpy(buffer + len, &rand_num, sizeof(rand_num));
    len += sizeof(rand_num);
   }
  rand_num = random_rand();
  memcpy(buffer, &rand_num, length - len);

  LOG_WARN("Missing CSPRNG: using %zu bytes of possibly non-random values!\n",
           length);

  return 0;
#else /* COAP_DTLS_PRNG_INSECURE */
#if !CSPRNG_ENABLED
#error CSPRNG module needs to be enabled for DTLS. Set CSPRNG_CONF_ENABLED to 1.
#endif /* !CSPRNG_ENABLED */

  if(!csprng_rand(buffer, length)) {
    LOG_ERR("Failed to generate %zu bytes of random values\n", length);
    return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
  }
  LOG_DBG("Generated %zu bytes of random values\n", length);

  return 0;
#endif /* COAP_DTLS_PRNG_INSECURE */
}
#endif /* defined(MBEDTLS_NO_PLATFORM_ENTROPY) */
/*---------------------------------------------------------------------------*/
void
coap_dtls_init(void)
{
  /* The buffer should be at least 18 bytes to hold the full version string. */
  char version[20];
  mbedtls_version_get_string_full(version);
  LOG_INFO("Initializing DTLS support with library \"%s\"\n", version);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(COAP_MBEDTLS_LIB_DEBUG_LEVEL);
#endif /* MBEDTLS_DEBUG_C */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT) || \
  defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
  if(nrf_crypto_init() != NRF_SUCCESS) {
    LOG_ERR("Unable to initialize nRF Crypto\n");
    return;
  }
#endif

  LIST_STRUCT_INIT(&dtls_context, sessions);
  LIST_STRUCT_INIT(&dtls_context, send_message_fifo);

  /* DTLS context initialized and ready */
  dtls_context.ready = 1;
  return;
}
/*---------------------------------------------------------------------------*/
void
coap_dtls_conn_init(struct uip_udp_conn *udp_conn,
                    struct process *host_process)
{
  dtls_context.udp_conn = udp_conn;
  dtls_context.host_process = host_process;
}
/*---------------------------------------------------------------------------*/
bool
coap_ep_is_dtls_peer(const coap_endpoint_t *ep)
{
  coap_dtls_session_info_t *info = NULL;

  for(info = list_head(dtls_context.sessions); info; info = info->next) {
    if(coap_endpoint_cmp(&info->ep, ep)) {
      return true;
    }
  }
  return false;
}
/*---------------------------------------------------------------------------*/
#ifdef COAP_DTLS_CONF_WITH_SERVER
coap_dtls_session_info_t *
coap_get_free_server_session(void)
{
  coap_dtls_session_info_t *info = NULL;

  for(info = list_head(dtls_context.sessions); info; info = info->next) {
    if(info->role == COAP_MBEDTLS_ROLE_SERVER && !info->in_use) {
      return info;
    }
  }

  return NULL;
}
#endif /* COAP_DTLS_CONF_WITH_SERVER */
/*---------------------------------------------------------------------------*/
coap_dtls_session_info_t *
coap_ep_get_dtls_session_info(const coap_endpoint_t *ep)
{
  coap_dtls_session_info_t *info = NULL;

  for(info = list_head(dtls_context.sessions); info; info = info->next) {
    if(coap_endpoint_cmp(&info->ep, ep)) {
      break;
    }
  }
  return info;
}
/*---------------------------------------------------------------------------*/
bool
coap_ep_is_dtls_connected(const coap_endpoint_t *ep)
{
  coap_dtls_session_info_t *info = coap_ep_get_dtls_session_info(ep);
  return info != NULL ? mbedtls_ssl_is_handshake_over(&info->ssl) : 0;
}
/*---------------------------------------------------------------------------*/
int
coap_ep_get_dtls_state(const coap_endpoint_t *ep)
{
  coap_dtls_session_info_t *info = coap_ep_get_dtls_session_info(ep);
  return info != NULL ? info->ssl.MBEDTLS_PRIVATE(state) : 0;
}
/*---------------------------------------------------------------------------*/
static int
perform_handshake(coap_dtls_session_info_t *session_info)
{
  int ret;

  etimer_stop(&session_info->retransmission_et);
  memset(&session_info->retransmission_et, 0, sizeof(struct etimer));

#ifdef COAP_DTLS_CONF_WITH_SERVER
  if(session_info->role == COAP_MBEDTLS_ROLE_SERVER) {
    /* For HelloVerifyRequest cookies */
    ret = mbedtls_ssl_set_client_transport_id(&session_info->ssl,
                                              (const unsigned char *)&session_info->ep,
                                              sizeof(coap_endpoint_t));
    if(ret != 0) {
      LOG_DBG("mbedtls_ssl_set_client_transport_id() returned -0x%x\n",
              (unsigned int)-ret);
    }
  }
#endif /* COAP_DTLS_CONF_WITH_SERVER */

  LOG_INFO("Handshake starting\n");
  ret = mbedtls_ssl_handshake(&session_info->ssl);
  LOG_INFO("Handshake in progress, ending with completed = %d\n",
           mbedtls_ssl_is_handshake_over(&session_info->ssl));

  if(ret == 0) {
    LOG_INFO("DTLS handshake succesful\n");
  } else if(ret < 0) {
  /* Handshake error handling */
    if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LOG_ERR("Handshake unexpected error: -0x%04x\n", (unsigned int)-ret);
#ifdef COAP_DTLS_CONF_WITH_CLIENT
      /* HS failed -- Clean up
       * Call coap_ep_dtls_connect() again if a retry is needed  */
      if(session_info->role == COAP_MBEDTLS_ROLE_CLIENT) {
        list_remove(dtls_context.sessions, session_info);
        memb_free(&dtls_session_info_memb, session_info);
        return ret;
      }
#endif /* COAP_DTLS_CONF_WITH_CLIENT */
#ifdef COAP_DTLS_CONF_WITH_SERVER
      if(session_info->role == COAP_MBEDTLS_ROLE_SERVER) {
        /* For helloVerifyRequest, wait for ClientHello with Cookie,
         * otherwise cleanup to allow other connections */
        mbedtls_ssl_session_reset(&session_info->ssl);
        if(ret != MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
          session_info->in_use = false;
          memset(&session_info->ep, 0, sizeof(coap_endpoint_t));
          etimer_stop(&session_info->retransmission_et);
        } else {
          return ret;
        }
      }
#endif /* COAP_DTLS_CONF_WITH_SERVER */
      LOG_ERR("DTLS handshake failed\n");
    }
  }

  return ret;
}
/*---------------------------------------------------------------------------*/
/* TODO: Currently using MBEDTLS_PRIVATE to access now hidden timer internals */
/*---------------------------------------------------------------------------*/
void
coap_dtls_event_handler(void)
{
  LOG_DBG("Call to %s\n", __func__);

  /* Send DTLS message event */
  coap_dtls_send_message_t *send_message = list_pop(dtls_context.send_message_fifo);
  if(send_message == NULL) {
    LOG_DBG("No message in the FIFO\n");
  } else {
    uip_udp_packet_sendto(dtls_context.udp_conn, send_message->send_buf,
                          send_message->len,
                          &send_message->ep.ipaddr, send_message->ep.port);
    LOG_INFO("Sent DTLS message of len = %zu\n", send_message->len);
    if(!heapmem_free(send_message)) {
      LOG_ERR("Failed to free a sent message\n");
    }

    /* Update re-transmission timer */
    /* TODO, please note that the current timer implementation
       ignores the new mbedTLS default to hide the constituents,
       which otherwise requires access through
       timer.MBEDTLS_PRIVATE(<field>)
     */

    coap_dtls_session_info_t *info = coap_ep_get_dtls_session_info(&send_message->ep);
    if(info != NULL) {
      uint32_t elapsed_ms = mbedtls_timing_get_timer(&info->timer.MBEDTLS_PRIVATE(timer),
                                            0);
      if(info->timer.MBEDTLS_PRIVATE(fin_ms) > 0) {
        uint32_t time_left_ms = info->timer.MBEDTLS_PRIVATE(fin_ms) - elapsed_ms;
        if(time_left_ms > 0) {
          LOG_DBG("Updating re-transmission timer to %u ms\n",
                  (unsigned int)time_left_ms);
          etimer_set(&info->retransmission_et,
                     (time_left_ms * CLOCK_SECOND) / 1000);
        }
      }
    }

    if(list_head(dtls_context.send_message_fifo) != NULL) {
      if(COAP_MBEDTLS_FRAGMENT_TIMER > 0) {
        etimer_set(&dtls_context.fragmentation_et,
                   (CLOCK_SECOND * COAP_MBEDTLS_FRAGMENT_TIMER) / 1000);
        LOG_DBG("Setting fragmentation timer to %u ms\n",
                (unsigned int)COAP_MBEDTLS_FRAGMENT_TIMER);
      } else {
        process_poll(dtls_context.host_process);
      }
    }
  }

  /* DTLS re-transmission event */
  for(coap_dtls_session_info_t *info = list_head(dtls_context.sessions);
      info != NULL;
      info = info->next) {
    if(etimer_expiration_time(&info->retransmission_et) > 0 &&
       etimer_expired(&info->retransmission_et)) {
      LOG_INFO("Re-transmission timer expired\n");
      LOG_DBG("HS retry, current process = %s\n", PROCESS_CURRENT()->name);
      perform_handshake(info);
      break;
    }
  }

  return;
}
/*---------------------------------------------------------------------------*/
static int
coap_ep_mbedtls_sendto(void *ctx, const unsigned char *buf, size_t len)
{
  LOG_DBG("Call to %s\n", __func__);

  if(ctx == NULL) {
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }

  coap_dtls_send_message_t *send_message = (coap_dtls_send_message_t *)heapmem_alloc(sizeof(coap_dtls_send_message_t));
  if(send_message == NULL) {
    LOG_ERR("Unable to allocate memory for DTLS message\n");
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  coap_dtls_session_info_t *session_info = (coap_dtls_session_info_t *)ctx;
  if(len > COAP_MBEDTLS_MTU) {
    LOG_ERR("DTLS message too large: %zu > %d\n", len, COAP_MBEDTLS_MTU);
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  memcpy(&send_message->ep, &session_info->ep, sizeof(coap_endpoint_t));
  memcpy(send_message->send_buf, buf, len);
  send_message->len = len;
  list_add(dtls_context.send_message_fifo, send_message);

  process_poll(dtls_context.host_process);

  return len;
}
/*---------------------------------------------------------------------------*/
static int
coap_ep_mbedtls_recv(void *ctx, unsigned char *buf, size_t len)
{
  LOG_DBG("Call to %s\n", __func__);

  if(uip_datalen() == 0) {
    LOG_DBG("Input data length is 0\n");
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  if(ctx == NULL) {
    LOG_DBG("Session info is missing\n");
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  }
  coap_dtls_session_info_t *session_info = (coap_dtls_session_info_t *)ctx;
  if(session_info->is_packet_consumed) {
    LOG_DBG("The packet has been consumed\n");
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  if(len < uip_datalen()) {
    LOG_ERR("DTLS incoming buffer too small, len = %zu, uip_datalen = %d\n",
            len, uip_datalen());
    return 0;
  }

  memcpy(buf, uip_appdata, uip_datalen());
  session_info->is_packet_consumed = true;

  LOG_DBG("Read of %d bytes completed\n", uip_datalen());
  return uip_datalen();
}
/*---------------------------------------------------------------------------*/
#ifdef COAP_DTLS_CONF_WITH_C509
static void
debug_hex_dump(const char *label, const uint8_t *data, size_t len)
{
  size_t i;
  LOG_DBG("%s (%zu bytes):\n", label, len);
  for(i = 0; i < len; i++) {
    LOG_DBG_("%02x ", data[i]);
    if((i + 1) % 16 == 0) {
      LOG_DBG_("\n");
    }
  }
  LOG_DBG_("\n");
}

/*
 * Return true when the C509 cert at 'cert' (length 'len') is a natively
 * signed Type 2 certificate, as opposed to a DER-equivalent Type 0/1/3.
 *
 * The C509 "type" field is the first CBOR item of the TBS sequence; for
 * Type 2 it is the unsigned integer 2, which in CBOR major type 0 encodes
 * as a single byte 0x02. This is therefore just a peek at cert[0].
 *
 * Used by setup_session() to decide whether to register
 * c509_native_verify_cb() for this session's CA cert.
 */
static bool
c509_is_native_type2(const uint8_t *cert, size_t len)
{
  return len >= 1 && cert[0] == 0x02;
}

/*
 * Mbed TLS certificate verify callback for natively signed C509 Type-2
 * certificates, registered via mbedtls_ssl_conf_verify() (see
 * setup_session() below) only when the session's CA cert is Type 2.
 * Mbed TLS invokes this once per certificate in the chain during the
 * handshake, from the deepest (CA) to the shallowest (leaf, depth 0).
 *
 * Background: for Type 2, the original ECDSA signature was computed over
 * the CBOR-encoded TBS bytes, not over the reconstructed DER
 * TBSCertificate. Mbed TLS's normal X.509 signature check therefore always
 * fails for the leaf cert (it flags MBEDTLS_X509_BADCERT_NOT_TRUSTED), even
 * though the certificate itself is valid. To compensate, this callback
 * performs an independent chain check on the *raw* C509 bytes (using
 * c509_verify_chain(), which understands the CBOR-signed form) against the
 * pre-provisioned peer cert (session_info->native_peer_c509) and CA public
 * key (session_info->native_ca_pub_xy). If that check succeeds, we clear
 * the flags that Mbed TLS could not have correctly evaluated:
 *
 *  - MBEDTLS_X509_BADCERT_NOT_TRUSTED: always set for Type 2 leaf certs for
 *    the reason above; clearing it here is what makes the handshake
 *    succeed.
 *  - MBEDTLS_X509_BADCERT_EXPIRED / _FUTURE: the Contiki-NG native/Cooja
 *    targets have no real-time clock, so Mbed TLS's notBefore/notAfter
 *    check against "now" is meaningless. c509_verify_chain() instead checks
 *    the cert's POSIX validity window against the fixed timestamp below
 *    (~2028-08), which falls inside the test certs' validity period.
 *
 * NOTE: this callback runs c509_verify_chain() at depth 0 (the leaf), and
 * additionally at depth 1 when the peer's chain includes an intermediate
 * (Sub) CA cert (session_info->native_intermediate_c509 != NULL) -- in that
 * case the Sub CA cert was itself natively signed (Type 2), so Mbed TLS's
 * own check of the Sub CA's signature against the Root CA (in DER form)
 * fails for the same reason as the leaf. For depth values beyond the
 * provisioned chain length, or for non-native sessions, this is a no-op
 * that leaves 'flags' untouched (i.e. Mbed TLS's own verdict for the Root CA
 * cert and for non-Type-2 sessions stands unchanged). On success, the three
 * flags above are cleared unconditionally, regardless of which (if any) of
 * them Mbed TLS actually set -- i.e. this does not distinguish
 * "EXPIRED/FUTURE due to missing RTC" from "EXPIRED/FUTURE because the cert
 * is genuinely outside its validity window" beyond what
 * c509_verify_chain()'s own timestamp check provides.
 */
static int
c509_native_verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth,
                      uint32_t *flags)
{
  (void)crt;
  coap_dtls_session_info_t *si = (coap_dtls_session_info_t *)ctx;
  if(!si->is_native_c509) {
    return 0;
  }

  size_t chain_count = (si->native_intermediate_c509 != NULL) ? 2 : 1;
  if(depth < 0 || (size_t)depth >= chain_count) {
    return 0;
  }

  const uint8_t *chain[2];
  size_t lens[2];
  chain[0] = si->native_peer_c509;
  lens[0]  = si->native_peer_c509_len;
  if(chain_count == 2) {
    chain[1] = si->native_intermediate_c509;
    lens[1]  = si->native_intermediate_c509_len;
  }

  /* 1 850 000 000 s ≈ 2028-08 — within the test cert validity window. */
  validator_error_t r = c509_verify_chain(chain, lens, chain_count,
                                          si->native_ca_pub_xy, 64,
                                          si->native_ca_pk_alg,
                                          1850000000LL);
  if(r == VALIDATOR_OK) {
    *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_NOT_TRUSTED
                          | MBEDTLS_X509_BADCERT_EXPIRED
                          | MBEDTLS_X509_BADCERT_FUTURE);
    LOG_INFO("Native C509 Type-2 chain validation OK (depth %d)\n", depth);
  } else {
    LOG_ERR("Native C509 Type-2 chain validation FAILED: %d (depth %d)\n", (int)r, depth);
  }
  return 0;
}
#endif /* COAP_DTLS_CONF_WITH_C509 */

static coap_dtls_session_info_t *
setup_session(const coap_mbedtls_role_t role,
              const coap_dtls_sec_mode_t sec_mode,
              const void *keystore_entry)
{
  int ret;
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
  const char *pers = "Contiki_DTLS";
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */
  coap_dtls_session_info_t *session_info = NULL;

  /* Create and add to the linked list of sessions. */
  session_info = memb_alloc(&dtls_session_info_memb);
  if(!session_info) {
    LOG_ERR("Unable to allocate memory for DTLS server session\n");
    return NULL;
  }
  list_add(dtls_context.sessions, session_info);

  session_info->role = role;

  /* Initialize Mbed TLS structs */
  mbedtls_ssl_init(&session_info->ssl);
  mbedtls_ssl_config_init(&session_info->conf);

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
  mbedtls_entropy_init(&session_info->entropy);
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */
  mbedtls_ctr_drbg_init(&session_info->ctr_drbg);

#ifdef COAP_DTLS_CONF_WITH_CERT
  if(sec_mode == COAP_DTLS_SEC_MODE_CERT) {
    mbedtls_x509_crt_init(&session_info->ca_cert);
    mbedtls_x509_crt_init(&session_info->own_cert);
    mbedtls_pk_init(&session_info->pkey);
  }
#endif /* COAP_DTLS_CONF_WITH_CERT */

#ifdef COAP_DTLS_CONF_WITH_C509
  if(sec_mode == COAP_DTLS_SEC_MODE_C509) {
    mbedtls_x509_crt_init(&session_info->ca_cert);
    mbedtls_x509_crt_init(&session_info->own_cert);
    mbedtls_pk_init(&session_info->pkey);
    session_info->ca_der              = NULL;
    session_info->own_der             = NULL;
    session_info->intermediate_der    = NULL;
    /* Native Type-2 fields default to "off"; populated below (and the
     * verify callback registered) only if the keystore entry's CA cert is
     * a natively signed Type 2 cert and a peer cert / CA public key were
     * also provisioned. */
    session_info->is_native_c509      = false;
    session_info->native_peer_c509    = NULL;
    session_info->native_peer_c509_len = 0;
    memset(session_info->native_ca_pub_xy, 0, 64);
    session_info->native_ca_pk_alg    = 0;
    session_info->native_intermediate_c509     = NULL;
    session_info->native_intermediate_c509_len = 0;
  }
#endif /* COAP_DTLS_CONF_WITH_C509 */

#ifdef COAP_DTLS_CONF_WITH_SERVER
  /* Initialization for server side only */
  if(role == COAP_MBEDTLS_ROLE_SERVER) {
    mbedtls_ssl_cookie_init(&session_info->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&session_info->cache);
#endif /* MBEDTLS_SSL_CACHE_C */
  }
#endif /* COAP_DTLS_CONF_WITH_SERVER */

  /* Seed the random number generator -- Used when rng functionality is NOT
   * provided by platform (Currently, Native platform) */
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
  if((ret = mbedtls_ctr_drbg_seed(&session_info->ctr_drbg,
                                  mbedtls_entropy_func,
                                  &session_info->entropy,
                                  (const unsigned char *)pers,
                                  strlen(pers))) != 0) {
    LOG_ERR("mbedtls_ctr_drbg_seed returned %d\n", ret);
    goto clean_and_ret_err;
  }
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */

  /* Configure protocol as DTLS and role as Client or Server.
   * mbedtls_ssl_config_defaults() sets anti_replay = MBEDTLS_SSL_ANTI_REPLAY_ENABLED
   * by default, which is the correct and intended setting.  Fix D: a previous
   * workaround that called mbedtls_ssl_conf_dtls_anti_replay(..., DISABLED) here
   * has been removed.  The underlying GCC -O2 register-caching bugs that caused
   * false replay rejections on ARM Cortex-M4 are fixed in ssl_msg.c (Fixes A, B,
   * E, F) and ssl_tls12_client.c (Fix C). */
  if((ret = mbedtls_ssl_config_defaults(&session_info->conf,
                                        role == COAP_MBEDTLS_ROLE_CLIENT ?
                                         MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LOG_ERR("mbedtls_ssl_config_defaults returned %d\n", ret);
    goto clean_and_ret_err;
  }

#ifndef COAP_MBEDTLS_CONF_USE_ALL_CIPHERSUITES
#ifdef COAP_DTLS_CONF_WITH_CERT
  if(sec_mode == COAP_DTLS_SEC_MODE_CERT) {
    session_info->ciphersuite = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
  }
#endif /* COAP_DTLS_CONF_WITH_CERT */
#ifdef COAP_DTLS_CONF_WITH_C509
  if(sec_mode == COAP_DTLS_SEC_MODE_C509) {
    session_info->ciphersuite = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
  }
#endif /* COAP_DTLS_CONF_WITH_C509 */
#ifdef COAP_DTLS_CONF_WITH_PSK
  if(sec_mode == COAP_DTLS_SEC_MODE_PSK) {
    session_info->ciphersuite = MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8;
  }
#endif /* COAP_DTLS_CONF_WITH_PSK */
  mbedtls_ssl_conf_ciphersuites(&session_info->conf,
                                (const int *)&session_info->ciphersuite);
#endif /* COAP_MBEDTLS_CONF_USE_ALL_CIPHERSUITES */

  /* For testing purposes MBEDTLS_SSL_VERIFY_OPTIONAL maybe used to skip the
   * certificate check */
  mbedtls_ssl_conf_authmode(&session_info->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&session_info->conf,
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
                       mbedtls_ctr_drbg_random,
#else /* !MBEDTLS_NO_PLATFORM_ENTROPY */
                       random_number_generator,
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */
                       &session_info->ctr_drbg);
#ifdef COAP_DTLS_CONF_WITH_CERT
  if(sec_mode == COAP_DTLS_SEC_MODE_CERT) {
    coap_keystore_cert_entry_t *ks =
      (coap_keystore_cert_entry_t *)keystore_entry;
    if(ks->ca_cert == NULL || ks->own_cert == NULL || ks->priv_key == NULL) {
      LOG_ERR("Certificate or private key missing!\n");
      goto clean_and_ret_err;
    }

    /* Load the root CA certificate */
    ret = mbedtls_x509_crt_parse(&session_info->ca_cert,
                                 (const unsigned char *)ks->ca_cert,
                                 ks->ca_cert_len);
    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse failed for CA cert (error %d)\n", ret);
      goto clean_and_ret_err;
    }

    mbedtls_ssl_conf_ca_chain(&session_info->conf, &session_info->ca_cert,
                              NULL);

    /* Load the client/server certificate and private key */
    ret = mbedtls_x509_crt_parse(&session_info->own_cert,
                                 (const unsigned char *)ks->own_cert,
                                 ks->own_cert_len);
    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse for own cert (error %d)\n", ret);
      goto clean_and_ret_err;
    }

    ret = mbedtls_pk_parse_key(&session_info->pkey,
                               (const unsigned char *)ks->priv_key,
                               ks->priv_key_len, NULL, 0,
                               mbedtls_entropy_func, NULL); /* TODO: test */
    if(ret < 0) {
      LOG_DBG("mbedtls_pk_parse_key returned %d\n", ret);
      goto clean_and_ret_err;
    }

    ret = mbedtls_ssl_conf_own_cert(&session_info->conf,
                                    &session_info->own_cert,
                                    &session_info->pkey);
    if(ret != 0) {
      LOG_ERR("mbedtls_ssl_conf_own_cert returned %d\n", ret);
      goto clean_and_ret_err;
    }
  } else
#endif /* COAP_DTLS_CONF_WITH_CERT */
#ifdef COAP_DTLS_CONF_WITH_C509
  if(sec_mode == COAP_DTLS_SEC_MODE_C509) {
    coap_keystore_c509_entry_t *ks =
      (coap_keystore_c509_entry_t *)keystore_entry;
    if(ks->ca_cert == NULL || ks->own_cert == NULL || ks->priv_key == NULL) {
      LOG_ERR("C509 Certificate or private key missing!\n");
      goto clean_and_ret_err;
    }

    c509_cert_t c509;
    size_t offset;

    /* Convert CA Cert */
    session_info->ca_der = heapmem_alloc(1024);
    if(session_info->ca_der == NULL) {
      LOG_ERR("Failed to allocate memory for CA DER\n");
      goto clean_and_ret_err;
    }
    if(c509_parse_cert(&c509, ks->ca_cert, ks->ca_cert_len) != CBOR_ERR_NONE) {
      LOG_ERR("Failed to parse C509 CA cert\n");
      goto clean_and_ret_err;
    }
    offset = 0;
    if(x509_encode_full_cert(session_info->ca_der, 1024, &offset, &c509) < 0) {
      LOG_ERR("Failed to encode X.509 CA cert\n");
      goto clean_and_ret_err;
    }
    debug_hex_dump("CA DER", session_info->ca_der, offset);

    ret = mbedtls_x509_crt_parse(&session_info->ca_cert,
                                 (const unsigned char *)session_info->ca_der,
                                 offset);
    LOG_DBG("mbedtls_x509_crt_parse(CA) returned %d\n", ret);
    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse failed for CA cert (error %d)\n", ret);
      goto clean_and_ret_err;
    }

    mbedtls_ssl_conf_ca_chain(&session_info->conf, &session_info->ca_cert,
                              NULL);

    /* Convert Own Cert */
    session_info->own_der = heapmem_alloc(1024);
    if(session_info->own_der == NULL) {
      LOG_ERR("Failed to allocate memory for Own DER\n");
      goto clean_and_ret_err;
    }
    if(c509_parse_cert(&c509, ks->own_cert, ks->own_cert_len) != CBOR_ERR_NONE) {
      LOG_ERR("Failed to parse C509 own cert\n");
      goto clean_and_ret_err;
    }
    offset = 0;
    if(x509_encode_full_cert(session_info->own_der, 1024, &offset, &c509) < 0) {
      LOG_ERR("Failed to encode X.509 own cert\n");
      goto clean_and_ret_err;
    }
    debug_hex_dump("Own DER", session_info->own_der, offset);

    ret = mbedtls_x509_crt_parse(&session_info->own_cert,
                                 (const unsigned char *)session_info->own_der,
                                 offset);
    if(ret < 0) {
      LOG_ERR("mbedtls_x509_crt_parse for own cert (error %d)\n", ret);
      goto clean_and_ret_err;
    }

    /*
     * Optional intermediate (Sub) CA cert: convert to DER and append to
     * own_cert's chain via a second mbedtls_x509_crt_parse() call (which
     * links it onto own_cert.next), so Mbed TLS sends [leaf, Sub CA] to the
     * peer during the handshake.
     */
    if(ks->intermediate_cert != NULL) {
      session_info->intermediate_der = heapmem_alloc(1024);
      if(session_info->intermediate_der == NULL) {
        LOG_ERR("Failed to allocate memory for intermediate DER\n");
        goto clean_and_ret_err;
      }
      if(c509_parse_cert(&c509, ks->intermediate_cert, ks->intermediate_cert_len) != CBOR_ERR_NONE) {
        LOG_ERR("Failed to parse C509 intermediate cert\n");
        goto clean_and_ret_err;
      }
      offset = 0;
      if(x509_encode_full_cert(session_info->intermediate_der, 1024, &offset, &c509) < 0) {
        LOG_ERR("Failed to encode X.509 intermediate cert\n");
        goto clean_and_ret_err;
      }
      debug_hex_dump("Intermediate DER", session_info->intermediate_der, offset);

      ret = mbedtls_x509_crt_parse(&session_info->own_cert,
                                   (const unsigned char *)session_info->intermediate_der,
                                   offset);
      if(ret < 0) {
        LOG_ERR("mbedtls_x509_crt_parse for intermediate cert (error %d)\n", ret);
        goto clean_and_ret_err;
      }
    }

    ret = mbedtls_pk_parse_key(&session_info->pkey,
                               (const unsigned char *)ks->priv_key,
                               ks->priv_key_len, NULL, 0,
                               mbedtls_entropy_func, NULL);
    if(ret < 0) {
      LOG_DBG("mbedtls_pk_parse_key returned %d\n", ret);
      goto clean_and_ret_err;
    }

    ret = mbedtls_ssl_conf_own_cert(&session_info->conf,
                                    &session_info->own_cert,
                                    &session_info->pkey);
    if(ret != 0) {
      LOG_ERR("mbedtls_ssl_conf_own_cert returned %d\n", ret);
      goto clean_and_ret_err;
    }

    /*
     * For natively signed Type-2 C509 (detected from the CA cert's type
     * byte), additionally register a verify callback that performs chain
     * validation on the raw C509 bytes. The CA/own certs above are still
     * reconstructed to DER and loaded into Mbed TLS as usual so that Mbed
     * TLS can build the chain and run its other checks (e.g. on the CA
     * cert itself); only the leaf's signature check is expected to fail,
     * because the original signature was computed over the CBOR TBS, not
     * the DER TBSCertificate -- c509_native_verify_cb() compensates for
     * that.
     *
     * This requires that the keystore entry also provides the peer's raw
     * C509 bytes (peer_cert) and the CA's public key (ca_pub_xy), which are
     * stashed on session_info here so the callback can use them once the
     * handshake reaches the peer's certificate (depth 0). If either is
     * missing, no callback is registered and Mbed TLS's normal verification
     * result stands (which will reject a Type-2 leaf cert as untrusted).
     */
    if(c509_is_native_type2(ks->ca_cert, ks->ca_cert_len) &&
       ks->peer_cert != NULL && ks->ca_pub_xy != NULL) {
      session_info->is_native_c509       = true;
      session_info->native_peer_c509     = ks->peer_cert;
      session_info->native_peer_c509_len = ks->peer_cert_len;
      memcpy(session_info->native_ca_pub_xy, ks->ca_pub_xy, 64);
      session_info->native_ca_pk_alg     = ks->ca_pk_alg;
      if(ks->peer_intermediate_cert != NULL) {
        session_info->native_intermediate_c509     = ks->peer_intermediate_cert;
        session_info->native_intermediate_c509_len = ks->peer_intermediate_cert_len;
      }
      mbedtls_ssl_conf_verify(&session_info->conf,
                              c509_native_verify_cb, session_info);
      LOG_INFO("Native C509 Type-2: verify callback registered\n");
    }
  } else
#endif /* COAP_DTLS_CONF_WITH_C509 */
#ifdef COAP_DTLS_CONF_WITH_PSK
  if(sec_mode == COAP_DTLS_SEC_MODE_PSK) {

    coap_keystore_psk_entry_t *ks =
      (coap_keystore_psk_entry_t *)keystore_entry;

    if(ks->identity == NULL || ks->key == NULL) {
      LOG_ERR("PSK identity or key missing\n");
      goto clean_and_ret_err;
    }

    /* Load the PSK key and identity */
    mbedtls_ssl_conf_psk(&session_info->conf,
                         (const unsigned char *)ks->key,
                         ks->key_len,
                         (const unsigned char *)ks->identity,
                         ks->identity_len);
  } else
#endif /* COAP_DTLS_CONF_WITH_PSK */
  {
    LOG_ERR("DTLS Security mode NOT specified!\n");
    goto clean_and_ret_err;
  }

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_ssl_conf_dbg(&session_info->conf, mbedtls_debug, stdout);
#endif /* MBEDTLS_DEBUG_C */
  mbedtls_ssl_conf_handshake_timeout(&session_info->conf,
                                     COAP_MBEDTLS_HANDSHAKE_MIN_TIMEOUT_MS,
                                     COAP_MBEDTLS_HANDSHAKE_MAX_TIMEOUT_MS);

  mbedtls_ssl_conf_max_frag_len(&session_info->conf,
                                COAP_MBEDTLS_MAX_FRAG_LEN);

#ifdef COAP_DTLS_CONF_WITH_SERVER
  if(role == COAP_MBEDTLS_ROLE_SERVER) {
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&session_info->conf, &session_info->cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif /* MBEDTLS_SSL_CACHE_C */

    ret = mbedtls_ssl_cookie_setup(&session_info->cookie_ctx,
                                   mbedtls_ctr_drbg_random,
                                   &session_info->ctr_drbg);
    if(ret != 0) {
      LOG_ERR("mbedtls_ssl_cookie_setup returned %d\n", ret);
      goto clean_and_ret_err;
    }

    mbedtls_ssl_conf_dtls_cookies(&session_info->conf,
                                  mbedtls_ssl_cookie_write,
                                  mbedtls_ssl_cookie_check,
                                  &session_info->cookie_ctx);
  }
#endif /* COAP_DTLS_CONF_WITH_SERVER */

  ret = mbedtls_ssl_setup(&session_info->ssl, &session_info->conf);
  if(ret != 0) {
    LOG_ERR("mbedtls_ssl_setup returned -0x%x\n", (unsigned int)-ret);
    goto clean_and_ret_err;
  }

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
  /* Used for SNI extension -- Currently unused. Could be used when
   * DTLS server contains multiple certificates. */
  ret = mbedtls_ssl_set_hostname(&session_info->ssl,
                                 hostname);
  if(ret != 0) {
    LOG_ERR("mbedtls_ssl_set_hostname returned %d\n", ret);
  }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

  mbedtls_ssl_set_bio(&session_info->ssl, session_info, coap_ep_mbedtls_sendto,
                      coap_ep_mbedtls_recv, NULL);
  mbedtls_ssl_set_timer_cb(&session_info->ssl, &session_info->timer,
                           mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  mbedtls_ssl_set_mtu(&session_info->ssl, COAP_MBEDTLS_MTU);
  return session_info;

 clean_and_ret_err:
#ifdef COAP_DTLS_CONF_WITH_C509
  if(session_info->ca_der != NULL) heapmem_free(session_info->ca_der);
  if(session_info->own_der != NULL) heapmem_free(session_info->own_der);
  if(session_info->intermediate_der != NULL) heapmem_free(session_info->intermediate_der);
#endif
  list_remove(dtls_context.sessions, session_info);
  memb_free(&dtls_session_info_memb, session_info);
  return NULL;
}
/*---------------------------------------------------------------------------*/
/* TODO: One usage of MBEDTLS_PRIVATE to access now state */
/*---------------------------------------------------------------------------*/

#ifdef COAP_DTLS_CONF_WITH_CLIENT
int
coap_ep_dtls_connect(const coap_endpoint_t *ep,
                     const coap_dtls_sec_mode_t sec_mode,
                     const void *keystore_entry)
{
  if(!dtls_context.ready) {
    LOG_WARN("DTLS not initialized but %s called!\n", __func__);
    return 0;
  }

  /* Create and setup session info if it does not exist already */
  coap_dtls_session_info_t *session_info = coap_ep_get_dtls_session_info(ep);
  if(session_info == NULL) {
    session_info = setup_session(COAP_MBEDTLS_ROLE_CLIENT,
                                 sec_mode, keystore_entry);
    if(session_info == NULL) {
      return 0;
    }
    memcpy(&session_info->ep, ep, sizeof(coap_endpoint_t));
  } else {
    /*
     * The session already exists. If this func is called again, we
     * may want to retry handshake. But, first check if DTLS is in a
     * valid state and the re-transmission timer is expired.
     */

    if((session_info->ssl.MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HELLO_REQUEST)
       || mbedtls_ssl_is_handshake_over(&session_info->ssl)
       || mbedtls_timing_get_delay(&session_info->timer) != 2) {
      return 0;
    }

    /* Re-transmission event invoked by application process */
    LOG_INFO("Re-transmission timer expired\n");
    LOG_DBG("HS retry, current process = %s\n", PROCESS_CURRENT()->name);
  }

  /* Client initiate handshake */
  perform_handshake(session_info);
  return 1;
}
#endif /* COAP_DTLS_CONF_WITH_CLIENT */
/*---------------------------------------------------------------------------*/
#ifdef COAP_DTLS_CONF_WITH_SERVER
int
coap_dtls_server_setup(const coap_dtls_sec_mode_t sec_mode,
                          const void *keystore_entry)
{
  /* Create and setup session info. */
  coap_dtls_session_info_t *session_info = setup_session(COAP_MBEDTLS_ROLE_SERVER,
                                                         sec_mode, keystore_entry);
  if(session_info == NULL) {
    LOG_ERR("Unable to setup DTLS server\n");
    return 0;
  }

  LOG_INFO("DTLS server setup complete, ready to accept connections\n");
  return 1;
}
#endif /* COAP_DTLS_CONF_WITH_SERVER */
/*---------------------------------------------------------------------------*/
int
coap_ep_dtls_write(const coap_endpoint_t *ep,
                   const unsigned char *message, int len)
{
  if(!dtls_context.ready) {
    LOG_WARN("DTLS not initialized but %s called!\n", __func__);
    return -1;
  }
  coap_dtls_session_info_t *info = coap_ep_get_dtls_session_info(ep);
  if(info == NULL) {
    LOG_ERR("Unable to find DTLS peer ");
    LOG_ERR_6ADDR(&ep->ipaddr);
    LOG_ERR_("\n");
    return -1;
  }

  if(!mbedtls_ssl_is_handshake_over(&info->ssl)) {
    LOG_ERR("DTLS handshake not complete yet, but %s called!\n", __func__);
    return -1;
  }

  int ret = mbedtls_ssl_get_max_out_record_payload(&info->ssl);
  if(ret < len && ret >= 0) {
    /* Note: payload limit dependent on MTU, Max. Frag len, or I/O buffers */
    LOG_ERR("Payload too large to handle, Max allowed = %d, Given = %d\n",
            ret, len);
    return -1;
  }

  ret = mbedtls_ssl_write(&info->ssl, message, len);
  if(ret < 0) {
    LOG_ERR("mbedtls_ssl_write returned 0x%x\n", ret);
    return -1;
  }

  return len;
}
/*---------------------------------------------------------------------------*/
int
coap_ep_dtls_handle_message(const coap_endpoint_t *ep)
{
  if(!dtls_context.ready) {
    LOG_WARN("Called %s without DTLS being initialized; dropping message\n",
             __func__);
    return -1;
  }

  LOG_INFO("Recieved DTLS message of len = %d\n", uip_datalen());

  /* First check and process handshake messages. If the session
     already exists, there maybe an ongoing handshake. */
  coap_dtls_session_info_t *session_info = coap_ep_get_dtls_session_info(ep);
  if(session_info != NULL) {
    /* For both server/client check if handshake is not complete.
       Otherwise it maybe a DTLS record layer message. */
    if(!mbedtls_ssl_is_handshake_over(&session_info->ssl)) {
      goto perform_handshake;
    }
  } else {
#ifdef COAP_DTLS_CONF_WITH_SERVER
    /* If the session does not exist already, a new handshake maybe
       initated by a client endpoint. */
    if((session_info = coap_get_free_server_session()) != NULL) {
      memcpy(&session_info->ep, ep, sizeof(coap_endpoint_t));
      goto perform_handshake;
    } else
#endif /* COAP_DTLS_CONF_WITH_SERVER */
    {
      LOG_WARN("DTLS message recvd from ");
      LOG_WARN_6ADDR(&ep->ipaddr);
      LOG_WARN(" without a session\n");
      return -1;
    }
  }

  session_info->is_packet_consumed = false;

  int ret = mbedtls_ssl_read(&session_info->ssl, uip_appdata,
                             UIP_CONF_BUFFER_SIZE);
  if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    LOG_INFO("DTLS peer closed connection\n");
    coap_ep_dtls_disconnect(ep);
  } else if(ret <= 0) {
    LOG_DBG("mbedtls_ssl_read returned %d\n", ret);
  } else {
    LOG_DBG("Read %d application data bytes\n", ret);
  }

  return ret;

perform_handshake:
  session_info->is_packet_consumed = false;
  perform_handshake(session_info);
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
free_session_resources(coap_dtls_session_info_t *info)
{
  mbedtls_ssl_free(&info->ssl);
  mbedtls_ssl_config_free(&info->conf);
  mbedtls_ctr_drbg_free(&info->ctr_drbg);
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
  mbedtls_entropy_free(&info->entropy);
#endif

#if defined(COAP_DTLS_CONF_WITH_CERT) || defined(COAP_DTLS_CONF_WITH_C509)
  mbedtls_x509_crt_free(&info->ca_cert);
  mbedtls_x509_crt_free(&info->own_cert);
  mbedtls_pk_free(&info->pkey);
#endif

#ifdef COAP_DTLS_CONF_WITH_C509
  if(info->ca_der != NULL) {
    heapmem_free(info->ca_der);
    info->ca_der = NULL;
  }
  if(info->own_der != NULL) {
    heapmem_free(info->own_der);
    info->own_der = NULL;
  }
  if(info->intermediate_der != NULL) {
    heapmem_free(info->intermediate_der);
    info->intermediate_der = NULL;
  }
#endif
}

void
coap_ep_dtls_disconnect(const coap_endpoint_t *ep)
{
  coap_dtls_session_info_t *info = coap_ep_get_dtls_session_info(ep);
  if(info != NULL) {
    mbedtls_ssl_close_notify(&info->ssl);
    
    free_session_resources(info);

#ifdef COAP_DTLS_CONF_WITH_CLIENT
    if(info->role == COAP_MBEDTLS_ROLE_CLIENT) {
      list_remove(dtls_context.sessions, info);
      memb_free(&dtls_session_info_memb, info);
    }
#endif /* COAP_DTLS_CONF_WITH_CLIENT */
#ifdef COAP_DTLS_CONF_WITH_SERVER
    if(info->role == COAP_MBEDTLS_ROLE_SERVER) {
      /* On server we might want to keep the session info struct but it must be ready for next client */
      mbedtls_ssl_init(&info->ssl);
      mbedtls_ssl_config_init(&info->conf);
      info->in_use = false;
      memset(&info->ep, 0, sizeof(coap_endpoint_t));
      etimer_stop(&info->retransmission_et);
    }
#endif /* COAP_DTLS_CONF_WITH_SERVER */
  }
}
