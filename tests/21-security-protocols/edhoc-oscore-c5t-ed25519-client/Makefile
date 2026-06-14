CONTIKI_PROJECT = edhoc-oscore-c5t-ed25519-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# EDHOC_CONF_SIGNATURE_ALG EDDSA (project-conf.h) pulls in ed25519_verify.c's
# ed25519_sign()/ed25519_verify() from os/services/c509, which need
# mbedtls_sha512. Compile that one file directly via vpath (not the whole
# os/services/c509 module as a PROJECTDIR/MODULE, which would shadow
# lib/cbor.c used by oscore.c with os/services/c509/cbor.c -- different,
# incompatible cbor.h API) and bring in MbedTLS via the standard CoAP-DTLS
# path.
vpath ed25519_verify.c $(CONTIKI)/os/services/c509
CFLAGS += -I$(CONTIKI)/os/services/c509
PROJECT_SOURCEFILES += ed25519_verify.c

MODULES += os/net/app-layer/coap
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1

# os/net/security/edhoc/ecdh.c (ecdh_generate_ikm, EDHOC's own ECDH) and
# os/net/security/mbedtls/library/ecdh.c (mbedtls_ecdh_init/free, needed by
# ssl_tls.c) share the basename "ecdh.c" -- only one "ecdh.o" can exist, and
# the EDHOC module's wins. Pull in MbedTLS's ecdh.c under a different object
# name via an #include wrapper.
vpath mbedtls-ecdh-wrapper.c $(CONTIKI)/os/services/c509/mbedtls-ecdh-wrapper
PROJECT_SOURCEFILES += mbedtls-ecdh-wrapper.c

# MbedTLS (pulled in via MAKE_WITH_DTLS) uses heapmem for dynamic allocation,
# but os/lib/heapmem.c is opt-in and not auto-added by any MODULES entry.
vpath heapmem.c $(CONTIKI)/os/lib
PROJECT_SOURCEFILES += heapmem.c

# CoAP module has unused functions when pulled in only for MbedTLS.
WERROR = 0

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because:
#  - A SEQUENCE_ERROR on MSG_1 triggers a second round trip before MSG_2 arrives.
#  - 802.15.4 fragmentation of MSG_2 takes additional time on slow links.
# Real hardware: 5-8 s may suffice on a clean link; keep 15 s for robustness.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
