CONTIKI_PROJECT = edhoc-oscore-crts-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

# c509-chain.c is added directly (not via "MODULES += os/services/c509", and
# not via a directory-wide SOURCEDIRS entry) to avoid pulling in
# os/services/c509/cbor.c: a directory-wide vpath would let "cbor.c" (needed
# by os/lib for EDHOC's CBOR writer) resolve to the c509 module's
# decoder-only cbor.c instead, breaking the link. A per-file vpath sidesteps
# that.
vpath c509-chain.c $(CONTIKI)/os/services/c509
vpath c509-csr-build.c $(CONTIKI)/os/services/c509
vpath c509-csr-parse.c $(CONTIKI)/os/services/c509
CONTIKI_SOURCEFILES += c509-chain.c c509-csr-build.c c509-csr-parse.c
CFLAGS += -I$(CONTIKI)/os/services/c509

# Shared Welford benchmark harness (mean/median/p95/sd over ENROLL_ITERS runs).
CFLAGS += -I$(CONTIKI)/local-tests/bench
ENROLL_ITERS ?= 20
CFLAGS += -DENROLL_ITERS=$(ENROLL_ITERS)
# ENROLL_BENCH=1: statistical-benchmark build (loop N iters; the server disables
# its /sen idempotency cache to time a full issuance each iteration).
ifdef ENROLL_BENCH
  CFLAGS += -DENROLL_BENCH=1
endif

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1
# restart-on-failure Phase 2.5: bound the CoAP retransmit budget for the (small,
# chain-less c5t) EDHOC handshake messages so a message that gets no ACK under loss
# gives up quickly -> the EDHOC-level recovery (validate_response NULL -> EVT_RESTART
# -> handle_retry) preempts it WITHIN the run budget, instead of the CoAP CON
# retransmitting for ~245 s (COAP_RESPONSE_TIMEOUT 15 * exp) and outlasting it.
# (Only the EDHOC handshake uses CoAP here; /crts+/sen use their own UDP retransmit.)
# Multi-hop (build with MULTIHOP_CONNECT_DELAY_S>0): settle delay + relaxed TSCH
# ASN-drift eviction (project-conf) + longer CoAP CON timeout for the EDHOC handshake
# (the >15 s multi-hop MSG round trip outlasts a 3 s CON, causing premature restarts).
# Single-hop keeps the tight restart-on-failure 3 s. /crts+/sen use their own UDP
# retransmit (ENROLL_MAX_RETX) regardless.
ifdef MULTIHOP_CONNECT_DELAY_S
  CFLAGS += -DMULTIHOP_CONNECT_DELAY_S=$(MULTIHOP_CONNECT_DELAY_S) -DMULTIHOP=1
  CFLAGS += -DCOAP_RESPONSE_TIMEOUT=25
else
  CFLAGS += -DCOAP_RESPONSE_TIMEOUT=3
endif
CFLAGS += -DCOAP_MAX_RETRANSMIT=2

# restart-on-failure Phase 2: give the EDHOC handshake more attempts under lossy
# links (default 2), with exponential inter-attempt backoff (edhoc-config.h).
CFLAGS += -DEDHOC_CONF_ATTEMPTS=5

# X.509-DER enrollment trial (build ENROLL_X509=1): validate the /crts + /sen
# responses as full X.509 DER certs (~380 B) rather than compact C509, to measure
# the X.509-sized enrollment flights over multi-hop. See X509-ENROLL-WRAPPING.md.
ifdef ENROLL_X509
  CFLAGS += -DENROLL_X509=1
endif

# ENROLL_X509_DYN=1: fully-faithful X.509 uplink — POST a real PKCS#10 DER CSR on
# /sen (via c509_csr_to_pkcs10_der -> x509_encode_csr) instead of the compact C509
# Type-3 CSR. Pulls the c509 encoder (cbor-collision-free through the wrapper) and
# selects x509_encode's micro-ecc point-decompression backend.
ifdef ENROLL_X509_DYN
  CFLAGS += -DENROLL_X509_DYN=1
  CFLAGS += -DC509_X509_ENCODE_UECC=1
  vpath c509-x509-wrap.c $(CONTIKI)/os/services/c509
  vpath x509_encode.c $(CONTIKI)/os/services/c509
  vpath x509-csr-parse.c $(CONTIKI)/os/services/c509
  vpath c509.c        $(CONTIKI)/os/services/c509
  vpath c509-cbor.c   $(CONTIKI)/os/services/c509
  vpath der.c         $(CONTIKI)/os/services/c509
  vpath validity.c    $(CONTIKI)/os/services/c509
  CONTIKI_SOURCEFILES += c509-x509-wrap.c x509_encode.c x509-csr-parse.c c509.c c509-cbor.c der.c validity.c
  CFLAGS += -I$(CONTIKI)/os/net/security/micro-ecc
endif

# Firmware build id, stamped into the [ENROLL-TIMING] block (Exp H2 wall-clock).
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

include $(CONTIKI)/Makefile.include
