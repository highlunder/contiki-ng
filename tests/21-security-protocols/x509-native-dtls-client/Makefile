CONTIKI_PROJECT = x509-native-dtls-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/lib

# X.509 test credentials are in the EDHOC header directory
CFLAGS += -I$(CONTIKI)/os/net/security/edhoc
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=65536

# Multi-hop (build with MULTIHOP=1): wait longer for the RPL downward route + TSCH
# slots to settle before the DTLS handshake, and relax the emulator's over-strict
# TSCH ASN-drift eviction so a relay-sourced node stays associated (see tsch-conf.h).
# Single-hop unaffected. DTLS's own flight retransmission handles per-message loss.
ifdef MULTIHOP
  CFLAGS += -DCONNECT_DELAY_S=30 -DMULTIHOP=1
endif

include $(CONTIKI)/Makefile.include
