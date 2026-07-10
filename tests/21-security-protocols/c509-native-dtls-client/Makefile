CONTIKI_PROJECT = c509-native-dtls-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/services/c509
MODULES += os/services/ecc
MODULES += os/lib

# native C509 test credentials are in the EDHOC header directory
CFLAGS += -I$(CONTIKI)/os/net/security/edhoc
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=65536

# Multi-hop (build with MULTIHOP=1): longer settle before the handshake + relaxed
# TSCH ASN-drift eviction (see tsch-conf.h). Single-hop unaffected.
ifdef MULTIHOP
  CFLAGS += -DCONNECT_DELAY_S=30 -DMULTIHOP=1
endif

include $(CONTIKI)/Makefile.include
