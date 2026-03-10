CONTIKI_PROJECT = test-dtls-setup
all: $(CONTIKI_PROJECT)

# Include C509
MODULES += os/services/c509

# Include CoAP with DTLS
MODULES += os/net/app-layer/coap
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1
WERROR = 0

# Enable client support explicitly
CFLAGS += -DCOAP_DTLS_CONF_WITH_CLIENT=1

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
