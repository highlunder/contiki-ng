CONTIKI_PROJECT = x509-slip-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/lib

# X.509 test credentials live in the EDHOC header directory.
CFLAGS += -I$(CONTIKI)/os/net/security/edhoc
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=65536

# Console logs over the nRF native USB CDC (SLIP keeps UART0); see project-conf.h.
NRF52840_NATIVE_USB = 1

# Phase-2 single-board uplink: board is its own RPL root over SLIP (tunslip6).
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
