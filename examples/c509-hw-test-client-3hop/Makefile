CONTIKI_PROJECT = c509-client-border
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

NRF52840_USE_RTT = 0

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/services/c509
MODULES += os/lib

# Source the client .c from the border variant (identical application logic).
PROJECTDIRS += ../c509-hw-test-client-border

include $(CONTIKI)/Makefile.include
