CONTIKI_PROJECT = edhoc-method2-c5t-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because of SEQUENCE_ERROR retry and fragmentation.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
