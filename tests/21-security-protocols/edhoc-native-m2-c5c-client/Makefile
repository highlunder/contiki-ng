CONTIKI_PROJECT = edhoc-native-m2-c5c-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# Raised for c5c inline cert delivery (block-wise CoAP + fragmentation).
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
