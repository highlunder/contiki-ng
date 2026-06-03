CONTIKI_PROJECT = edhoc-test-c5c-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc

#uECC fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# c5c MSG_2 is 266 bytes and takes longer to fragment across 802.15.4
# than the default 3s CoAP response timeout allows.  10s gives margin.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
