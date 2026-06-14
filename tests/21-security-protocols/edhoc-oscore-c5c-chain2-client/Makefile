CONTIKI_PROJECT = edhoc-oscore-c5c-chain2-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 — see
# edhoc-oscore-c5c-client/Makefile for rationale; the 3-cert chain inline
# delivery is larger than chain-length-1 c5c, so the same margin is kept.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
