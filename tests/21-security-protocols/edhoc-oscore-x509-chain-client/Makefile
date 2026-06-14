CONTIKI_PROJECT = edhoc-oscore-x509-chain-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 — see
# edhoc-oscore-x509-client/Makefile for the rationale; the chain-length-1
# x5chain cert is even larger (782 B CRED_x vs 384 B), so block-wise
# delivery takes more round trips.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
