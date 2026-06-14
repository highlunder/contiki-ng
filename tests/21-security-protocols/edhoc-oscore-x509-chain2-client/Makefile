CONTIKI_PROJECT = edhoc-oscore-x509-chain2-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CoAP CON retransmit timeout in seconds (default 3). Raised to 20 — the
# chain-length-2 x5chain cert is larger still (1188 B CRED_x vs 782 B for
# chain-length-1), so block-wise delivery takes more round trips. See
# edhoc-oscore-x509-chain-client/Makefile for the rationale.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=20

include $(CONTIKI)/Makefile.include
