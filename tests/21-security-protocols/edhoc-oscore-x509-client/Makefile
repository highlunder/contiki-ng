CONTIKI_PROJECT = edhoc-oscore-x509-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because:
#  - A SEQUENCE_ERROR on MSG_1 triggers a second round trip before MSG_2 arrives.
#  - x5chain carries the full X.509 DER certificate inline (block-wise),
#    extending delivery time (387 bytes vs 159 for the C509 c5c variant).
#  - 802.15.4 fragmentation adds further delay on slow or lossy links.
# Real hardware: 5–8 s may suffice on a clean link; keep 15 s for robustness.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
