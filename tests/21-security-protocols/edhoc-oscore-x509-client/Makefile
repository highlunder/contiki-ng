CONTIKI_PROJECT = edhoc-oscore-x509-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# Multi-hop: wait for RPL routes + TSCH slots to settle before EDHOC.
# e.g. `make ... MULTIHOP_CONNECT_DELAY_S=30`. Default off (single-hop unaffected).
ifdef MULTIHOP_CONNECT_DELAY_S
  CFLAGS += -DMULTIHOP_CONNECT_DELAY_S=$(MULTIHOP_CONNECT_DELAY_S)
endif

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because:
#  - A SEQUENCE_ERROR on MSG_1 triggers a second round trip before MSG_2 arrives.
#  - x5chain carries the full X.509 DER certificate inline (block-wise),
#    extending delivery time (387 bytes vs 159 for the C509 c5c variant).
#  - 802.15.4 fragmentation adds further delay on slow or lossy links.
# Real hardware: 5–8 s may suffice on a clean link; keep 15 s for robustness.
# Multi-hop forwards the big x5chain flight across several TSCH slotframes and
# back, routinely exceeding 15 s, so give it 30 s there (x5chain is bigger than
# c5t, so a touch more than c5t's 25 s).
ifdef MULTIHOP_CONNECT_DELAY_S
  COAP_RESPONSE_TIMEOUT ?= 30
else
  COAP_RESPONSE_TIMEOUT ?= 15
endif
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=$(COAP_RESPONSE_TIMEOUT)

# Opt-in dedicated-slot TSCH schedule (build ORCHESTRA=1); see local-tests/multihop/relay/Makefile.
ifdef ORCHESTRA
  MODULES += os/services/orchestra
endif

include $(CONTIKI)/Makefile.include
