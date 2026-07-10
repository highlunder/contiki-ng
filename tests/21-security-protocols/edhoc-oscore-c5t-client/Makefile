CONTIKI_PROJECT = edhoc-oscore-c5t-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# Opt-in DWT cycle + wall-clock profiling of the EDHOC crypto path
# (per-op ecc_* cycles in ecdh.c + whole-handshake wall-clock here).
# Build with EDHOC_PROFILE=1 to enable; off by default (zero cost).
ifeq ($(EDHOC_PROFILE),1)
  CFLAGS += -DEDHOC_PROFILE_CYCLES
endif

# Short build id stamped into the startup printout for record-keeping (matches
# the cc310-bringup benches). Defaults to the UTC build date; override FW_ID=.
# Always clean-build (rm -rf build) so the stamp regenerates.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

# Name the ECC backend in the stamp so a pasted handshake log is self-identifying
# (which silicon/software path produced the timing). Mirrors Makefile.nrf52840's
# ECC_HW_BACKEND switch.
ifeq ($(ECC_HW_BACKEND),cc310)
  CFLAGS += -DECC_BACKEND_NAME='"CC310 hardware"'
else
  CFLAGS += -DECC_BACKEND_NAME='"software (uECC)"'
endif

# Multi-hop: wait for RPL routes + TSCH slots to settle before EDHOC.
# e.g. `make ... MULTIHOP_CONNECT_DELAY_S=90`. Default off (single-hop unaffected).
ifdef MULTIHOP_CONNECT_DELAY_S
  CFLAGS += -DMULTIHOP_CONNECT_DELAY_S=$(MULTIHOP_CONNECT_DELAY_S)
endif

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because:
#  - A SEQUENCE_ERROR on MSG_1 triggers a second round trip before MSG_2 arrives.
#  - 802.15.4 fragmentation of MSG_2 takes additional time on slow links.
# Single-hop keeps 3 s (unchanged): on a fast single-hop link MSG_2 returns in
# well under a second, so the CON timeout never fires and 3 s is harmless.
#
# Multi-hop needs far more headroom: forwarding a fragmented EDHOC message across
# several TSCH slotframes and back routinely exceeds 15 s, so a 3 s CON timeout
# fires mid-round-trip and the client keeps retransmitting MSG_1 into a half-done
# handshake — a real flaky-multi-hop cause (MSG_1 requests time out with CoAP
# status 3 = TIMEOUT and the handshake needs several attempts to land). Raise it
# to 25 s only for multi-hop builds so single-hop timing is byte-for-byte unchanged.
ifdef MULTIHOP_CONNECT_DELAY_S
  COAP_RESPONSE_TIMEOUT ?= 25
else
  COAP_RESPONSE_TIMEOUT ?= 3
endif
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=$(COAP_RESPONSE_TIMEOUT)
CFLAGS += -DCOAP_MAX_RETRANSMIT=2

include $(CONTIKI)/Makefile.include
