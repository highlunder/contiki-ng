CONTIKI_PROJECT = edhoc-c5t-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

# Shared benchmark harness (bench-stats.h).
CFLAGS += -I$(CONTIKI)/local-tests/bench

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# CC310_DIAG=1 -> capturable printf of each CC310 init/rng/keygen return code
# (post-join, so a boot-time failure that scrolled past serial re-attach is still
# visible). Diagnostic only; no effect on the software backend.
ifeq ($(CC310_DIAG),1)
  CFLAGS += -DCC310_DIAG
endif

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

# CoAP CON retransmit timeout in seconds (default 3).  Raised to 15 for both
# emulated and real nRF52840 because:
#  - A SEQUENCE_ERROR on MSG_1 triggers a second round trip before MSG_2 arrives.
#  - 802.15.4 fragmentation of MSG_2 takes additional time on slow links.
# Real hardware: 5–8 s may suffice on a clean link; keep 15 s for robustness.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=3
CFLAGS += -DCOAP_MAX_RETRANSMIT=2

# PPK2 energy-window marker (Exp H4). ENERGY_MARKER_PIN=<n> drives nRF P1.<n>
# high across the timed handshake so the PPK2's D0 logic channel marks it. Off
# by default -> timing builds stay byte-identical. P1.10 is the runbook default.
# See ENERGY-PPK2-RUNBOOK.md.
ifdef ENERGY_MARKER_PIN
  CFLAGS += -DENERGY_MARKER_PIN=$(ENERGY_MARKER_PIN)
endif

include $(CONTIKI)/Makefile.include
