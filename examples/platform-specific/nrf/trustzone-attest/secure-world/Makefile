CONTIKI_PROJECT = secure-world-attest
all: $(CONTIKI_PROJECT)

PLATFORMS_ONLY += nrf
BOARDS_ONLY = nrf5340/dk/application

TARGET ?= nrf
BOARD ?= nrf5340/dk/application

# Minimal netstack keeps the secure-world trusted computing base small.
MAKE_MAC = MAKE_MAC_NULLMAC
MAKE_NET = MAKE_NET_NULLNET

TRUSTZONE_SECURE_BUILD = 1

# The attestation codec + Root-of-Trust core (portable, self-contained).
MODULES += os/services/attestation

# The RoT signer: Monocypher Ed25519 (vendored). A CC312/uECC backend is the
# follow-up (see P2-TRUSTZONE-PLAN.md §9-b).
MONOCYPHER = $(CONTIKI)/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
PROJECTDIRS += $(MONOCYPHER)
PROJECT_SOURCEFILES += tz-attest.c monocypher.c monocypher-ed25519.c
CFLAGS += -I$(MONOCYPHER)

CONTIKI = ../../../../..
include $(CONTIKI)/Makefile.include
