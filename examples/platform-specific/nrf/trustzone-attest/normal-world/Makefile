CONTIKI_PROJECT = normal-world-attest
all: $(CONTIKI_PROJECT)

PLATFORMS_ONLY += nrf
BOARDS_ONLY = nrf5340/dk/application

TARGET ?= nrf
BOARD ?= nrf5340/dk/application

TRUSTZONE_SECURE_BUILD = 0
TRUSTZONE_SECURE_WORLD_PATH ?= ../secure-world

# The attestation codec + verifier (portable, self-contained).
MODULES += os/services/attestation

# tz-attest.h (the secure-callable API) lives in the secure-world dir.
CFLAGS += -I../secure-world

# NS-side signature verify uses Monocypher (vendored); a real device could use
# os/services/c509/ed25519_verify.c or CC312 instead.
MONOCYPHER = $(CONTIKI)/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
PROJECTDIRS += $(MONOCYPHER)
PROJECT_SOURCEFILES += monocypher.c monocypher-ed25519.c
CFLAGS += -I$(MONOCYPHER)

CONTIKI = ../../../../..
include $(CONTIKI)/Makefile.include
