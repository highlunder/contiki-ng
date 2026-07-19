CONTIKI_PROJECT = attest-selftest
all: $(CONTIKI_PROJECT)

# Single-world runtime self-test of the RA attestation stack, for cooja-ng
# (emulated nRF52840). The TrustZone version runs on the nRF5340-DK.
MODULES += os/services/attestation

# The signer/verifier backend: Monocypher Ed25519 (vendored).
MONOCYPHER = $(CONTIKI)/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
PROJECTDIRS += $(MONOCYPHER)
PROJECT_SOURCEFILES += monocypher.c monocypher-ed25519.c
CFLAGS += -I$(MONOCYPHER)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
