CONTIKI_PROJECT = test-attestation
all: $(CONTIKI_PROJECT)

# The RA-over-EDHOC attestation codec (P0). Self-contained: no c509/mbedTLS.
MODULES += os/services/attestation

# Select the Contiki (PROCESS) build variant of the test; standalone gcc omits it.
CFLAGS += -DCONTIKI_BUILD=1

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
