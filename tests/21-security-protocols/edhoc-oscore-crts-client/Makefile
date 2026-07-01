CONTIKI_PROJECT = edhoc-oscore-crts-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

# c509-chain.c is added directly (not via "MODULES += os/services/c509", and
# not via a directory-wide SOURCEDIRS entry) to avoid pulling in
# os/services/c509/cbor.c: a directory-wide vpath would let "cbor.c" (needed
# by os/lib for EDHOC's CBOR writer) resolve to the c509 module's
# decoder-only cbor.c instead, breaking the link. A per-file vpath sidesteps
# that.
vpath c509-chain.c $(CONTIKI)/os/services/c509
vpath c509-csr-build.c $(CONTIKI)/os/services/c509
vpath c509-csr-parse.c $(CONTIKI)/os/services/c509
CONTIKI_SOURCEFILES += c509-chain.c c509-csr-build.c c509-csr-parse.c
CFLAGS += -I$(CONTIKI)/os/services/c509

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

# restart-on-failure Phase 2: give the EDHOC handshake more attempts under lossy
# links (default 2), with exponential inter-attempt backoff (edhoc-config.h).
CFLAGS += -DEDHOC_CONF_ATTEMPTS=5

include $(CONTIKI)/Makefile.include
