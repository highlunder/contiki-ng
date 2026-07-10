CONTIKI_PROJECT = edhoc-oscore-crts-server

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/edhoc/server
MODULES += os/net/security/oscore

# c509-chain.c is added directly (not via "MODULES += os/services/c509", and
# not via a directory-wide SOURCEDIRS entry) to avoid pulling in
# os/services/c509/cbor.c: a directory-wide vpath would let "cbor.c" (needed
# by os/lib for EDHOC's CBOR writer) resolve to the c509 module's
# decoder-only cbor.c instead, breaking the link. A per-file vpath sidesteps
# that.
vpath c509-chain.c $(CONTIKI)/os/services/c509
vpath c509-csr-parse.c $(CONTIKI)/os/services/c509
vpath c509-ca.c $(CONTIKI)/os/services/c509
CONTIKI_SOURCEFILES += c509-chain.c c509-csr-parse.c c509-ca.c
CFLAGS += -I$(CONTIKI)/os/services/c509

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# X.509-DER enrollment trial (build ENROLL_X509=1): /crts + /sen return full X.509
# DER certs (~380 B) instead of the compact C509 forms, to measure the X.509-sized
# enrollment flights over multi-hop. See the .c and X509-ENROLL-WRAPPING.md.
ifdef ENROLL_X509
  CFLAGS += -DENROLL_X509=1
endif

include $(CONTIKI)/Makefile.include
