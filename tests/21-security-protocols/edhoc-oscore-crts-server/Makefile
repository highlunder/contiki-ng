CONTIKI_PROJECT = edhoc-oscore-crts-server

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/edhoc/server
MODULES += os/net/security/oscore

# c509 sources are added per-file (not via "MODULES += os/services/c509", and
# not via a directory-wide SOURCEDIRS entry) so that only the specific decoder/
# encoder files are pulled in. The c509 CBOR decoder was renamed cbor.c ->
# c509-cbor.c precisely so its object no longer collides with os/lib/cbor.o
# (EDHOC's CBOR writer); the two can now coexist in one link.
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

# ENROLL_X509_DYN=1: fully-dynamic wrapper — reconstruct the X.509 DER at runtime
# from the C509 CA/issued certs with x509_encode_full_cert() (the same converter the
# DTLS path uses), rather than shipping static blobs. Pulls the c509 parser/encoder
# (now cbor-collision-free) and selects x509_encode's micro-ecc point-decompression
# backend (the enroll apps link uECC, not mbedTLS).
ifdef ENROLL_X509_DYN
  CFLAGS += -DENROLL_X509_DYN=1
  CFLAGS += -DC509_X509_ENCODE_UECC=1
  vpath c509-x509-wrap.c $(CONTIKI)/os/services/c509
  vpath x509_encode.c $(CONTIKI)/os/services/c509
  vpath c509.c        $(CONTIKI)/os/services/c509
  vpath c509-cbor.c   $(CONTIKI)/os/services/c509
  vpath der.c         $(CONTIKI)/os/services/c509
  vpath validity.c    $(CONTIKI)/os/services/c509
  CONTIKI_SOURCEFILES += c509-x509-wrap.c x509_encode.c c509.c c509-cbor.c der.c validity.c
  CFLAGS += -I$(CONTIKI)/os/net/security/micro-ecc
endif

include $(CONTIKI)/Makefile.include
