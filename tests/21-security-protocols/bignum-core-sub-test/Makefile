CONTIKI_PROJECT = bignum-core-sub-test

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

# Pull in Mbed TLS (bignum_core.c lives in $(MBEDTLS_PATH)/library) without
# needing a full DTLS handshake -- we only call mbedtls_mpi_core_sub_int().
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1
MAKE_COAP_DTLS_WITH_SERVER = 1
MODULES += os/net/app-layer/coap

include $(CONTIKI)/Makefile.include
