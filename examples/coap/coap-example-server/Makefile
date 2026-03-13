CONTIKI_PROJECT = coap-example-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky/Z1 because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../../..

# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

# Include C509 service
MODULES += os/services/c509

# Include heapmem and other libs
MODULES += os/lib

# Enable C509 in CFLAGS
CFLAGS += -DCOAP_DTLS_CONF_WITH_C509=1

# Force ignore unused function and variable errors for Mbed TLS
CFLAGS += -Wno-error=unused-function
CFLAGS += -Wno-error=unused-variable
CFLAGS += -Wno-error=unused-but-set-variable

include $(CONTIKI)/Makefile.include
