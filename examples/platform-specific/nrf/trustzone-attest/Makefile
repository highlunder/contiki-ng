# P2 -- Remote Attestation over EDHOC with a TrustZone secure-world Root of Trust
# (draft-ietf-lake-ra Contiki port). Builds a secure-world firmware (holding the
# attestation key + measuring the normal-world image + signing Evidence, via
# tz-attest) and a normal-world firmware (the RA app), merged into one hex for the
# nRF5340-DK. Mirrors examples/platform-specific/nrf/trustzone.
BUILD_DIR ?= build/nrf/nrf5340/dk/application
SREC_CAT ?= srec_cat

SECURE_WORLD_FIRMWARE ?= secure-world-attest
NORMAL_WORLD_FIRMWARE ?= normal-world-attest
MERGED_FIRMWARE ?= tz-attest-merged

.PHONY: all
all: tz_build

.PHONY: tz_build
tz_build:
	$(MAKE) -C secure-world $(BUILD_DIR)/$(SECURE_WORLD_FIRMWARE).hex
	$(MAKE) -C normal-world $(BUILD_DIR)/$(NORMAL_WORLD_FIRMWARE).hex
	$(SREC_CAT) secure-world/$(BUILD_DIR)/$(SECURE_WORLD_FIRMWARE).hex -Intel \
		normal-world/$(BUILD_DIR)/$(NORMAL_WORLD_FIRMWARE).hex -Intel \
		-o secure-world/$(BUILD_DIR)/$(MERGED_FIRMWARE).hex -Intel

.PHONY: upload
upload: tz_build
	$(MAKE) -C secure-world $(MERGED_FIRMWARE).upload PORT=$(PORT)

.PHONY: login
login:
	$(MAKE) -C secure-world login PORT=$(PORT)

.PHONY: clean
clean:
	$(MAKE) -C secure-world clean
	$(MAKE) -C normal-world clean
