TARGET = app

DEBUG = 0
OPT = -Os
# -Os == size optimalization, -Og for debugging

DIR_ROOT  ?= .

DIR_HW     := ../hw
DIR_SDK    := ../sdk
DIR_USB    := ../usb

include  $(DIR_SDK)/sdk_stm32u535.mk

BUILD_DIR = build
.DEFAULT_GOAL := all

# Detect number of parallel jobs (fallback to 4)
NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

C_SOURCES +=  \
  $(DIR_ROOT)/main.c \
  $(DIR_ROOT)/cmd.c \
  $(DIR_ROOT)/sphincs.c \
  $(DIR_ROOT)/dilithium.c \
  $(DIR_ROOT)/kyber.c \
  $(DIR_ROOT)/tls_pqc.c \
  \
  $(DIR_HAL)/tty.c \
  $(DIR_HAL)/led.c \
  \
  $(DIR_DRV)/dma.c \
  $(DIR_DRV)/gpio.c \
  $(DIR_DRV)/irq.c \
  $(DIR_DRV)/reset.c \
  $(DIR_DRV)/time.c \
  $(DIR_DRV)/uart.c \
  $(DIR_DRV)/sys.c \
  $(DIR_DRV)/wd.c \
  $(DIR_DRV)/spi.c \
  \
  $(DIR_COMMON)/util.c \
  \
  $(DIR_USB)/ux_device_cdc_acm.c \
  $(DIR_USB)/ux_device_descriptors.c \
  $(DIR_USB)/usb_device.c \


C_DEFS +=  \
-DMAIN_DEBUG=$(DEBUG)

# C includes
C_INCLUDES +=  \
-I$(DIR_ROOT) \
-I$(DIR_USB) \
-I$(DIR_HW)

#######################################
# wolfSSL integration (TLS 1.3 + ML-KEM)
#######################################

# Enable wolfSSL user settings
C_DEFS += -DWOLFSSL_USER_SETTINGS

# wolfSSL include directories
WOLFSSL_DIR := ../wolfssl
C_INCLUDES += -I$(WOLFSSL_DIR) -I$(WOLFSSL_DIR)/wolfssl -I$(WOLFSSL_DIR)/wolfssl/wolfcrypt

# wolfSSL TLS sources
C_SOURCES += \
  $(WOLFSSL_DIR)/src/bio.c \
  $(WOLFSSL_DIR)/src/crl.c \
  $(WOLFSSL_DIR)/src/internal.c \
  $(WOLFSSL_DIR)/src/keys.c \
  $(WOLFSSL_DIR)/src/ocsp.c \
  $(WOLFSSL_DIR)/src/sniffer.c \
  $(WOLFSSL_DIR)/src/ssl.c \
  $(WOLFSSL_DIR)/src/tls.c \
  $(WOLFSSL_DIR)/src/tls13.c \
  $(WOLFSSL_DIR)/src/wolfio.c

# wolfCrypt core (minimal set for TLS 1.3 and ML-KEM)
C_SOURCES += \
  $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/kdf.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/logging.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/misc.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sha.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sha3.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/md5.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/signature.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/sp_cortexm.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/port/st/stm32.c

# ML-KEM (Kyber) sources
C_SOURCES += \
  $(WOLFSSL_DIR)/wolfcrypt/src/ext_mlkem.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/wc_mlkem.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/wc_mlkem_poly.c \
  $(WOLFSSL_DIR)/wolfcrypt/src/port/arm/thumb2-mlkem-asm_c.c

#######################################
# PQClean integration (SPHINCS+-SHA2-128f-simple)
#######################################

# Enable PQClean-based SPHINCS+
C_DEFS += -DHAVE_PQCLEAN -DSPHINCS_ALG_NAME=\"Sphincs+-SHA2-128f-simple\"

# PQClean include directories
PQCLEAN_DIR := $(DIR_ROOT)/../PQClean
PQCLEAN_SIG_DIR := $(PQCLEAN_DIR)/crypto_sign/sphincs-sha2-128f-simple/clean
PQCLEAN_DIL_DIR := $(PQCLEAN_DIR)/crypto_sign/ml-dsa-65/clean
PQCLEAN_KEM_DIR := $(PQCLEAN_DIR)/crypto_kem/ml-kem-768/clean
PQCLEAN_COMMON_DIR := $(PQCLEAN_DIR)/common

C_INCLUDES += -I$(PQCLEAN_SIG_DIR)
C_INCLUDES += -I$(PQCLEAN_DIL_DIR)
C_INCLUDES += -I$(PQCLEAN_KEM_DIR)
C_INCLUDES += -I$(PQCLEAN_COMMON_DIR)

# PQClean SPHINCS+-SHA2-128f-simple (clean) sources
C_SOURCES += \
  $(PQCLEAN_SIG_DIR)/address.c \
  $(PQCLEAN_SIG_DIR)/context_sha2.c \
  $(PQCLEAN_SIG_DIR)/fors.c \
  $(PQCLEAN_SIG_DIR)/hash_sha2.c \
  $(PQCLEAN_SIG_DIR)/merkle.c \
  $(PQCLEAN_SIG_DIR)/sign.c \
  $(PQCLEAN_SIG_DIR)/thash_sha2_simple.c \
  $(PQCLEAN_SIG_DIR)/utils.c \
  $(PQCLEAN_SIG_DIR)/utilsx1.c \
  $(PQCLEAN_SIG_DIR)/wots.c \
  $(PQCLEAN_SIG_DIR)/wotsx1.c

# PQClean ML-DSA-65 (Dilithium3) clean sources
C_SOURCES += \
  $(PQCLEAN_DIL_DIR)/ntt.c \
  $(PQCLEAN_DIL_DIR)/packing.c \
  $(PQCLEAN_DIL_DIR)/poly.c \
  $(PQCLEAN_DIL_DIR)/polyvec.c \
  $(PQCLEAN_DIL_DIR)/reduce.c \
  $(PQCLEAN_DIL_DIR)/rounding.c \
  $(PQCLEAN_DIL_DIR)/sign.c \
  $(PQCLEAN_DIL_DIR)/symmetric-shake.c

# PQClean ML-KEM-768 (Kyber768) clean sources
C_SOURCES += \
  $(PQCLEAN_KEM_DIR)/cbd.c \
  $(PQCLEAN_KEM_DIR)/indcpa.c \
  $(PQCLEAN_KEM_DIR)/kem.c \
  $(PQCLEAN_KEM_DIR)/ntt.c \
  $(PQCLEAN_KEM_DIR)/poly.c \
  $(PQCLEAN_KEM_DIR)/polyvec.c \
  $(PQCLEAN_KEM_DIR)/reduce.c \
  $(PQCLEAN_KEM_DIR)/symmetric-shake.c \
  $(PQCLEAN_KEM_DIR)/verify.c

# PQClean SHA2 and FIPS202 (portable C)
C_SOURCES += \
  $(PQCLEAN_COMMON_DIR)/sha2.c \
  $(PQCLEAN_COMMON_DIR)/fips202.c

.PHONY: FORCE
FORCE:



# default action: build all
all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin


#######################################

# list of objects (preserve directory structure to avoid name collisions)
OBJECTS = $(addprefix $(BUILD_DIR)/,$(C_SOURCES:.c=.o))
vpath %.c $(sort $(dir $(C_SOURCES)))
# list of ASM program objects
OBJECTS += $(addprefix $(BUILD_DIR)/,$(ASM_SOURCES:.s=.o))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile user_settings.h $(if $(USE_LIBOQS),$(LIBOQS_A))
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(basename $@).lst $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile
	@mkdir -p $(dir $@)
	$(AS) -c $(CFLAGS) $< -o $@

ifeq ($(USE_LIBOQS),1)
$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS) $(LIBOQS_A) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@
else
$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@
endif

$(BUILD_DIR)/%.hex: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(HEX) $< $@
	
$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(BIN) $< $@	
	
$(BUILD_DIR):
	mkdir $@		

#######################################

.PHONY: clean
clean:
	-rm -fR $(BUILD_DIR)

.PHONY: flash
flash:
	#-st-flash --reset write $(BUILD_DIR)/$(TARGET).bin 0x8000000
	-st-flash --format ihex --reset write $(BUILD_DIR)/$(TARGET).hex


.PHONY: erase
erase:
	-st-flash erase
  
#######################################
# -include $(wildcard $(BUILD_DIR)/*.d)

