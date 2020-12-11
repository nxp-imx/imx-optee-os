#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug: define 3x32 bits value (same bit used to debug a module)
# CFG_DBG_CAAM_TRACE  Module print trace
# CFG_DBG_CAAM_DESC   Module descriptor dump
# CFG_DBG_CAAM_BUF    Module buffer dump
#
# DBG_HAL    BIT32(0)  // HAL trace
# DBG_CTRL   BIT32(1)  // Controller trace
# DBG_MEM    BIT32(2)  // Memory utility trace
# DBG_SGT    BIT32(3)  // Scatter Gather trace
# DBG_PWR    BIT32(4)  // Power trace
# DBG_JR     BIT32(5)  // Job Ring trace
# DBG_RNG    BIT32(6)  // RNG trace
# DBG_HASH   BIT32(7)  // Hash trace
# DBG_RSA    BIT32(8)  // RSA trace
# DBG_CIPHER BIT32(9)  // Cipher trace
CFG_DBG_CAAM_TRACE ?= BIT32(1)
CFG_DBG_CAAM_DESC ?= 0x0
CFG_DBG_CAAM_BUF ?= 0x0

$(call force, CFG_CAAM_SIZE_ALIGN,4)

# Enable the BLOB module used for the hardware unique key
CFG_NXP_CAAM_BLOB_DRV ?= y

#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force,CFG_JR_BLOCK_SIZE,0x10000)
$(call force,CFG_JR_INDEX,2)  # Default JR index used

ifneq (,$(filter $(PLATFORM_FLAVOR),ls1012afrwy))
$(call force,CFG_CAAM_BIG_ENDIAN,y)
$(call force,CFG_JR_INT,105)  # Default JR IT Number (73 + 32) = 105
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1012ardb))
$(call force,CFG_CAAM_BIG_ENDIAN,y)
$(call force,CFG_JR_INT,105)  # Default JR IT Number (73 + 32) = 105
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1021atwr))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT,137)
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1021aqds))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT,137)
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1043ardb))
$(call force,CFG_CAAM_BIG_ENDIAN,y)
$(call force,CFG_JR_INT,105)  # Default JR IT Number (73 + 32) = 105
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1046ardb))
$(call force,CFG_CAAM_BIG_ENDIAN,y)
$(call force,CFG_JR_INT,137)  # Default JR IT Number (105 + 32) = 137
# Linux indicate the IRQ is 73 + 32 = 105
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1088ardb))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT,175)  # Default JR IT Number (142 + 32) = 175
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls2088ardb))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT,175)  # Default JR IT Number (142 + 32) = 175
else ifneq (,$(filter $(PLATFORM_FLAVOR),ls1028ardb))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT,175)  # Default JR IT Number (142 + 32) = 175
else ifneq (,$(filter $(PLATFORM_FLAVOR),lx2160aqds))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT, 174)
# Linux indicate the IRQ is 175
$(call force,CFG_NB_JOBS_QUEUE, 80)  # Default JR index used
else ifneq (,$(filter $(PLATFORM_FLAVOR),lx2160ardb))
$(call force,CFG_CAAM_LITTLE_ENDIAN,y)
$(call force,CFG_JR_INT, 174)
# Linux indicate the IRQ is 175
$(call force,CFG_NB_JOBS_QUEUE, 80)  # Default JR index used
endif

#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER),y)

$(call force, CFG_NXP_CAAM_RUNTIME_JR, y)

#
# Definition of all HW accelerations for all LS
#
$(call force, CFG_NXP_CAAM_RNG_DRV, n)
$(call force, CFG_WITH_SOFTWARE_PRNG,y)

# Force to 'y' the CFG_NXP_CAAM_xxx_DRV to enable the CAAM HW driver
# and enable the associated CFG_CRYPTO_DRV_xxx Crypto driver
# API
#
# Example: Enable CFG_CRYPTO_DRV_HASH and CFG_NXP_CAAM_HASH_DRV
#     $(eval $(call cryphw-enable-drv-hw, HASH))
define cryphw-enable-drv-hw
_var := $(strip $(1))
$$(call force, CFG_NXP_CAAM_$$(_var)_DRV, y)
$$(call force, CFG_CRYPTO_DRV_$$(_var), y)
endef

# Return 'y' if at least one of the variable
# CFG_CRYPTO_xxx_HW is 'y'
cryphw-one-enabled = $(call cfg-one-enabled, \
                        $(foreach v,$(1), CFG_NXP_CAAM_$(v)_DRV))

# Definition of the HW and Cryto Driver Algorithm supported by all LS
# HASH, CIPHER, HMAC, CMAC, RSA support is disabled

# Define the RSA Private Key Format used by the CAAM
#   Format #1: (n, d)
#   Format #2: (p, q, d)
#   Format #3: (p, q, dp, dq, qp)
CFG_NXP_CAAM_RSA_KEY_FORMAT ?= 3

$(call force, CFG_NXP_CAAM_ACIPHER_DRV, $(call cryphw-one-enabled, RSA))
$(call force, CFG_CRYPTO_DRV_MAC, $(call cryphw-one-enabled, HMAC CMAC))

#
# Enable Cryptographic Driver interface
#
CFG_CRYPTO_DRV_ACIPHER ?= $(CFG_NXP_CAAM_ACIPHER_DRV)

endif
