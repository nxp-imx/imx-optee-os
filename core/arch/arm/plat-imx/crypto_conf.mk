#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug Trace
#
# DBG_TRACE_HAL    BIT32(0)  // HAL trace
# DBG_TRACE_CTRL   BIT32(1)  // Controller trace
# DBG_TRACE_MEM    BIT32(2)  // Memory utility trace
# DBG_TRACE_SGT    BIT32(3)  // Scatter Gather trace
# DBG_TRACE_PWR    BIT32(4)  // Power trace
# DBG_TRACE_JR     BIT32(5)  // Job Ring trace
# DBG_DESC_JR      BIT32(6)  // Job Ring dump descriptor
# DBG_TRACE_RNG    BIT32(7)  // RNG trace
# DBG_DESC_RNG     BIT32(8)  // RNG dump descriptor
# DBG_TRACE_HASH   BIT32(9)  // Hash trace
# DBG_DESC_HASH    BIT32(10) // Hash dump descriptor
# DBG_BUF_HASH     BIT32(11) // Hash dump Buffer
# DBG_TRACE_BLOB   BIT32(12) // BLOB trace
# DBG_DESC_BLOB    BIT32(13) // BLOB dump descriptor
# DBG_BUF_BLOB     BIT32(14) // BLOB dump Buffer
# DBG_TRACE_CIPHER BIT32(15) // Cipher trace
# DBG_DESC_CIPHER  BIT32(16) // Cipher dump descriptor
# DBG_BUF_CIPHER   BIT32(17) // Cipher dump Buffer
# DBG_TRACE_ECC    BIT32(18) // ECC trace
# DBG_DESC_ECC     BIT32(19) // ECC dump descriptor
# DBG_BUF_ECC      BIT32(20) // ECC dump Buffer
# DBG_TRACE_RSA    BIT32(21) // RSA trace
# DBG_DESC_RSA     BIT32(22) // RSA dump descriptor
# DBG_BUF_RSA      BIT32(23) // RSA dump Buffer
CFG_CAAM_DBG ?= 0x2

#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x1000)

$(call force, CFG_JR_INDEX,0)  # Default JR index used
$(call force, CFG_JR_INT,137)  # Default JR IT Number (105 + 32) = 137

#
# Enable HUK CAAM Generation
#
CFG_NXP_CAAM_HUK_DRV ?= y

#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER), y)

$(call force, CFG_NXP_CAAM_RUNTIME_JR, y)

#
# Definition of all HW accelerations for all i.MX
#
$(call force, CFG_NXP_CAAM_RNG_DRV, y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)

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


# Definition of the HW and Cryto Driver Algorithm supported by all i.MX
$(eval $(call cryphw-enable-drv-hw, HASH))
$(eval $(call cryphw-enable-drv-hw, CIPHER))

ifneq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) \
	$(CFG_MX6S) $(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)), y)
$(eval $(call cryphw-enable-drv-hw, ECC))
$(eval $(call cryphw-enable-drv-hw, RSA))
endif

$(call force, CFG_NXP_CAAM_ACIPHER_DRV, $(call cryphw-one-enabled, ECC RSA))

#
# Enable Cryptographic Driver interface
#
CFG_CRYPTO_DRV_ACIPHER ?= $(CFG_NXP_CAAM_ACIPHER_DRV)

endif
