ifeq ($(CFG_IMX_ELE),y)
CFG_IMX_ELE_ECC_DRV ?= n
CFG_IMX_ELE_ACIPHER_DRV ?= $(CFG_IMX_ELE_ECC_DRV)

# If IMX ELE Driver is supported, the Crypto Driver interfacing
# it with generic crypto API can be enabled.
CFG_CRYPTO_DRIVER ?= $(CFG_IMX_ELE_ACIPHER_DRV)

ifeq ($(CFG_CRYPTO_DRIVER),y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0
CFG_CRYPTO_DRV_ECC ?= $(CFG_IMX_ELE_ECC_DRV)
CFG_CRYPTO_DRV_ACIPHER ?= $(CFG_IMX_ELE_ACIPHER_DRV)
endif # CFG_CRYPTO_DRIVER

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx93-flavorlist)))
# Disable software RNG when ELE driver is enabled
$(call force, CFG_WITH_SOFTWARE_PRNG,n,Mandated by CFG_IMX_ELE)
endif
endif # CFG_IMX_ELE
