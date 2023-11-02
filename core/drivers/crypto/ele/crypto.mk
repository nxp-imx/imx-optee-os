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

# Issues in the ELE FW prevent OPTEE and Kernel from using
# the RNG concurrently at runtime. To prevent any issue,
# use the software RNG instead in OPTEE.
CFG_WITH_SOFTWARE_PRNG ?= y

endif # CFG_IMX_ELE
