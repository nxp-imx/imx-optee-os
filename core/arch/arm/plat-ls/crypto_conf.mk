#
# Define the cryptographic algorithm to be built
#
$(call force, CFG_JR_BLOCK_SIZE,0x10000)

ifeq ($(PLATFORM_FLAVOR),ls1046ardb)
$(call force,CFG_JR_IDX,0x2)
$(call force,CFG_JR_IRQ_ID,105)
$(call force,CFG_PHYS_64BIT,y)
$(call force,CFG_NXP_SEC_BE,y)
endif

ifeq ($(CFG_NXPCRYPT), y)
$(call force, CFG_CRYPTO_WITH_HW_ACC,y)
#
# Define the TomCrypt as the Software library used to do
# algorithm not done by the HW
#
$(call force, CFG_NXPCRYPT_TOMCRYPT,y)

ifeq ($(CFG_NXPCRYPT_TOMCRYPT), y)
# Don't enable LTC GCM mode which seems to be slower than
# Core/Crypto ones
$(call force, CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB,n)
endif

#
# Definition of all HW accelerations for all LS
#
$(call force, CFG_CRYPTO_RNG_HW,y)
ifeq ($(CFG_CRYPTO_RNG_HW),y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)
else
$(call force, CFG_WITH_SOFTWARE_PRNG,y)
endif

$(call force, CFG_CRYPTO_HASH_HW,y)
$(call force, CFG_CRYPTO_CIPHER_HW,y)

$(call force, CFG_CRYPTO_CCM_HW,n)
$(call force, CFG_CRYPTO_GCM_HW,n)

$(call force, CFG_CRYPTO_PKCS_HW,n)

# Definition of the Asymmetric Cipher supported by HW
$(call force, CFG_CRYPTO_RSA_HW,y)
$(call force, CFG_CRYPTO_DSA_HW,n)
$(call force, CFG_CRYPTO_DH_HW,n)
$(call force, CFG_CRYPTO_ECC_HW,y)

$(call force, CFG_CRYPTO_CMAC_HW,y)

# Definition of the HASH Algorithm supported by all LS
ifeq ($(CFG_CRYPTO_HASH_HW), y)
CFG_CRYPTO_HASH_HW_MD5    ?= n
CFG_CRYPTO_HASH_HW_SHA1   ?= y
CFG_CRYPTO_HASH_HW_SHA224 ?= y
CFG_CRYPTO_HASH_HW_SHA256 ?= y
CFG_CRYPTO_HASH_HW_SHA384 ?= y
CFG_CRYPTO_HASH_HW_SHA512 ?= y
endif

cryp-one-hw-enabled =                                               \
	$(call cfg-one-enabled, $(foreach cfg, $(1),                    \
               CFG_CRYPTO_$(strip $(cfg))_HW))

cryp-full-hw-enabled =												\
	$(call cfg-all-enabled, 										\
		$(patsubst %, CFG_CRYPTO_$(strip $(1))_HW_%, $(strip $(2))))

$(call force, CFG_CRYPTO_HMAC_FULL_HW, $(call cryp-full-hw-enabled, HASH, \
	MD5 SHA1 SHA224 SHA256 SHA384 SHA512))


$(call force, CFG_CRYPTO_AUTHENC_HW, $(call cryp-one-hw-enabled, CCM GCM))

$(call force, CFG_CRYPTO_PK_HW, $(call cryp-one-hw-enabled, RSA ECC DH DSA))
endif
