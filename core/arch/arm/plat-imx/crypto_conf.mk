#
# Define the cryptographic algorithm to be built
#

ifeq ($(CFG_IMXCRYPT), y)
$(call force, CFG_CRYPTO_WITH_HW_ACC,y)
#
# Define the TomCrypt as the Software library used to do
# algorithm not done by the HW
#
$(call force, CFG_IMXCRYPT_TOMCRYPT,y)

ifeq ($(CFG_IMXCRYPT_TOMCRYPT), y)
# Don't enable LTC GCM mode which seems to be slower than
# Core/Crypto ones
$(call force, CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB,n)
endif

#
# Definition of all HW accelerations for all i.MX
#
$(call force, CFG_CRYPTO_RNG_HW,y)
ifeq ($(CFG_CRYPTO_RNG_HW), y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)
else
$(call force, CFG_WITH_SOFTWARE_PRNG,y)
endif


$(call force, CFG_CRYPTO_HASH_HW,y)
$(call force, CFG_CRYPTO_CIPHER_HW,y)

$(call force, CFG_CRYPTO_CCM_HW,n)
$(call force, CFG_CRYPTO_GCM_HW,n)

$(call force, CFG_CRYPTO_PKCS_HW,n)

$(call force, CFG_CRYPTO_BLOB_HW,y)

ifeq ($(filter y, $(CFG_MX6UL)$(CFG_MX7)$(CFG_MX8MM)$(CFG_MX8M)),y)
# Definition of the Asymmetric Cipher supported by HW
$(call force, CFG_CRYPTO_RSA_HW,y)
$(call force, CFG_CRYPTO_DSA_HW,n)
$(call force, CFG_CRYPTO_DH_HW,n)
$(call force, CFG_CRYPTO_ECC_HW,y)
endif

$(call force, CFG_CRYPTO_CMAC_HW,y)

#
# Enable Manufacturing Protection if the platform support it
# CFG_CRYPTO_MP_HW enables the manufacturing protection functionnalities
# _CFG_CRYPTO_WITH_MP enables the generic crypto api
# CFG_MANUFACT_PROTEC_PTA enables the MP PTA
# CFG_MBEDTLS_MP enables the setting of the public key type
#
ifeq ($(filter y, $(CFG_MX6UL)$(CFG_MX7)), y)
CFG_CRYPTO_MP_HW ?= y
_CFG_CRYPTO_WITH_MP ?= y
CFG_MANUFACT_PROTEC_PTA ?= y
CFG_MBEDTLS_MP ?= y
endif

# Definition of the HASH Algorithm supported by all i.MX
ifeq ($(CFG_CRYPTO_HASH_HW), y)
CFG_CRYPTO_HASH_HW_MD5    ?= y
CFG_CRYPTO_HASH_HW_SHA1   ?= y
CFG_CRYPTO_HASH_HW_SHA224 ?= y
CFG_CRYPTO_HASH_HW_SHA256 ?= y
CFG_CRYPTO_HASH_HW_SHA384 ?= n
CFG_CRYPTO_HASH_HW_SHA512 ?= n
endif

cryp-one-hw-enabled =						\
	$(call cfg-one-enabled, $(foreach cfg, $(1),		\
               CFG_CRYPTO_$(strip $(cfg))_HW))

cryp-full-hw-enabled =								\
	$(call cfg-all-enabled,							\
		$(patsubst %, CFG_CRYPTO_$(strip $(1))_HW_%, $(strip $(2))))

$(call force, CFG_CRYPTO_HMAC_FULL_HW, $(call cryp-full-hw-enabled, HASH, \
	MD5 SHA1 SHA224 SHA256 SHA384 SHA512))


$(call force, CFG_CRYPTO_AUTHENC_HW, $(call cryp-one-hw-enabled, CCM GCM))

$(call force, CFG_CRYPTO_PK_HW, $(call cryp-one-hw-enabled, RSA ECC DH DSA))

$(call force, _CFG_CRYPTO_WITH_HUK, $(call cryp-one-hw-enabled, BLOB))
endif
