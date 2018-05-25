#
# Define the cryptographic algorithm to be built
#

ifeq ($(CFG_IMX_CAAM), y)
$(call force, CFG_CRYPTO_WITH_HW_ACC,y)
$(call force, CFG_IMXCRYPT,y)
endif

ifeq ($(CFG_IMXCRYPT), y)
$(call force, CFG_CRYPTO_RNG_HW,y)
$(call force, CFG_CRYPTO_HASH_HW,y)
$(call force, CFG_CRYPTO_CIPHER_HW,y)

# Ciphers
$(call force, CFG_CRYPTO_DES,n)

# Cipher block modes
$(call force, CFG_CRYPTO_CBC,n)
$(call force, CFG_CRYPTO_CTR,n)
$(call force, CFG_CRYPTO_CTS,n)
$(call force, CFG_CRYPTO_XTS,n)

# Message authentication codes
$(call force, CFG_CRYPTO_CMAC,n)
$(call force, CFG_CRYPTO_CBC_MAC,n)

# Hashes
$(call force, CFG_CRYPTO_MD5,n)
$(call force, CFG_CRYPTO_SHA1,n)
$(call force, CFG_CRYPTO_SHA224,n)
$(call force, CFG_CRYPTO_SHA384,n)
$(call force, CFG_CRYPTO_SHA512,n)

# Asymmetric ciphers
$(call force, CFG_CRYPTO_DSA,n)
$(call force, CFG_CRYPTO_DH,n)
$(call force, CFG_CRYPTO_ECC,n)

# Authenticated encryption
$(call force, CFG_CRYPTO_CCM,n)
# Default uses the OP-TEE internal AES-GCM implementation
#$(call force, CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB,y)

#### NEEDED TO LOAD TA
$(call force, CFG_CRYPTO_RSA,y)
$(call force, CFG_CRYPTO_GCM,y)
#$(call force, CFG_CRYPTO_AES,n)
#$(call force, CFG_CRYPTO_ECB,n)
#$(call force, CFG_CRYPTO_HMAC,n)
#$(call force, CFG_CRYPTO_SHA256,n)


endif

