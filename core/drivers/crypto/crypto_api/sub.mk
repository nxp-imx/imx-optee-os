srcs-y += drvcrypt.c

subdirs-$(CFG_CRYPTO_DRV_HASH)   += hash
subdirs-$(CFG_CRYPTO_DRV_CIPHER) += cipher
