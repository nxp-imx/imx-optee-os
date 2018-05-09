
global-incdirs-y += include

srcs-y += tee_provider.c

subdirs-y += rng

subdirs-$(_CFG_CRYPTO_WITH_CIPHER)  += cipher
subdirs-$(_CFG_CRYPTO_WITH_HASH)    += hash
subdirs-$(_CFG_CRYPTO_WITH_MAC)     += mac
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += bignum
subdirs-$(CFG_CRYPTO_RSA)           += rsa
