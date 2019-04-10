
srcs-y += tee_provider.c

subdirs-y += math

subdirs-$(_CFG_CRYPTO_WITH_CIPHER)  += cipher
subdirs-$(_CFG_CRYPTO_WITH_HASH)    += hash
subdirs-$(_CFG_CRYPTO_WITH_MAC)     += mac
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += bignum
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += acipher
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += oid
subdirs-$(_CFG_CRYPTO_WITH_AUTHENC) += authenc
subdirs-$(_CFG_CRYPTO_WITH_MP)      += mp
subdirs-$(_CFG_CRYPTO_WITH_HUK)     += huk
subdirs-$(_CFG_CRYPTO_WITH_BLOB)    += blob
