
incdirs-y += include

srcs-y += init.c
srcs-y += init_mpa_pool.c

subdirs-y += utils
subdirs-y += rng
subdirs-$(_CFG_CRYPTO_WITH_CIPHER)  += cipher
subdirs-$(_CFG_CRYPTO_WITH_ACIPHER) += acipher
subdirs-$(_CFG_CRYPTO_WITH_HASH)    += hashes
subdirs-$(_CFG_CRYPTO_WITH_HASH)    += mac
subdirs-$(_CFG_CRYPTO_WITH_AUTHENC) += authenc
