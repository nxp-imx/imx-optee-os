
incdirs-y += ../include

srcs-$(CFG_CRYPTO_RSA) += rsa.c
srcs-$(CFG_CRYPTO_DSA) += dsa.c
srcs-$(CFG_CRYPTO_ECC) += ecc.c
srcs-$(CFG_CRYPTO_DH)  += dh.c
