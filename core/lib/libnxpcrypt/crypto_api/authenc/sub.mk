
srcs-y += authenc.c
srcs-$(CFG_CRYPTO_CCM) += aes_ccm.c
srcs-$(CFG_CRYPTO_GCM) += aes_gcm.c
