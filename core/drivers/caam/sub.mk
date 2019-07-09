incdirs-y += include

subdirs-$(CFG_LS) += hal/ls
subdirs-$(CFG_MX6)$(CFG_MX7)$(CFG_MX7ULP) += hal/imx_6_7
subdirs-$(CFG_MX8M)$(CFG_MX8MM)$(CFG_MX8MN) += hal/imx_8m
subdirs-y += utils

srcs-y += caam_pwr.c
srcs-y += caam_ctrl.c
srcs-y += caam_jr.c
srcs-y += caam_rng.c
srcs-y += caam_desc.c
srcs-$(CFG_CRYPTO_SM_HW)        += caam_sm.c
srcs-$(CFG_CRYPTO_HASH_HW)      += caam_hash.c
srcs-$(CFG_CRYPTO_MP_HW)        += caam_mp.c
srcs-$(CFG_CRYPTO_BLOB_HW)      += caam_blob.c
subdirs-$(CFG_CRYPTO_CIPHER_HW) += cipher
subdirs-$(CFG_CRYPTO_PK_HW)     += acipher

