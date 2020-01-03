incdirs-y += include

subdirs-y += hal
subdirs-y += utils
subdirs-y += blob

srcs-y += caam_pwr.c
srcs-y += caam_ctrl.c
srcs-y += caam_jr.c
srcs-y += caam_rng.c
srcs-y += caam_desc.c
ifneq ( ,$(filter y, $(CFG_NXP_CAAM_HASH_DRV) $(CFG_NXP_CAAM_HMAC_DRV)))
subdirs-y += hash
endif
ifneq ( ,$(filter y, $(CFG_NXP_CAAM_CIPHER_DRV) $(CFG_NXP_CAAM_CMAC_DRV)))
subdirs-$(CFG_NXP_CAAM_CIPHER_DRV) += cipher
endif
subdirs-$(CFG_NXP_CAAM_ACIPHER_DRV) += acipher
subdirs-$(CFG_NXP_CAAM_MP_DRV) += mp
subdirs-$(CFG_NXP_CAAM_SM_DRV) += sm
