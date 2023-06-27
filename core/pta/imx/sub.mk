srcs-$(CFG_IMX_DIGPROG) += digprog.c
srcs-$(call cfg-one-enabled,CFG_IMX_OCOTP CFG_IMX_ELE) += ocotp.c
srcs-$(CFG_NXP_CAAM_MP_DRV) += manufacturing_protection.c
srcs-$(CFG_NXP_CAAM_DEK_DRV) += dek_blob.c
srcs-$(CFG_IMX_TRUSTED_ARM_CE) += trusted_arm_ce.c
