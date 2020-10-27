incdirs-y += ../../include
incdirs-y += ../$(CAAM_HAL_DIR)
incdirs-y += .

srcs-$(CFG_DT) += hal_cfg_dt.c
srcs-y += hal_cfg.c
srcs-y += hal_rng.c
srcs-y += hal_jr.c
srcs-y += hal_ctrl.c
ifeq ($(CFG_CRYPTO_DRV_SM),y)
srcs-y += hal_sm.c
srcs-$(CFG_DT) += hal_sm_dt.c
endif
