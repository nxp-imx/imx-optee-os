global-incdirs-y += .
srcs-y += main.c imx-common.c

srcs-$(CFG_PL310) += imx_pl310.c

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6QP) $(CFG_MX6D) $(CFG_MX6DL) \
	$(CFG_MX6S) $(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)))
srcs-y += a9_plat_init.S
endif

ifneq (,$(filter y, $(CFG_MX7) $(CFG_MX7ULP) $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
endif

srcs-$(CFG_TZC380) += tzc380.c
srcs-$(CFG_SM_PLATFORM_HANDLER) += sm_platform_handler.c
