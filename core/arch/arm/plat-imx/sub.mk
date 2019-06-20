global-incdirs-y += .

srcs-y += main.c
srcs-$(CFG_MX6)$(CFG_MX7)$(CFG_MX7ULP)$(CFG_MX8M)$(CFG_MX8MM)$(CFG_MX8MN) += imx-common.c
srcs-$(CFG_MX6)$(CFG_MX7) += imx_src.c mmdc.c
srcs-$(CFG_MX7) += gpcv2.c
srcs-$(CFG_MX6)$(CFG_MX7)$(CFG_MX7ULP)$(CFG_MX8M)$(CFG_MX8MM)$(CFG_MX8MN) += imx_ocotp.c

srcs-$(_CFG_CRYPTO_WITH_HUK) += imx_huk.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
$(call force,CFG_PM_ARM32,y)
asm-defines-y += imx_pm_asm_defines.c
endif

ifneq (,$(filter y, $(CFG_MX6Q) $(CFG_MX6QP) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
	$(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX)))
srcs-y += a9_plat_init.S
endif

ifneq (,$(filter y, $(CFG_MX7) $(CFG_MX7ULP) $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
endif

srcs-$(CFG_SM_PLATFORM_HANDLER) += sm_platform_handler.c
srcs-$(CFG_TZC380) += tzasc.c
srcs-$(CFG_DT) += imx_dt.c
srcs-$(CFG_CSU) += imx_csu.c
srcs-$(CFG_SCU) += imx_scu.c
srcs-$(CFG_IMX_OCRAM) += imx_ocram.c
srcs-$(CFG_XRDC) += xrdc.c
subdirs-$(CFG_PSCI_ARM32) += pm

# Build the busfreq module
subdirs-$(CFG_BUSFREQ) += busfreq

# Build the imx-PTA
subdirs-y += pta
