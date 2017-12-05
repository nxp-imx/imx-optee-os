global-incdirs-y += .
global-incdirs-y += registers

ifneq (,$(filter y, $(CFG_MX6) $(CFG_MX7)))
srcs-y += main.c
endif

srcs-$(CFG_MX7ULP) += imx7ulp.c a7_plat_init.S

srcs-$(CFG_MX6)$(CFG_MX7) += imx-common.c mmdc.c

srcs-$(CFG_PL310) += imx_pl310.c
ifeq ($(CFG_PSCI_ARM32),y)
srcs-$(CFG_MX6)$(CFG_MX7) += gpcv2.c
srcs-$(CFG_MX6) += pm/imx6_suspend.c pm/psci-suspend-imx6.S pm/pm-imx6.c
srcs-$(CFG_MX6UL) += pm/cpuidle-imx6ul.c pm/imx6ul_lowpower_idle.S
srcs-$(CFG_MX6ULL) += pm/cpuidle-imx6ul.c pm/imx6ull_lowpower_idle.S
srcs-$(CFG_MX6SX) += pm/cpuidle-imx6sx.c pm/imx6sx_lowpower_idle.S
srcs-$(CFG_MX6SL) += pm/cpuidle-imx6sl.c pm/imx6sl_lowpower_idle.S
srcs-$(CFG_MX7) += pm/pm-imx7.c pm/psci-suspend-imx7.S pm/imx7_suspend.c pm/cpuidle-imx7d.c pm/imx7d_low_power_idle.S
srcs-$(CFG_MX7ULP) += pm/pm-imx7ulp.c pm/psci-suspend-imx7ulp.S pm/imx7ulp_suspend.c
$(call force,CFG_PM_ARM32,y)
endif

cflags-pm/psci.c-y += -Wno-suggest-attribute=noreturn

ifneq (,$(filter y, $(CFG_MX6SX) $(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6QP) \
	$(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL)))
srcs-y += a9_plat_init.S
endif

ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
srcs-y += a7_plat_init.S
endif

srcs-$(CFG_MX7) += a7_plat_init.S
srcs-$(CFG_TZC380) += tzasc.c

srcs-$(CFG_CSU) += imx_csu.c
srcs-$(CFG_SCU) += imx_scu.c

## Place here the objects initialize as service_init
## File order give the order of the initialization
srcs-$(CFG_IMX_OCRAM) += imx_ocram.c
srcs-$(CFG_PSCI_ARM32) += pm/psci.c
