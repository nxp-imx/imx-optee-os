incdirs-y += .

subdirs-$(CFG_BUSFREQ) += busfreq
subdirs-y += cpuidle
subdirs-y += suspend

srcs-$(CFG_PSCI_ARM32) += psci.c imx_ocram.c
srcs-$(CFG_MX7) += pm-imx7.c gpcv2.c
srcs-$(CFG_MX6) += pm-imx6.c
srcs-$(CFG_MX6)$(CFG_MX7) += src.c mmdc.c
srcs-$(CFG_MX7ULP) += pm-imx7ulp.c
srcs-$(CFG_MX8M)$(CFG_MX8ULP) += pm-imx8.c

asm-defines-y += imx_pm_asm_defines.c
