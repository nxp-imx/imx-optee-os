
incdirs-y += ../registers

srcs-y += busfreq.c

srcs-$(CFG_MX6) += busfreq_imx6.c
asm-defines-$(CFG_MX6) += busfreq_imx6_defines.c
srcs-$(CFG_MX6) += busfreq_ddr3_imx6.S
srcs-$(CFG_MX6) += busfreq_lpddr2_imx6.S
