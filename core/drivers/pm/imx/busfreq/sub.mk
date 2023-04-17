incdirs-y += ./..

srcs-y += busfreq.c utils.S

srcs-$(CFG_MX6) += busfreq_imx6.c busfreq_ddr3_imx6.S busfreq_lpddr2_imx6.S
asm-defines-$(CFG_MX6) += busfreq_imx6_defines.c

srcs-$(CFG_MX7) += busfreq_imx7.c busfreq_asm_imx7.S
asm-defines-$(CFG_MX7) += busfreq_imx7_defines.c
