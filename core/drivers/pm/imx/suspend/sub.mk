incdirs-y += ./..

srcs-$(CFG_MX7) += psci-suspend-imx7.S imx7_suspend.c
srcs-$(CFG_MX6) += imx6_suspend.c psci-suspend-imx6.S
srcs-$(CFG_MX7ULP) += psci-suspend-imx7ulp.S imx7ulp_suspend.c
