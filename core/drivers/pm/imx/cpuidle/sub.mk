incdirs-y += ./..
srcs-$(CFG_MX7) += cpuidle-imx7d.c psci-cpuidle-imx7.S
srcs-$(CFG_MX6UL) += psci-cpuidle-imx6ul.S cpuidle-imx6ul.c
srcs-$(CFG_MX6ULL) += psci-cpuidle-imx6ull.S cpuidle-imx6ul.c
srcs-$(CFG_MX6SX) += psci-cpuidle-imx6sx.S cpuidle-imx6sx.c
srcs-$(CFG_MX6SL) += psci-cpuidle-imx6sl.S cpuidle-imx6sl.c
srcs-$(CFG_MX6SLL) += psci-cpuidle-imx6sll.S cpuidle-imx6sll.c
