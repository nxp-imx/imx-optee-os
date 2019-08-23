/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef __IMX_PM_H
#define __IMX_PM_H

#include <stdint.h>

#define MX7_DDRC_NUM			32
#define MX7_DDRC_PHY_NUM		16

#define SUSPEND_OCRAM_SIZE		0x1000
#define LOWPOWER_IDLE_OCRAM_SIZE	0x1000

#define SUSPEND_OCRAM_OFFSET		0x0
#define LOWPOWER_IDLE_OCRAM_OFFSET	0x1000

/*
 * Except i.MX6SX only 16KB ocram_s available, others use 16KB offset.
 */
#define IRAM_TBL_OFFSET			0x4000

#ifndef __ASSEMBLER__
#include <sm/sm.h>

/* The structure is used for suspend and low power idle */
struct imx7_pm_info {
	uint32_t	m4_reserve0;
	uint32_t	m4_reserve1;
	uint32_t	m4_reserve2;
	vaddr_t		va_base;	/* va of pm_info */
	paddr_t		pa_base;	/* pa of pm_info */
	uintptr_t	entry;
	paddr_t		tee_resume;
	uint32_t	ddr_type;
	uint32_t	pm_info_size;
	paddr_t		ddrc_pa_base;
	vaddr_t		ddrc_va_base;
	paddr_t		ddrc_phy_pa_base;
	vaddr_t		ddrc_phy_va_base;
	paddr_t		src_pa_base;
	vaddr_t		src_va_base;
	paddr_t		iomuxc_gpr_pa_base;
	vaddr_t		iomuxc_gpr_va_base;
	paddr_t		ccm_pa_base;
	vaddr_t		ccm_va_base;
	paddr_t		gpc_pa_base;
	vaddr_t		gpc_va_base;
	paddr_t		snvs_pa_base;
	vaddr_t		snvs_va_base;
	paddr_t		anatop_pa_base;
	vaddr_t		anatop_va_base;
	paddr_t		lpsr_pa_base;
	vaddr_t		lpsr_va_base;
	paddr_t		gic_pa_base;
	vaddr_t		gic_va_base;
	uint32_t	ttbr0;
	uint32_t	ttbr1;
	uint32_t	num_online_cpus;
	uint32_t	num_lpi_cpus;
	uint32_t	val;
	uint32_t	flag0;
	uint32_t	flag1;
	uint32_t	ddrc_num;
	uint32_t	ddrc_val[MX7_DDRC_NUM][2];
	uint32_t	ddrc_phy_num;
	uint32_t	ddrc_phy_val[MX7_DDRC_NUM][2];
} __aligned(8);

struct imx7_pm_data {
	uint32_t ddr_type;
	uint32_t ddrc_num;
	uint32_t (*ddrc_offset)[2];
	uint32_t ddrc_phy_num;
	uint32_t (*ddrc_phy_offset)[2];
};

/* IMX6 Power initialization functions */
int imx6_suspend_init(void);
int imx6sx_cpuidle_init(void);
int imx6ul_cpuidle_init(void);
int imx6sl_cpuidle_init(void);
int imx6sll_cpuidle_init(void);

void v7_cpu_resume(void);

int imx6ul_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sx_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sll_lowpower_idle(uint32_t power_state, uintptr_t entry,
			  uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sl_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6_cpu_suspend(uint32_t power_state, uintptr_t entry, uint32_t context_id,
		     struct sm_nsec_ctx *nsec);

/* IMX7 Power Initialization functions */
int imx7_suspend_init(void);
int imx7ulp_suspend_init(void);
int imx7d_cpuidle_init(void);

void imx7_suspend(struct imx7_pm_info *info);
void imx7_resume(void);
void ca7_cpu_resume(void);

int imx7_cpu_suspend(uint32_t power_state, uintptr_t entry, uint32_t context_id,
		     struct sm_nsec_ctx *nsec);
int imx7d_lowpower_idle(uint32_t power_state, uintptr_t entry,
			uint32_t context_id, struct sm_nsec_ctx *nsec);
void imx7d_low_power_idle(struct imx7_pm_info *info);

int imx7ulp_cpu_suspend(uint32_t power_state, uintptr_t entry,
			uint32_t context_id, struct sm_nsec_ctx *nsec);
#endif

#endif
