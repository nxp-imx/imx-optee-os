/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 */

#ifndef __IMX_PM_H
#define __IMX_PM_H

#include <stdint.h>

#define PM_INFO_PBASE_OFF	0x0
#define PM_INFO_ENTRY_OFF	0x4
#define PM_INFO_TEE_RESUME_OFF	0x8
#define PM_INFO_DDR_TYPE_OFF	0xC
#define PM_INFO_INFO_SIZE_OFF	0x10
#define PM_INFO_MMDC0_P_OFF	0x14
#define PM_INFO_MMDC0_V_OFF	0x18
#define PM_INFO_MMDC1_P_OFF	0x1C
#define PM_INFO_MMDC1_V_OFF	0x20
#define PM_INFO_SRC_P_OFF	0x24
#define PM_INFO_SRC_V_OFF	0x28
#define PM_INFO_IOMUXC_P_OFF	0x2C
#define PM_INFO_IOMUXC_V_OFF	0x30
#define PM_INFO_CCM_P_OFF	0x34
#define PM_INFO_CCM_V_OFF	0x38
#define PM_INFO_GPC_P_OFF	0x3C
#define PM_INFO_GPC_V_OFF	0x40
#define PM_INFO_PL310_P_OFF	0x44
#define PM_INFO_PL310_V_OFF	0x48
#define PM_INFO_ANATOP_P_OFF	0x4C
#define PM_INFO_ANATOP_V_OFF	0x50
#define PM_INFO_TTBR0_OFF	0x54
#define PM_INFO_TTBR1_OFF	0x58
#define PM_INFO_SAVED_DIAGNOSTIC_OFF 0x5c
#define PM_INFO_IDLE_STATE	0x60
#define PM_INFO_MMDC_IO_NUM_OFF	0x64
#define PM_INFO_MMDC_IO_VAL_OFF	0x68
/* below offsets depends on MX6_MAX_MMDC_IO_NUM(36) definition */
#define PM_INFO_MMDC_NUM_OFF	0x218
#define PM_INFO_MMDC_VAL_OFF	0x21c

#define MX6_MAX_MMDC_IO_NUM		36
#define MX6_MAX_MMDC_NUM		36

#define PM_INFO_MX7_M4_RESERVE0_OFF	0x0
#define PM_INFO_MX7_M4_RESERVE1_OFF	0x4
#define PM_INFO_MX7_M4_RESERVE2_OFF	0x8
#define PM_INFO_MX7_PBASE_OFF		0xc
#define PM_INFO_MX7_ENTRY_OFF		0x10
#define PM_INFO_MX7_RESUME_ADDR_OFF	0x14
#define PM_INFO_MX7_DDR_TYPE_OFF	0x18
#define PM_INFO_MX7_SIZE_OFF		0x1c
#define PM_INFO_MX7_DDRC_P_OFF		0x20
#define PM_INFO_MX7_DDRC_V_OFF		0x24
#define PM_INFO_MX7_DDRC_PHY_P_OFF	0x28
#define PM_INFO_MX7_DDRC_PHY_V_OFF	0x2c
#define PM_INFO_MX7_SRC_P_OFF		0x30
#define PM_INFO_MX7_SRC_V_OFF		0x34
#define PM_INFO_MX7_IOMUXC_GPR_P_OFF	0x38
#define PM_INFO_MX7_IOMUXC_GPR_V_OFF	0x3c
#define PM_INFO_MX7_CCM_P_OFF		0x40
#define PM_INFO_MX7_CCM_V_OFF		0x44
#define PM_INFO_MX7_GPC_P_OFF		0x48
#define PM_INFO_MX7_GPC_V_OFF		0x4c
#define PM_INFO_MX7_SNVS_P_OFF		0x50
#define PM_INFO_MX7_SNVS_V_OFF		0x54
#define PM_INFO_MX7_ANATOP_P_OFF	0x58
#define PM_INFO_MX7_ANATOP_V_OFF	0x5c
#define PM_INFO_MX7_LPSR_P_OFF		0x60
#define PM_INFO_MX7_LPSR_V_OFF		0x64
#define PM_INFO_MX7_GIC_DIST_P_OFF	0x68
#define PM_INFO_MX7_GIC_DIST_V_OFF	0x6c
#define PM_INFO_MX7_TTBR0_OFF		0x70
#define PM_INFO_MX7_TTBR1_OFF		0x74
#define PM_INFO_MX7_DDRC_REG_NUM_OFF	0x78
#define PM_INFO_MX7_DDRC_REG_OFF	0x7C
#define PM_INFO_MX7_DDRC_PHY_REG_NUM_OFF	0x17C
#define PM_INFO_MX7_DDRC_PHY_REG_OFF	0x180

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

#ifndef ASM
#include <sm/sm.h>

struct imx7_pm_info {
	uint32_t	m4_reserve0;
	uint32_t	m4_reserve1;
	uint32_t	m4_reserve2;
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
	uint32_t	ddrc_num;
	uint32_t	ddrc_val[MX7_DDRC_NUM][2];
	uint32_t	ddrc_phy_num;
	uint32_t	ddrc_phy_val[MX7_DDRC_NUM][2];
} __aligned(8);

struct imx7_cpuidle_pm_info {
	vaddr_t		va_base;	/* va of pm_info */
	paddr_t		pa_base;	/* pa of pm_info */
	paddr_t		tee_resume;
	uint32_t	pm_info_size;
	uint32_t	ttbr0;
	uint32_t	ttbr1;
	volatile uint32_t	num_online_cpus;
	volatile uint32_t	num_lpi_cpus;
	volatile uint32_t	val;
	uint32_t	flag0;
	uint32_t	flag1;
	paddr_t		ddrc_pa_base;
	vaddr_t		ddrc_va_base;
	paddr_t		ccm_pa_base;
	vaddr_t		ccm_va_base;
	paddr_t		anatop_pa_base;
	vaddr_t		anatop_va_base;
	paddr_t		src_pa_base;
	vaddr_t		src_va_base;
	paddr_t		iomuxc_gpr_pa_base;
	vaddr_t		iomuxc_gpr_va_base;
	paddr_t		gpc_pa_base;
	vaddr_t		gpc_va_base;
	paddr_t		gic_pa_base;
	vaddr_t		gic_va_base;
} __aligned(8);

#define MX7ULP_MAX_IOMUX_NUM		116
#define MX7ULP_MAX_SELECT_INPUT_NUM	78
#define MX7ULP_MAX_MMDC_IO_NUM		36
#define MX7ULP_MAX_MMDC_NUM		50
struct imx7ulp_pm_info {
	uint32_t m4_reserve0;
	uint32_t m4_reserve1;
	uint32_t m4_reserve2;
	paddr_t pbase; /* The physical address of pm_info. */
	paddr_t resume_addr; /* The physical resume address for asm code */
	uint32_t pm_info_size; /* Size of pm_info. */
	vaddr_t sim_base;
	vaddr_t scg1_base;
	vaddr_t mmdc_base;
	vaddr_t mmdc_io_base;
	vaddr_t smc1_base;
	uint32_t scg1[16];
	uint32_t ttbr0;
	uint32_t ttbr1;
	uint32_t gpio[4][2];
	uint32_t iomux_num;
	uint32_t iomux_val[MX7ULP_MAX_IOMUX_NUM];
	uint32_t select_input_num;
	uint32_t select_input_val[MX7ULP_MAX_SELECT_INPUT_NUM];
	uint32_t mmdc_io_num;
	uint32_t mmdc_io_val[MX7ULP_MAX_MMDC_IO_NUM][2];
	uint32_t mmdc_num;
	uint32_t mmdc_val[MX7ULP_MAX_MMDC_NUM][2];
} __aligned(8);

struct imx7ulp_pm_data {
	uint32_t ddr_type;
	uint32_t mmdc_io_num;
	uint32_t *mmdc_io_offset;
	uint32_t mmdc_num;
	uint32_t *mmdc_offset;
};

struct suspend_save_regs {
	uint32_t irq[3];
	uint32_t fiq[3];
	uint32_t und[3];
	uint32_t abt[3];
	uint32_t mon[3];
} __aligned(64);

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
int imx6_cpu_suspend(uint32_t power_state, uintptr_t entry,
		     uint32_t context_id, struct sm_nsec_ctx *nsec);

extern struct imx7_pm_data imx7d_pm_data;

/* IMX7 Power Initialization functions */
int imx7_suspend_init(void);
int imx7ulp_suspend_init(void);
int imx7d_cpuidle_init(void);

void imx7_suspend(struct imx7_pm_info *info);
void imx7_resume(void);
void ca7_cpu_resume(void);
void imx7ulp_cpu_resume(void);

int imx7_cpu_suspend(uint32_t power_state, uintptr_t entry,
		     uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx7d_lowpower_idle(uint32_t power_state, uintptr_t entry,
			uint32_t context_id, struct sm_nsec_ctx *nsec);
void imx7d_low_power_idle(struct imx7_cpuidle_pm_info *info);
#endif

#endif
