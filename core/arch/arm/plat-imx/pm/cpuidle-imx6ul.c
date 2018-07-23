// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx_pm.h>
#include <imx.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <sm/psci.h>
#include <sm/pm.h>
#include <util.h>

/*
 * cpuidle and suspend use the same one,
 * because lowpower idle and suspend can not reach at the same time
 */

int imx6ul_cpuidle_init(void)
{
	uint32_t i;
	uint32_t *mmdc_io_offset_array;
	uint32_t lowpower_idle_ocram_base = (uint32_t)phys_to_virt(
			imx_get_ocram_tz_start_addr() +
			LOWPOWER_IDLE_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT,
			LOWPOWER_IDLE_OCRAM_SIZE);
	struct imx6_pm_info *p =
			(struct imx6_pm_info *)lowpower_idle_ocram_base;
	struct imx6_pm_data *pm_data;

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	p->pa_base = imx_get_ocram_tz_start_addr() + LOWPOWER_IDLE_OCRAM_OFFSET;
	p->tee_resume = (paddr_t)virt_to_phys((void *)(vaddr_t)v7_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->ccm_va_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC, CCM_SIZE);
	p->ccm_pa_base = CCM_BASE;
	p->mmdc0_va_base = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC,
					   MMDC_P0_SIZE);
	p->mmdc0_pa_base = MMDC_P0_BASE;
	p->src_va_base = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC, SRC_SIZE);
	p->src_pa_base = SRC_BASE;
	p->iomuxc_va_base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC,
					    IOMUXC_SIZE);
	p->iomuxc_pa_base = IOMUXC_BASE;
	p->gpc_va_base = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC, GPC_SIZE);
	p->gpc_pa_base = GPC_BASE;
	p->anatop_va_base = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC,
					    ANATOP_SIZE);
	p->anatop_pa_base = ANATOP_BASE;

	pm_data = &imx6ul_pm_data;

	p->mmdc_io_num = pm_data->mmdc_io_num;
	mmdc_io_offset_array = pm_data->mmdc_io_offset;

	for (i = 0; i < p->mmdc_io_num; i++)
		p->mmdc_io_val[i][0] = mmdc_io_offset_array[i];

	memcpy((void *)(lowpower_idle_ocram_base + sizeof(*p)),
#if defined(CFG_MX6UL)
		(void *)(vaddr_t)imx6ul_low_power_idle,
#elif defined(CFG_MX6ULL)
		(void *)(vaddr_t)imx6ull_low_power_idle,
#endif
	       LOWPOWER_IDLE_OCRAM_SIZE - sizeof(*p));

	dcache_clean_range((void *)lowpower_idle_ocram_base,
			   LOWPOWER_IDLE_OCRAM_SIZE);
	/*
	 * Note that IRAM IOSEC map, if changed to MEM map,
	 * need to flush cache
	 */
	icache_inv_all();

	return 0;
}

static int lowpoweridle_init;

int imx6ul_lowpower_idle(uint32_t power_state __unused,
			 uintptr_t entry,
			 uint32_t context_id __unused,
			 struct sm_nsec_ctx *nsec)
{
	int ret;
	/*
	 * TODO: move the code to a platform init place, note that
	 * need to change kernel pm-imx6.c to avoid use LPRAM.
	 */
	uint32_t cpuidle_ocram_base = (uint32_t)phys_to_virt(
			imx_get_ocram_tz_start_addr() +
			LOWPOWER_IDLE_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT,
			LOWPOWER_IDLE_OCRAM_SIZE);
	struct imx6_pm_info *p = (struct imx6_pm_info *)cpuidle_ocram_base;

	/*
	 * TODO:
	 * Check power_state?
	 */
	if (!lowpoweridle_init) {
		imx6ul_cpuidle_init();
		lowpoweridle_init = 1;
	}

	/* Store non-sec ctx regs */
	sm_save_unbanked_regs(&nsec->ub_regs);

	ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(cpuidle_ocram_base + sizeof(*p)));
	/*
	 * Sometimes cpu_suspend may not really suspended, we need to check
	 * it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	/* Restore register of different mode in secure world */
	sm_restore_unbanked_regs(&nsec->ub_regs);

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
