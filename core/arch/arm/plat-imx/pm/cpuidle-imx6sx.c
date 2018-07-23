// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx_pl310.h>
#include <imx_pm.h>
#include <imx.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
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

static uint32_t imx6sx_mmdc_io_offset[] = {
	0x2ec, 0x2f0, 0x2f4, 0x2f8,
	0x330, 0x334, 0x338, 0x33c,
	0x60c, 0x610, 0x61c, 0x620,
	0x5f8, 0x608, 0x310, 0x314,
	0x300, 0x2fc, 0x32c,
};

int imx6sx_cpuidle_init(void)
{
	uint32_t i;
	uint32_t *mmdc_io_offset_array;
	uint32_t lowpower_idle_ocram_base = (uint32_t)phys_to_virt(
			imx_get_ocram_tz_start_addr() +
			LOWPOWER_IDLE_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT);
	struct imx6_pm_info *p =
		(struct imx6_pm_info *)lowpower_idle_ocram_base;

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	p->pa_base = imx_get_ocram_tz_start_addr() + LOWPOWER_IDLE_OCRAM_OFFSET;
	p->tee_resume = (paddr_t)virt_to_phys((void *)(vaddr_t)v7_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->mmdc0_pa_base = MMDC_P0_BASE;
	p->mmdc0_va_base = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC);
	p->iomuxc_pa_base = IOMUXC_BASE;
	p->iomuxc_va_base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);
	p->ccm_pa_base = CCM_BASE;
	p->ccm_va_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	p->gpc_pa_base = GPC_BASE;
	p->gpc_va_base = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC);
	p->pl310_pa_base = PL310_BASE;
	p->pl310_va_base = core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC);
	p->anatop_pa_base = ANATOP_BASE;
	p->anatop_va_base = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);
	p->src_pa_base = SRC_BASE;
	p->src_va_base = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);
	p->sema4_pa_base = SEMA4_BASE;
	p->sema4_va_base = core_mmu_get_va(SEMA4_BASE, MEM_AREA_IO_SEC);

	p->mmdc_io_num = ARRAY_SIZE(imx6sx_mmdc_io_offset);
	mmdc_io_offset_array = imx6sx_mmdc_io_offset;

	for (i = 0; i < p->mmdc_io_num; i++)
		p->mmdc_io_val[i][0] = mmdc_io_offset_array[i];

	memcpy((void *)(lowpower_idle_ocram_base + sizeof(*p)),
	       (void *)(vaddr_t)imx6sx_low_power_idle,
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

int imx6sx_lowpower_idle(uint32_t power_state __unused,
			 uintptr_t entry,
			 uint32_t context_id __unused,
			 struct sm_nsec_ctx *nsec)
{
	int ret;
	vaddr_t scu_base = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_SEC, SCU_SIZE);

	if (!lowpoweridle_init) {
		imx6sx_cpuidle_init();
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

	/* SCU config */
	io_write32(scu_base + SCU_INV_SEC, SCU_INV_CTRL_INIT);
	io_write32(scu_base + SCU_SAC, SCU_SAC_CTRL_INIT);
	io_write32(scu_base + SCU_NSAC, SCU_NSAC_CTRL_INIT);

	/* SCU enable */
	io_write32(scu_base + SCU_CTRL,
		io_read32(scu_base + SCU_CTRL) | 0x1);

	/* after enable, flush cache to let other cores can see the data */
	dcache_op_all(DCACHE_OP_CLEAN_INV);

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

#ifdef CFG_PL310
	if (pl310_enabled(pl310_base()))
		return 0;

	arm_cl2_config(pl310_base());
	arm_cl2_invbyway(pl310_base());
	arm_cl2_enable(pl310_base());
	/* Do we need to lock? cpu performance? */
	/*arm_cl2_lockallways(pl310_base()); */
	arm_cl2_invbyway(pl310_base());
#endif

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
