// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */
#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx.h>
#include <imx_pm.h>
#include <kernel/boot.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/sm.h>
#include <sm/pm.h>

int imx6_cpu_suspend(uint32_t power_state __unused, uintptr_t entry,
		     uint32_t context_id __unused, struct sm_nsec_ctx *nsec)
{
	int ret;

	uint32_t suspend_ocram_base = core_mmu_get_va(
					imx_get_ocram_tz_start_addr() +
					SUSPEND_OCRAM_OFFSET,
						MEM_AREA_TEE_COHERENT);
	struct imx6_pm_info *p = (struct imx6_pm_info *)suspend_ocram_base;

	/* Store non-sec ctx regs */
	sm_save_unbanked_regs(&nsec->ub_regs);

	ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(suspend_ocram_base + sizeof(*p)));
	/*
	 * Sometimes sm_pm_cpu_suspend may not really suspended,
	 * we need to check it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	/* Restore register of different mode in secure world */
	sm_restore_unbanked_regs(&nsec->ub_regs);

	/*
	 * Call the Wakeup Late function to restore some
	 * HW configuration (e.g. TZASC)
	 */
	plat_cpu_wakeup_late();

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	/*
	 * There is no driver suspend/resume framework in op-tee.
	 * Add L2 code here, a bit different from OPTEE initialization
	 * when bootup. Now MMU is up, L1 enabled.
	 */
#ifdef CFG_PL310
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
