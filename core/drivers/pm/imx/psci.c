// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2018-2020 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <console.h>
#include <drivers/imx_snvs.h>
#include <drivers/imx_uart.h>
#include <drivers/imx_wdog.h>
#include <io.h>
#include <imx.h>
#include <imx-regs.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/pm.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/std_smc.h>

#include "imx_pm.h"
#include "local.h"

#define IOMUXC_GPR5_OFFSET	0x14
#define ARM_WFI_STAT_MASK(n)	BIT(n)

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
	case ARM_SMCCC_VERSION:
	case PSCI_PSCI_FEATURES:
	case PSCI_VERSION:
	case PSCI_CPU_SUSPEND:
	case PSCI_CPU_OFF:
#ifdef CFG_BOOT_SECONDARY_REQUEST
	case PSCI_CPU_ON:
#endif
	case PSCI_AFFINITY_INFO:
	case PSCI_SYSTEM_OFF:
	case PSCI_SYSTEM_RESET:
	case PSCI_SYSTEM_RESET2:
		return PSCI_RET_SUCCESS;
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

uint32_t psci_version(void)
{
	return PSCI_VERSION_1_0;
}

#ifdef CFG_BOOT_SECONDARY_REQUEST
int psci_cpu_on(uint32_t core_idx, uint32_t entry, uint32_t context_id)
{
	if (core_idx == 0 || core_idx >= CFG_TEE_CORE_NB_CORE)
		return PSCI_RET_INVALID_PARAMETERS;

	/* set secondary cores' NS entry addresses */
	boot_set_core_ns_entry(core_idx, entry, context_id);
	imx_set_src_gpr_entry(core_idx, virt_to_phys((void *)TEE_LOAD_ADDR));

#ifdef CFG_MX7
	imx_gpcv2_set_core1_pup_by_software();
	imx_src_release_secondary_core(core_idx);
#else
	imx_src_release_secondary_core(core_idx);
	imx_set_src_gpr_arg(core_idx, 0);
#endif /* CFG_MX7 */

	IMSG("psci on ok");

	return PSCI_RET_SUCCESS;
}

int __noreturn psci_cpu_off(void)
{
	uint32_t core_id = get_core_pos();

	IMSG("core_id: %" PRIu32, core_id);

	psci_armv7_cpu_off();

	imx_set_src_gpr_arg(core_id, UINT32_MAX);

	thread_mask_exceptions(THREAD_EXCP_ALL);

	while (true)
		wfi();
}

int psci_affinity_info(uint32_t affinity,
		       uint32_t lowest_affnity_level __unused)
{
	vaddr_t base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC,
				       IOMUXC_SIZE);
	uint32_t cpu = affinity;
	bool wfi = true;

	if (!soc_is_imx7ds())
		wfi = io_read32(base + IOMUXC_GPR5_OFFSET) &
		      ARM_WFI_STAT_MASK(cpu);

	if (imx_get_src_gpr_arg(cpu) == 0 || !wfi)
		return PSCI_AFFINITY_LEVEL_ON;

	DMSG("cpu: %" PRIu32 "GPR: %" PRIx32, cpu, imx_get_src_gpr_arg(cpu));

	while (imx_get_src_gpr_arg(cpu) != UINT_MAX)
		;

	imx_src_shutdown_core(cpu);
	imx_set_src_gpr_arg(cpu, 0);

	return PSCI_AFFINITY_LEVEL_OFF;
}
#endif

void __noreturn psci_system_off(void)
{
#ifndef CFG_MX7ULP
	imx_snvs_shutdown();
#endif
	dsb();

	while (1)
		;
}
__weak int imx6ul_lowpower_idle(uint32_t power_state __unused,
				uintptr_t entry __unused,
				uint32_t context_id __unused,
				struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx6sx_lowpower_idle(uint32_t power_state __unused,
				uintptr_t entry __unused,
				uint32_t context_id __unused,
				struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx6sl_lowpower_idle(uint32_t power_state __unused,
				uintptr_t entry __unused,
				uint32_t context_id __unused,
				struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx6sll_lowpower_idle(uint32_t power_state __unused,
				uintptr_t entry __unused,
				uint32_t context_id __unused,
				struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx6_cpu_suspend(uint32_t power_state __unused,
			    uintptr_t entry __unused,
			    uint32_t context_id __unused,
			    struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx7d_lowpower_idle(uint32_t power_state __unused,
			uintptr_t entry __unused,
			uint32_t context_id __unused,
			struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx7_cpu_suspend(uint32_t power_state __unused,
			    uintptr_t entry __unused,
			    uint32_t context_id __unused,
			    struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

__weak int imx7ulp_cpu_suspend(uint32_t power_state __unused,
			    uintptr_t entry __unused,
			    uint32_t context_id __unused,
			    struct sm_nsec_ctx *nsec __unused)
{
	return 0;
}

int psci_cpu_suspend(uint32_t power_state,
		     uintptr_t entry, uint32_t context_id __unused,
		     struct sm_nsec_ctx *nsec)
{
	uint32_t id, type;
	int ret = PSCI_RET_INVALID_PARAMETERS;
	TEE_Result retstatus;

	id = power_state & PSCI_POWER_STATE_ID_MASK;
	type = (power_state & PSCI_POWER_STATE_TYPE_MASK) >>
		PSCI_POWER_STATE_TYPE_SHIFT;

	if ((type != PSCI_POWER_STATE_TYPE_POWER_DOWN) &&
	    (type != PSCI_POWER_STATE_TYPE_STANDBY)) {
		DMSG("Not supported %x\n", type);
		return ret;
	}

	/*
	 * ID 0 means suspend
	 * ID 1 means low power idle
	 * TODO: follow PSCI StateID sample encoding.
	 */
	DMSG("ID = %d\n", id);

	/*
	 * For i.MX6SL, the cpuidle need the state of LDO 2P5 and
	 * the busfreq mode. these info is packed in the power_state,
	 * when doing 'id' check, the LDO 2P5 and busfreq mode info need
	 * to be removed from 'id'.
	 */
	if (soc_is_imx6sl())
		id &= ~(0x6);

	if (id == 1) {
		retstatus = pm_change_state(PM_OP_SUSPEND, PM_HINT_CLOCK_STATE);
		if (retstatus != TEE_SUCCESS) {
			EMSG("Drivers idle preparation ret 0x%" PRIx32,
			     retstatus);
			pm_change_state(PM_OP_RESUME, PM_HINT_CLOCK_STATE);
			return PSCI_RET_DENIED;
		}

		if (soc_is_imx6ul() || soc_is_imx6ull())
			ret = imx6ul_lowpower_idle(power_state, entry,
						   context_id, nsec);
		else if (soc_is_imx7ds())
			ret = imx7d_lowpower_idle(power_state, entry,
						  context_id, nsec);
		else if (soc_is_imx6sx())
			ret = imx6sx_lowpower_idle(power_state, entry,
						   context_id, nsec);
		else if (soc_is_imx6sl())
			ret = imx6sl_lowpower_idle(power_state, entry,
						   context_id, nsec);
		else if (soc_is_imx6sll())
			ret = imx6sll_lowpower_idle(power_state, entry,
						    context_id, nsec);
		else {
			EMSG("Not supported now\n");
			ret = PSCI_RET_INVALID_PARAMETERS;
		}
		pm_change_state(PM_OP_RESUME, PM_HINT_CLOCK_STATE);
	} else if (id == 0) {
		retstatus =
			pm_change_state(PM_OP_SUSPEND, PM_HINT_CONTEXT_STATE);
		if (retstatus != TEE_SUCCESS) {
			EMSG("Drivers suspend preparation ret 0x%" PRIx32 "",
			     retstatus);
			pm_change_state(PM_OP_RESUME, PM_HINT_CONTEXT_STATE);
			return PSCI_RET_DENIED;
		}

		if (soc_is_imx7ds())
			ret = imx7_cpu_suspend(power_state, entry, context_id,
					       nsec);
		else if (soc_is_imx6())
			ret = imx6_cpu_suspend(power_state, entry, context_id,
					       nsec);
		else if (soc_is_imx7ulp())
			ret = imx7ulp_cpu_suspend(power_state, entry,
						  context_id, nsec);
		else {
			EMSG("Not supported now\n");
			ret = PSCI_RET_INVALID_PARAMETERS;
		}
		pm_change_state(PM_OP_RESUME, PM_HINT_CONTEXT_STATE);
	} else {
		DMSG("ID %d not supported\n", id);
	}

	return ret;
}

/* Weak functions because files are not all built */
__weak int imx6ul_cpuidle_init(void)
{
	return 0;
}

__weak int imx6sx_cpuidle_init(void)
{
	return 0;
}

__weak int imx6sll_cpuidle_init(void)
{
	return 0;
}

__weak int imx6_suspend_init(void)
{
	return 0;
}

__weak int imx7d_cpuidle_init(void)
{
	return 0;
}

__weak int imx7_suspend_init(void)
{
	return 0;
}

__weak int imx7ulp_suspend_init(void)
{
	return 0;
}

static TEE_Result init_psci(void)
{
	int err = 0;

	/*
	 * Initialize the power management data.
	 * It must be done after the OCRAM initialization.
	 */
#ifdef CFG_MX7ULP
	err = imx7ulp_suspend_init();
#else
	if (!err) {
		if (soc_is_imx6())
			err = imx6_suspend_init();
		else if (soc_is_imx7ds())
			err = imx7_suspend_init();
	}

	if (soc_is_imx6ul() || soc_is_imx6ull()) {
		err = imx6ul_cpuidle_init();
	} else if (soc_is_imx6sx()) {
		err = imx6sx_cpuidle_init();
	} else if (soc_is_imx6sll()) {
		err = imx6sll_cpuidle_init();
	} else if (soc_is_imx7ds()) {
		err = imx7d_cpuidle_init();
	}

#endif

	return (!err) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

void __noreturn psci_system_reset(void)
{
	imx_wdog_restart(true);
}

int __noreturn psci_system_reset2(uint32_t reset_type __unused,
				  uint32_t cookie __unused)
{
	/* force WDOG reset */
	imx_wdog_restart(false);
}

service_init(init_psci);
