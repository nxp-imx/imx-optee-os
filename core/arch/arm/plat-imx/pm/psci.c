// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <console.h>
#include <drivers/imx_uart.h>
#include <drivers/imx_wdog.h>
#include <io.h>
#include <imx.h>
#include <imx_pm.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>

int psci_features(uint32_t psci_fid)
{
	switch (psci_fid) {
#ifdef CFG_BOOT_SECONDARY_REQUEST
	case PSCI_CPU_ON:
		return 0;
#endif

	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

#ifdef CFG_BOOT_SECONDARY_REQUEST
int psci_cpu_on(uint32_t core_idx, uint32_t entry,
		uint32_t context_id)
{
	uint32_t val;
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);

	if (!va)
		EMSG("No SRC mapping\n");

	if ((core_idx == 0) || (core_idx >= CFG_TEE_CORE_NB_CORE))
		return PSCI_RET_INVALID_PARAMETERS;

	/* set secondary cores' NS entry addresses */
	generic_boot_set_core_ns_entry(core_idx, entry, context_id);

	val = virt_to_phys((void *)TEE_TEXT_VA_START);
#ifdef CFG_MX7
	write32(val, va + SRC_GPR1 + core_idx * 8);

	imx_gpcv2_set_core1_pup_by_software();

	/* release secondary core */
	val = read32(va + SRC_A7RCR1);
	val |=  BIT32(BP_SRC_A7RCR1_A7_CORE1_ENABLE +
			     (core_idx - 1));
	write32(val, va + SRC_A7RCR1);
#else
	/* boot secondary cores from OP-TEE load address */
	write32(val, va + SRC_GPR1 + core_idx * 8);

	/* release secondary core */
	val = read32(va + SRC_SCR);
	val |=  BIT32(BP_SRC_SCR_CORE1_ENABLE + (core_idx - 1));
	val |=  BIT32(BP_SRC_SCR_CORE1_RST + (core_idx - 1));
	write32(val, va + SRC_SCR);

	imx_set_src_gpr(core_idx, 0);
#endif
	return PSCI_RET_SUCCESS;
}

int psci_cpu_off(void)
{
	uint32_t core_id;

	core_id = get_core_pos();

	DMSG("core_id: %" PRIu32, core_id);

	psci_armv7_cpu_off();

	imx_set_src_gpr(core_id, UINT32_MAX);

	thread_mask_exceptions(THREAD_EXCP_ALL);

	while (true)
		wfi();

	return PSCI_RET_INTERNAL_FAILURE;
}

int psci_affinity_info(uint32_t affinity,
		       uint32_t lowest_affnity_level __unused)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);
	vaddr_t gpr5 = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC) +
				       IOMUXC_GPR5_OFFSET;
	uint32_t cpu, val;
	bool wfi;

	cpu = affinity;

	if (soc_is_imx7ds())
		wfi = true;
	else
		wfi = read32(gpr5) & ARM_WFI_STAT_MASK(cpu);

	if ((imx_get_src_gpr(cpu) == 0) || !wfi)
		return PSCI_AFFINITY_LEVEL_ON;

	DMSG("cpu: %" PRIu32 "GPR: %" PRIx32, cpu, imx_get_src_gpr(cpu));
	/*
	 * Wait secondary cpus ready to be killed
	 * TODO: Change to non dead loop
	 */
#ifdef CFG_MX7
	if (soc_is_imx7ds()) {
		while (read32(va + SRC_GPR1 + cpu * 8 + 4) != UINT_MAX)
			;

		val = read32(va + SRC_A7RCR1);
		val &=  ~BIT32(BP_SRC_A7RCR1_A7_CORE1_ENABLE + (cpu - 1));
		write32(val, va + SRC_A7RCR1);
	}
#else
	while (read32(va + SRC_GPR1 + cpu * 8 + 4) != UINT32_MAX)
		;

	/* Kill cpu */
	val = read32(va + SRC_SCR);
	val &= ~BIT32(BP_SRC_SCR_CORE1_ENABLE + cpu - 1);
	val |=  BIT32(BP_SRC_SCR_CORE1_RST + cpu - 1);
	write32(val, va + SRC_SCR);
#endif

	/* Clean arg */
	imx_set_src_gpr(cpu, 0);

	return PSCI_AFFINITY_LEVEL_OFF;
}
#endif

void __noreturn psci_system_off(void)
{
#ifndef CFG_MX7ULP
	vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);

	write32(BM_SNVS_LPCR_TOP | BM_SNVS_LPCR_DP_EN |	BM_SNVS_LPCR_SRTC_ENV,
			snvs_base + SNVS_LPCR);
	dsb();
#endif

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
			EMSG("Drivers idle preparation ret 0x%"PRIx32"",
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
		retstatus = pm_change_state(PM_OP_SUSPEND,
			PM_HINT_CONTEXT_STATE);
		if (retstatus != TEE_SUCCESS) {
			EMSG("Drivers suspend preparation ret 0x%"PRIx32"",
				retstatus);
			pm_change_state(PM_OP_RESUME, PM_HINT_CONTEXT_STATE);
			return PSCI_RET_DENIED;
		}

		if (soc_is_imx7ds())
			ret = imx7_cpu_suspend(power_state, entry,
						context_id, nsec);
		else if (soc_is_imx6())
			ret = imx6_cpu_suspend(power_state, entry,
						context_id, nsec);
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
	TEE_Result ret = TEE_SUCCESS;
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

	if (err) {
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}

void psci_system_reset(void)
{
#ifdef CFG_XRDC
	xrdc_reset();
#endif
	imx_wdog_restart();
}

service_init(init_psci);
