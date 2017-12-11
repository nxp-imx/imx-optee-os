// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 */

#include <arm.h>
#include <console.h>
#include <drivers/gic.h>
#include <drivers/imx_lpuart.h>
#include <io.h>
#include <imx.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>


static void main_fiq(void);
static struct gic_data gic_data;

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = pm_panic,
	.cpu_off = pm_panic,
	.cpu_suspend = pm_panic,
	.cpu_resume = pm_panic,
	.system_off = pm_panic,
	.system_reset = pm_panic,
};

static struct imx_lpuart_data console_data;

#ifdef AIPS0_BASE
register_phys_mem(MEM_AREA_IO_SEC, AIPS0_BASE, AIPS0_SIZE);
#endif
#ifdef AIPS1_BASE
register_phys_mem(MEM_AREA_IO_SEC, AIPS1_BASE, AIPS1_SIZE);
#endif
#ifdef M4_AIPS_BASE
register_phys_mem(MEM_AREA_IO_SEC, M4_AIPS_BASE, M4_AIPS_SIZE);
#endif
#ifdef IRAM_BASE
register_phys_mem(MEM_AREA_TEE_COHERENT,
		ROUNDDOWN(IRAM_BASE, CORE_MMU_DEVICE_SIZE),
		CORE_MMU_DEVICE_SIZE);
#endif

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

static void main_fiq(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	imx_lpuart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}

void main_init_gic(void)
{
	vaddr_t gicc_base;
	vaddr_t gicd_base;

	gicc_base = core_mmu_get_va(GIC_BASE + GICC_OFFSET, MEM_AREA_IO_SEC);
	gicd_base = core_mmu_get_va(GIC_BASE + GICD_OFFSET, MEM_AREA_IO_SEC);

	if (!gicc_base || !gicd_base)
		panic();

	/* Initialize GIC */
	gic_init(&gic_data, gicc_base, gicd_base);
	itr_init(&gic_data.chip);
}
