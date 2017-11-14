// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright 2017 NXP
 */
#include <arm.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>

register_phys_mem(MEM_AREA_IO_SEC, PL310_BASE, CORE_MMU_DEVICE_SIZE);

void arm_cl2_config(vaddr_t pl310_base)
{
	/* Disable PL310 */
	write32(0, pl310_base + PL310_CTRL);

	write32(PL310_TAG_RAM_CTRL_INIT, pl310_base + PL310_TAG_RAM_CTRL);
	write32(PL310_DATA_RAM_CTRL_INIT, pl310_base + PL310_DATA_RAM_CTRL);
	write32(PL310_AUX_CTRL_INIT, pl310_base + PL310_AUX_CTRL);
	write32(PL310_PREFETCH_CTRL_INIT, pl310_base + PL310_PREFETCH_CTRL);
	write32(PL310_POWER_CTRL_INIT, pl310_base + PL310_POWER_CTRL);

	/* invalidate all cache ways */
	arm_cl2_invbyway(pl310_base);
}

bool arm_cl2_enabled(vaddr_t pl310_base)
{
	return read32(pl310_base + PL310_CTRL) & 1;
}

void arm_cl2_enable(vaddr_t pl310_base)
{
	uint32_t val;

	/* Enable PL310 ctrl -> only set lsb bit */
	write32(1, pl310_base + PL310_CTRL);

	/* if L2 FLZW enable, enable in L1 */
	val = read32(pl310_base + PL310_AUX_CTRL);
	if (val & 1)
		write_actlr(read_actlr() | (1 << 3));
}

vaddr_t pl310_base(void)
{
	return core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC);
}

