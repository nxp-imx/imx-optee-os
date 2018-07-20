// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <console.h>
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

static int imx_cpu_type     = (-1);
static int imx_soc_revision = (-1);

static void imx_digproc(void)
{
	uint32_t digprog;
	vaddr_t anatop_addr __maybe_unused;
#ifdef CFG_MX7ULP
/* Temporary Hack to unify detection of SoC*/
	digprog = SOC_MX7ULP << 16;
#else
	anatop_addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);

#ifdef CFG_MX7
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX7D);
#elif defined(CFG_MX6SL)
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX6SL);
#else
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG);
#endif

#endif
	/* Set the CPU type */
	imx_cpu_type = ((digprog >> 16) & 0xFF);

	/* Set the SOC revision = (Major + 1).(Minor) */
	imx_soc_revision = (((digprog & 0xFF00) >> 4) + 0x10) |
				 (digprog & 0x0F);

}

static uint32_t imx_soc_rev_major(void)
{
	if (imx_soc_revision < 0) {
		imx_digproc();
	}

	return (imx_soc_revision >> 4);
}

static uint32_t imx_soc_type(void)
{
	if (imx_cpu_type < 0) {
		imx_digproc();
	}

	return imx_cpu_type;
}

bool soc_is_imx6sll(void)
{
	return imx_soc_type() == SOC_MX6SLL;
}

bool soc_is_imx6sl(void)
{
	return imx_soc_type() == SOC_MX6SL;
}

bool soc_is_imx6sx(void)
{
	return imx_soc_type() == SOC_MX6SX;
}

bool soc_is_imx6ul(void)
{
	return imx_soc_type() == SOC_MX6UL;
}

bool soc_is_imx6ull(void)
{
	return imx_soc_type() == SOC_MX6ULL;
}

bool soc_is_imx6sdl(void)
{
	return imx_soc_type() == SOC_MX6DL;
}

bool soc_is_imx6dq(void)
{
	return (imx_soc_type() == SOC_MX6Q) &&
		(imx_soc_rev_major() == 1);
}

bool soc_is_imx6dqp(void)
{
	return (imx_soc_type() == SOC_MX6Q) &&
		(imx_soc_rev_major() == 2);
}

bool soc_is_imx6(void)
{
	return ((imx_soc_type() == SOC_MX6SLL) ||
			(imx_soc_type() == SOC_MX6SL) ||
			(imx_soc_type() == SOC_MX6SX) ||
			(imx_soc_type() == SOC_MX6UL) ||
			(imx_soc_type() == SOC_MX6ULL) ||
			(imx_soc_type() == SOC_MX6DL) ||
			(imx_soc_type() == SOC_MX6Q));
}

bool soc_is_imx7ds(void)
{
	return imx_soc_type() == SOC_MX7D;
}

bool soc_is_imx7ulp(void)
{
	return imx_soc_type() == SOC_MX7ULP;
}

uint32_t imx_get_src_gpr(int cpu)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);

	return read32(va + SRC_GPR1 + cpu * 8 + 4);
}

void imx_set_src_gpr(int cpu, uint32_t val)
{
	vaddr_t va = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);

	write32(val, va + SRC_GPR1 + cpu * 8 + 4);
}
