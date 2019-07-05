// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2019 NXP
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
	vaddr_t base __maybe_unused;
#ifdef CFG_MX7ULP
/* Temporary Hack to unify detection of SoC*/
	digprog = SOC_MX7ULP << 16;
#else
	anatop_addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);

#ifdef CFG_MX7
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX7D);
#elif defined(CFG_MX6SL)
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX6SL);
#elif defined(CFG_MX8M)
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX8MQ);

	base = core_mmu_get_va(IMX_OCOTP_BASE, MEM_AREA_IO_SEC);

	if (base && (read32(base + SW_INFO_B1) == SW_B1_MAGIC))
	{
		// update soc revision for B1
		digprog |= 0x1;
	}

#elif defined(CFG_MX8MM) || defined(CFG_MX8MN)
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG_IMX8MM);
#else
	digprog = read32(anatop_addr + HW_ANADIG_DIGPROG);
#endif

#endif
	/* Set the CPU type */
	imx_cpu_type = ((digprog >> 16) & 0xFF);

#ifndef CFG_MX7
	/* Set the SOC revision = (Major + 1).(Minor) */
	imx_soc_revision = (((digprog & 0xFF00) >> 4) + 0x10) |
				 (digprog & 0x0F);
#else
	imx_soc_revision = digprog & 0xFF;
#endif
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

bool soc_is_imx8mm(void)
{
	if (imx_soc_type() == SOC_MX8M)
	{
		switch (imx_soc_revision)
		{
			case 0x420:
				return true;
			default:
				break;
		}
	}
	return false;
}

bool soc_is_imx8mq(void)
{
	if (imx_soc_type() == SOC_MX8M)
	{
		switch (imx_soc_revision)
		{
			// B0
			case 0x410:
			// B1
			case 0x411:
				return true;
			default:
				break;
		}
	}
	return false;
}

bool soc_is_imx8mq_b1_layer(void)
{
	if (imx_soc_type() == SOC_MX8M)
	{
		switch (imx_soc_revision)
		{
			// B1
			case 0x411:
				return true;
			default:
				break;
		}
	}
	return false;
}

bool soc_is_imx8mq_b0_layer(void)
{
	if (imx_soc_type() == SOC_MX8M)
	{
		switch (imx_soc_revision)
		{
			// B0
			case 0x410:
				return true;
			default:
				break;
		}
	}
	return false;
}

uint16_t soc_revision(void)
{
	if (imx_soc_revision < 0)
		imx_digproc();

	return imx_soc_revision;
}

#ifdef CFG_IMX_SNVS
/**
 * @brief   Returns if the device is closed (full secure) or not
 *
 * @retval  true if closed device
 * @retval  false if not closed device
 */
bool imx_is_device_closed(void)
{
	uint32_t val;
	vaddr_t  snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);

	val = read32(snvs_base + SNVS_HPSTATUS);
	val &= BM_SNVS_HPSTATUS_SYS_SEC_CFG;

	if ((val & SNVS_HPSTATUS_CLOSED) && !(val & SNVS_HPSTATUS_BAD))
		return true;

	return false;
}
#else
/**
 * @brief   Returns if the device is not closed (full secure)
 *
 * @retval  false if not closed device
 */
bool imx_is_device_closed(void)
{
	return false;
}
#endif
