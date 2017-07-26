// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 */

#include <arm32.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <drivers/tzc380.h>
#include <imx.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#ifdef CONFIG_WITH_PAGER
#error "pager not supported"
#endif

#if (defined(PLATFORM_FLAVOR_mx6qsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6dlsabresd))
int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	/*
	 * Note, this is not a good way, because we split the regions
	 * to fit into tzc380 region size rules. Also, we try
	 * to pass DDR/TEE memory to build script from user, but hard
	 * to fit into tzasc. So hack code here.
	 */
	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0x40000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(3, 0x20000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_512M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(4, 0x10000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_256M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(5, 0x4e000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(6, 0x4fe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ulevk)
int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0x9e000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0x9fe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ullevk)
int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0x9e000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0x9fe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx7dsabresd)
int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	/*
	 * Note, this is not a good way, because we split the regions
	 * to fit into tzc380 region size rules. Also, we try
	 * to pass DDR/TEE memory to build script from user, but hard
	 * to fit into tzasc. So hack code here.
	 * The script for 7d-sdb revc board:
	 * `
	 * make PLATFORM=imx-mx7 ARCH=arm CFG_PAGEABLE_ADDR=0
	 * CFG_BUILT_IN_ARGS=y CFG_NS_ENTRY_ADDR=0x80800000
	 * CFG_DT_ADDR=0x83000000 CFG_DT=y CFG_TEE_CORE_LOG_LEVEL=4
	 * CFG_PSCI_ARM32=y CFG_MX7=y CFG_DDR_SIZE=0x40000000
	 * CFG_TZDRAM_BASE=0xbe200000 CFG_BOOT_SECONDARY_REQUEST=y
	 * CFG_TEE_CORE_NB_CORE=2 CFG_TZC380=y
	 * `
	 */
	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xbef00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_16M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xbe700000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_8M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(4, 0xbe300000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(5, 0xbe200000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(5, 0xbe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#else
#error "No tzasc defined"
#endif

#if defined(CFG_MX6)
TEE_Result tzasc_init(void)
{
	vaddr_t va1, va2;
	vaddr_t iomuxc_gpr;
	uint32_t val;

	DMSG("Initializing TZC380\n");

	if (soc_is_imx6ul() || soc_is_imx6ull())
		iomuxc_gpr = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);
	else
		iomuxc_gpr = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);

	val = read32(iomuxc_gpr + IOMUXC_GPR9_OFFSET);

	if (soc_is_imx6dqp() ||	soc_is_imx6dq() ||
		soc_is_imx6dqp() || soc_is_imx6sdl()) {
		DMSG("TZC2\n");
		if ((val & 2) != 2) {
			EMSG("TZASC2 not set\n");
			panic();
		}
		va2 = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC);
		board_imx_tzasc_configure(va2);

	}

	DMSG("TZC1\n");

	if ((val & 1) != 1) {
		EMSG("TZASC1 not set\n");
		panic();
	}

	va1 = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);
	board_imx_tzasc_configure(va1);

	/* Configure OCRAM to be splited into secure/non-secure */
	if (soc_is_imx6dqp() ||	soc_is_imx6dq() ||
		soc_is_imx6sdl()) {
		DMSG("------------------\n");
		val = read32(iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		val |= ((TRUSTZONE_OCRAM_START >> 12) <<
			IOMUXC_GPR10_OCRAM_TZ_ADDR_OFFSET) &
			IOMUXC_GPR10_OCRAM_TZ_ADDR_MASK;
		val |= IOMUXC_GPR10_OCRAM_TZ_EN_MASK;
		write32(val, iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		dsb();

		/* lock bits and other bits can not be set once */
		val |= IOMUXC_GPR10_OCRAM_TZ_EN_LOCK_OFFSET;
		val |= IOMUXC_GPR10_OCRAM_TZ_ADDR_LOCK_MASK;
		write32(val, iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		dsb();
	} else if (soc_is_imx6ul() || soc_is_imx6ull()) {
		val = read32(iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		val |= ((TRUSTZONE_OCRAM_START >> 12) <<
			IOMUXC_GPR10_OCRAM_TZ_ADDR_OFFSET_6UL) &
			IOMUXC_GPR10_OCRAM_TZ_ADDR_MASK_6UL;
		val |= IOMUXC_GPR10_OCRAM_TZ_EN_MASK_6UL;
		write32(val, iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		dsb();

		/* lock bits and other bits can not be set once */
		val |= IOMUXC_GPR10_OCRAM_TZ_EN_LOCK_OFFSET_6UL;
		val |= IOMUXC_GPR10_OCRAM_TZ_ADDR_LOCK_MASK_6UL;
		write32(val, iomuxc_gpr + IOMUXC_GPR10_OFFSET);
		dsb();
	}

	return TEE_SUCCESS;
}
#elif defined(CFG_MX7)
TEE_Result tzasc_init(void)
{
	vaddr_t va;
	vaddr_t iomuxc_gpr;
	uint32_t val;

	DMSG("Initializing TZC380");

	va = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);

	iomuxc_gpr = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);
	val = read32(iomuxc_gpr + IOMUXC_GPR9_OFFSET);
	if (val != 1) {
		EMSG("TZASC1_MUX_CONTROL not set\n");
		panic();
	}

	board_imx_tzasc_configure(va);

	/* Configure OCRAM_S only accessible in security side */
	val = read32(iomuxc_gpr + IOMUXC_GPR11_OFFSET);
	val |= IOMUXC_GPR11_OCRAM_S_TZ_EN_MASK;
	/*
	 * starts from ocram_s offset 0
	 */
	val |= ((0 >> 12) << IOMUXC_GPR11_OCRAM_S_TZ_ADDR_OFFSET) &
		IOMUXC_GPR11_OCRAM_S_TZ_ADDR_MASK;
	write32(val, iomuxc_gpr + IOMUXC_GPR11_OFFSET);
	dsb();
	/*
	 * Can not write all the bits once, seems lock bits
	 * set first, then not able to set other bits
	 */
	val |= IOMUXC_GPR11_OCRAM_S_TZ_EN_LOCK_MASK;
	val |= IOMUXC_GPR11_OCRAM_S_TZ_ADDR_LOCK_OFFSET;
	write32(val, iomuxc_gpr + IOMUXC_GPR11_OFFSET);

	return TEE_SUCCESS;
}
#else
#error "CFG_MX6/7 not defined"
#endif
