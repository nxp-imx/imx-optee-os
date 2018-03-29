// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
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


#if (defined(PLATFORM_FLAVOR_mx6qpsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6qsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6qsabrelite) \
	|| defined(PLATFORM_FLAVOR_mx6dlsabresd))
static int board_imx_tzasc_configure(vaddr_t addr)
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
#elif (defined(PLATFORM_FLAVOR_mx6qpsabreauto) \
	|| defined(PLATFORM_FLAVOR_mx6qsabreauto) \
	|| defined(PLATFORM_FLAVOR_mx6dlsabreauto))
static int board_imx_tzasc_configure(vaddr_t addr)
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
	tzc_configure_region(5, 0x8e000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(6, 0x8fe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ulevk)
static int board_imx_tzasc_configure(vaddr_t addr)
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
#elif defined(PLATFORM_FLAVOR_mx6ul9x9evk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0x8e000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0x8fe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ullevk)
static int board_imx_tzasc_configure(vaddr_t addr)
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
#elif defined(PLATFORM_FLAVOR_mx6sxsabresd)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xbe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xbfe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6sxsabreauto)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xfe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xffe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6slevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xbe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xbfe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}

#elif defined(PLATFORM_FLAVOR_mx6sllevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xfe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xffe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx7dsabresd)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, 0xbe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, 0xbfe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx8mqevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
	tzc_configure_region(1, 0xbe000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(2, 0xbfe00000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_set_action(3);

	tzc_region_enable(2);
	tzc_region_enable(1);
	tzc_region_enable(0);

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

	if (soc_is_imx6ul() || soc_is_imx6ull() || soc_is_imx6sx()) {
		iomuxc_gpr = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);
	} else {
		iomuxc_gpr = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);
	}

	val = read32(iomuxc_gpr + IOMUX_GPRx_OFFSET(IOMUX_GPR_TZASC_ID));

	if (soc_is_imx6dqp() || soc_is_imx6dq() || soc_is_imx6sdl()) {
		DMSG("TZC2\n");
		if ((val & BM_IOMUX_GPR_TZASC2_MUX_CTRL) !=
			 BM_IOMUX_GPR_TZASC2_MUX_CTRL) {
			EMSG("TZASC2 not set\n");
			panic();
		}
		va2 = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC);
		board_imx_tzasc_configure(va2);

	}

	DMSG("TZC1\n");

	if ((val & BM_IOMUX_GPR_TZASC1_MUX_CTRL) !=
		 BM_IOMUX_GPR_TZASC1_MUX_CTRL) {
		EMSG("TZASC1 not set\n");
		panic();
	}

	va1 = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);
	board_imx_tzasc_configure(va1);

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
	val = read32(iomuxc_gpr + IOMUX_GPRx_OFFSET(IOMUX_GPR_TZASC_ID));
	if (val != 1) {
		EMSG("TZASC1_MUX_CONTROL not set\n");
		panic();
	}

	board_imx_tzasc_configure(va);

	return TEE_SUCCESS;
}
#elif defined(CFG_MX8M)
register_phys_mem(MEM_AREA_IO_SEC, TZASC_BASE, CORE_MMU_DEVICE_SIZE);
TEE_Result tzasc_init(void)
{
	vaddr_t addr;

	addr = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);

	board_imx_tzasc_configure(addr);

	return TEE_SUCCESS;
}
driver_init(tzasc_init);
#else
#error "CFG_MX6/7 not defined"
#endif
