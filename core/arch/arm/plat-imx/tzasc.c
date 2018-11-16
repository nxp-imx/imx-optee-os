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

/*
 *             Explication about the TZASC configuration:
 *            ------------------------------------------
 *
 *  Generic regions configured:
 *  --------------------------
 *  region 0) The default configuration (region 0) is set to secured
 *    -> See "Protection against aliased access" below
 *
 *  region 1) The memory space corresponding to DDR installed is set as
 *            non-secured
 *
 *  region 2) The DDR memory needed for OPTEE (at the end of the DDR mapping)
 *
 *  region 3) The DDR for exchange between REE and TEE
 *
 *  Use of subregion:
 *  -----------------
 *  Another feature of the TZASC which can be used is the subregion
 *  functionality.
 *
 *  ex:
 *  This way if we have to map 1GB sarting at 0x1000 0000, it is possible to
 *  define a region of 2GB whose subregion are 256MB and to disables 1
 *  subregion of low address (range 0x0 -- 0x0fff ffff)and 3 at high address
 *  (ranges 0x5000 0000 -- 0x5fff ffff and 0x600 0000 -- 0x6fff ffff and
 *  0x7000 0000 -- 0x7fff ffff)
 *
 *  Protection against aliased access:
 *  ---------------------------------
 *  It is possible to access memory protected by the TZASC in case the DDR
 *  installed is smaller than the memory space supported by the controller.
 *  (Ref: RM, section about the TZASC: "Address Mapping in various memory
 *  mapping modes").
 *
 *  Without aliasing protection it is possible to use an address outside of the
 *  DDR ranged and bypass TZASC protection.
 *
 *  ex:
 *  DDR installed: 1GB (mapped to range 0x4000 0000 -- 0x8000 0000)
 *  Memory space supported: 4GB
 *  In this case the following addresses will access the same physical memory
 *  of the DDR:
 *   1) 0x8000 0000
 *   2) 0xc000 0000
 *
 *  If the address 1) is protected by the TZASC but not 2), then it is
 *  possible to read/write the content at 1) using the address 2).
 *
 *  That's why the default security configuration for region 0 is secure and
 *  the effective range of DDR installed is configured in region 1: All
 *  aliased access out of range of region 1) will fall in region 0).
 */


#if (defined(PLATFORM_FLAVOR_mx6qpsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6qsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6qsabrelite) \
	|| defined(PLATFORM_FLAVOR_mx6dlsabresd) \
	|| defined(PLATFORM_FLAVOR_mx6solosabresd))
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	/* We map 2G to effectively map 1G starting at 0x1000 0000
	   Disabling 4 subsection of 256M
	 */
	tzc_configure_region(1, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW
		| TZC_ATTR_SUBREGION_DIS(0)
		| TZC_ATTR_SUBREGION_DIS(5)
		| TZC_ATTR_SUBREGION_DIS(6)
		| TZC_ATTR_SUBREGION_DIS(7));
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif (defined(PLATFORM_FLAVOR_mx6qpsabreauto) \
	|| defined(PLATFORM_FLAVOR_mx6qsabreauto) \
	|| defined(PLATFORM_FLAVOR_mx6dlsabreauto) \
	|| defined(PLATFORM_FLAVOR_mx6solosabreauto))
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	/* We map 2G and 256M to effectively map 2G starting at 0x1000 0000
	   Disabling 1 subsection of 256M
	 */
	tzc_configure_region(1, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW
		| TZC_ATTR_SUBREGION_DIS(0));
	tzc_configure_region(2, 0x80000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_256M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(3, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(4, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ulevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_512M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ul9x9evk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_256M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6ullevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_512M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6sxsabresd)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6sxsabreauto)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx6slevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}

#elif defined(PLATFORM_FLAVOR_mx6sllevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx7dsabresd)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	tzc_configure_region(1, DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_1G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);
	tzc_configure_region(2, CFG_TZDRAM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, CFG_SHMEM_START,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx8mqevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	 tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	/* The DDR mapping seems to start at 0 instead of 0x4000 0000.
	 * Substract the offset from the CFG_TZDRAM_START and CFG_SHMEM_START
	 * addresses.
	 * In addition, to map the 3GBytes of DDR available on the board, 4Gbytes
	 * are configured and the last 2 subregions (of 512MB each) are disabled.
	 */
	tzc_configure_region(1, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW
		| TZC_ATTR_SUBREGION_DIS(6)
		| TZC_ATTR_SUBREGION_DIS(7)
		);

	tzc_configure_region(2, (CFG_TZDRAM_START - DRAM0_BASE),
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, (CFG_SHMEM_START  - DRAM0_BASE),
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

#ifdef CFG_DRM_SECURE_DATA_PATH
	/* Use TZASC protection only for B1 revision */
	if (soc_is_imx8mq_b1_layer())
   	{
		tzc_configure_region(4, CFG_TEE_SDP_MEM_BASE - DRAM0_BASE,
			TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
			TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
#ifdef CFG_RDC_SECURE_DATA_PATH
		/* Decoded buffer size is 768MB */
		tzc_configure_region(5, CFG_RDC_DECODED_BUFFER - DRAM0_BASE,
			TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_512M) |
			TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
		tzc_configure_region(6, CFG_RDC_DECODED_BUFFER - DRAM0_BASE + 0x20000000,
			TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_256M) |
			TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
#endif
	}
#endif

	tzc_set_action(3);

	tzc_dump_state();

	return 0;
}
#elif defined(PLATFORM_FLAVOR_mx8mmevk)
static int board_imx_tzasc_configure(vaddr_t addr)
{
	tzc_init(addr);

	tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

	/* 
	 * Like with i.MX 8MQ, The DDR mapping seems to start at 0.
	 */
	tzc_configure_region(1, 0x00000000,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_2G) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_NS_RW);

	tzc_configure_region(2, (CFG_TZDRAM_START - DRAM0_BASE),
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_S_RW);
	tzc_configure_region(3, (CFG_SHMEM_START  - DRAM0_BASE),
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_4M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);

#ifdef CFG_DRM_SECURE_DATA_PATH
	tzc_configure_region(4, CFG_TEE_SDP_MEM_BASE - DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_32M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
#ifdef CFG_RDC_SECURE_DATA_PATH
	/* Decoded buffer size is 128MB */
	tzc_configure_region(5, CFG_RDC_DECODED_BUFFER - DRAM0_BASE,
		TZC_ATTR_REGION_SIZE(TZC_REGION_SIZE_128M) |
		TZC_ATTR_REGION_EN_MASK | TZC_ATTR_SP_ALL);
#endif
#endif

	tzc_set_action(3);

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
#elif defined(CFG_MX8M) || defined(CFG_MX8MM)
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
