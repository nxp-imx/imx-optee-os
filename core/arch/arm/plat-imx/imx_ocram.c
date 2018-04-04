// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017 NXP
 *
 */

#include <kernel/panic.h>
#include <initcall.h>
#include <trace.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <io.h>

#include <imx.h>
#include <imx_pm.h>
#include <imx-regs.h>

paddr_t iram_tlb_phys_addr = -1UL;

#ifdef CFG_MX6
static const paddr_t phys_addr_imx6ull[] = {
	AIPS1_BASE, AIPS2_BASE, AIPS3_BASE, 0
};

static const paddr_t phys_addr_imx6ul[] = {
	AIPS1_BASE, AIPS2_BASE, 0
};

static const paddr_t phys_addr_imx6sl[] = {
	PL310_BASE, AIPS1_BASE, AIPS2_BASE, 0
};

static const paddr_t phys_addr_imx6[] = {
	PL310_BASE, AIPS1_BASE, AIPS2_BASE, AIPS3_BASE, 0
};

static void init_tz_ocram(void)
{
	/* Configure the Secure OCRAM granularity */
	vaddr_t  iomux_base;
	uint32_t val;
	uint32_t lock = 0;

	if (soc_is_imx6ul() || soc_is_imx6ull() ||
		soc_is_imx6sx() || soc_is_imx6sll()) {
		iomux_base = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);
	} else {
		iomux_base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);
	}

	/* Read the current value */
	val = read32(iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID));

	/* Caluclate the OCRAM split configuration */
	if (soc_is_imx6ul() || soc_is_imx6ull() ||
		soc_is_imx6sl() || soc_is_imx6sll()) {
		val &= ~BM_IOMUX_GPR_OCRAM_TZ_ADDR_6UL;
		// Address is 4 Kbytes granularity
		val |= (((TRUSTZONE_OCRAM_START >> 12) <<
				BP_IOMUX_GPR_OCRAM_TZ_ADDR_6UL) &
				BM_IOMUX_GPR_OCRAM_TZ_ADDR_6UL);
		// Enable
		val |= IOMUX_GPR_OCRAM_TZ_ENABLE_6UL;
		lock = BM_IOMUX_GPR_OCRAM_TZ_ADDR_6UL |
			IOMUX_GPR_OCRAM_TZ_ENABLE_6UL;
	} else if (soc_is_imx6sx()) {
		/*
		 * For IMX6SX, use S_OCRAM so don't need to lock configuration
		 * Just ensure that OCRAM is full released
		 */
		val &= ~BM_IOMUX_GPR_OCRAM_TZ_ADDR_6SX;
		val &= ~IOMUX_GPR_OCRAM_TZ_ENABLE_6SX;
	} else if (soc_is_imx6sdl()) {
		val &= ~BM_IOMUX_GPR_OCRAM_TZ_ADDR_6DL;
		// Address is 4 Kbytes granularity
		val |= (((TRUSTZONE_OCRAM_START >> 12) <<
				BP_IOMUX_GPR_OCRAM_TZ_ADDR_6DL) &
				BM_IOMUX_GPR_OCRAM_TZ_ADDR_6DL);
		// Enable
		val |= IOMUX_GPR_OCRAM_TZ_ENABLE_6DL;
		lock = BM_IOMUX_GPR_OCRAM_TZ_ADDR_6DL |
			IOMUX_GPR_OCRAM_TZ_ENABLE_6SX;
	} else {
		val &= ~BM_IOMUX_GPR_OCRAM_TZ_ADDR;
		// Address is 4 Kbytes granularity
		val |= (((TRUSTZONE_OCRAM_START >> 12) <<
				BP_IOMUX_GPR_OCRAM_TZ_ADDR) &
				BM_IOMUX_GPR_OCRAM_TZ_ADDR);
		// Enable
		val |= IOMUX_GPR_OCRAM_TZ_ENABLE;
		lock = BM_IOMUX_GPR_OCRAM_TZ_ADDR |
			IOMUX_GPR_OCRAM_TZ_ENABLE;
	}

	/* Write the configuration */
	write32(val, (iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID)));

	/* Then lock configuration */
	/* Normally the lock bits are not defined for 6UL and 6SX */
	write32(IOMUX_GPR_OCRAM_LOCK(lock) | val,
			(iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID)));

	if (soc_is_imx6sx()) {
		/* Lock the full S_OCRAM and don't use L2 cache as ocram */
		val = IOMUX_GPR_S_OCRAM_TZ_ENABLE_6SX;
		write32(val, (iomux_base +
			IOMUX_GPRx_OFFSET(IOMUX_GPR_S_OCRAM_ID)));
	}
}

static TEE_Result init_ocram(void)
{
	struct tee_mmap_region map;
	const paddr_t *phys_addr;
	paddr_t       iram_base;
	void          *iram_tlb_vaddr;

	DMSG("IRAM TLB phys addr = 0x%X", (uint32_t)iram_tlb_phys_addr);

	/* iram tlb already initialized */
	if (iram_tlb_phys_addr != (-1UL))
		return TEE_SUCCESS;

	/* Initialize the Secure OCRAM */
	init_tz_ocram();

	if (soc_is_imx6sx()) {
		iram_base = ROUNDDOWN(IRAM_6SX_S_BASE, CORE_MMU_DEVICE_SIZE);
		/* First we need to map the Secure RAM */
		if (!core_mmu_add_mapping(MEM_AREA_TEE_COHERENT, iram_base,
							IRAM_6SX_S_SIZE)) {
			panic("Failed to map Secure OCRAM");
		}
	} else {
		iram_base = IRAM_BASE;
	}

#ifdef CFG_MX6SX
	iram_tlb_phys_addr = TRUSTZONE_OCRAM_START;
#else
	iram_tlb_phys_addr = TRUSTZONE_OCRAM_START + IRAM_TBL_OFFSET;
#endif
	iram_tlb_vaddr = phys_to_virt(iram_tlb_phys_addr,
			MEM_AREA_TEE_COHERENT);
	if (!iram_tlb_vaddr) {
		panic("Failed to map Trustzone OCRAM");
	}

	/* 16KB */
	memset(iram_tlb_vaddr, 0, 16 * 1024);

	/* Get the array of the area to be mapped */
	if (soc_is_imx6ull()) {
		phys_addr = phys_addr_imx6ull;
	} else if (soc_is_imx6ul()) {
		phys_addr = phys_addr_imx6ul;
	} else if (soc_is_imx6sl()) {
		phys_addr = phys_addr_imx6sl;
	} else {
		phys_addr = phys_addr_imx6;
	}

	do {
		map.pa = ROUNDDOWN(*phys_addr, CORE_MMU_DEVICE_SIZE);
		map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_IO_SEC);
		map.region_size = CORE_MMU_DEVICE_SIZE;
		map.size = CORE_MMU_DEVICE_SIZE;
		map.type = MEM_AREA_IO_SEC;
		map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
				TEE_MATTR_GLOBAL | TEE_MATTR_SECURE |
				(TEE_MATTR_CACHE_NONCACHE <<
					TEE_MATTR_CACHE_SHIFT);
		map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);
	} while (*(++phys_addr));

	map.pa = iram_base;
	map.va = (vaddr_t)phys_to_virt(iram_base, MEM_AREA_TEE_COHERENT);
	map.region_size = CORE_MMU_DEVICE_SIZE;
	map.size = CORE_MMU_DEVICE_SIZE;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
				TEE_MATTR_GLOBAL | TEE_MATTR_SECURE |
				TEE_MATTR_PX;
	map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);

	/*
	 * Note: No map DRAM space, DRAM is in auto-selfrefresh,
	 * If map DRAM in to MMU, mmu will access DRAM which
	 * hang system.
	 */

	return TEE_SUCCESS;
}
#endif

#ifdef CFG_MX7
static const paddr_t phys_addr_imx7[] = {
	AIPS1_BASE, AIPS2_BASE, AIPS3_BASE, 0
};
#endif
#ifdef CFG_MX7ULP
static const paddr_t phys_addr_imx7ulp[] = {
	AIPS0_BASE, AIPS1_BASE, 0
};
#endif

#if defined(CFG_MX7) || defined(CFG_MX7ULP)
static void init_tz_ocram(void)
{
#ifndef CFG_MX7ULP
	/* Configure the Secure OCRAM granularity */
	vaddr_t  iomux_base;
	uint32_t val;
	uint32_t lock;

	iomux_base = (vaddr_t)phys_to_virt(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);

	val = read32(iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID));

	/* Configure the OCRAM Retention to start at offset 0 */
	val &= ~BM_IOMUX_GPR_OCRAM_S_TZ_ADDR;
	val |= IOMUX_GPR_OCRAM_S_TZ_ENABLE;

	lock = BM_IOMUX_GPR_OCRAM_S_TZ_ADDR | IOMUX_GPR_OCRAM_S_TZ_ENABLE;

	write32(val, (iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID)));

	/* Then lock configuration */
	write32(IOMUX_GPR_OCRAM_LOCK(lock) | val,
			(iomux_base + IOMUX_GPRx_OFFSET(IOMUX_GPR_OCRAM_ID)));
#endif
}

static TEE_Result init_ocram(void)
{
	struct tee_mmap_region map;
	const paddr_t *phys_addr;
	size_t        size_area;
	void          *iram_tlb_vaddr;

	DMSG("IRAM TLB phys addr = 0x%X", (uint32_t)iram_tlb_phys_addr);

	/* iram tlb already initialized */
	if (iram_tlb_phys_addr != (-1UL)) {
		return TEE_SUCCESS;
	}

	/* Initialize the Secure OCRAM */
	init_tz_ocram();

#ifdef CFG_MX7
	iram_tlb_phys_addr = TRUSTZONE_OCRAM_START + IRAM_TBL_OFFSET;
	phys_addr = phys_addr_imx7;
	size_area = AIPS1_SIZE; /* 4M for AIPS1/2/3 */
#endif
#ifdef CFG_MX7ULP
	iram_tlb_phys_addr = LP_OCRAM_START;
	phys_addr = phys_addr_imx7ulp;
	size_area = AIPS1_SIZE; /* 8M for AIPS0/1 */
#endif

	iram_tlb_vaddr = phys_to_virt(iram_tlb_phys_addr,
					  MEM_AREA_TEE_COHERENT);

	/* 16KB */
	DMSG("%x %x\n", (uint32_t)iram_tlb_phys_addr,
			(uint32_t)iram_tlb_vaddr);
	memset(iram_tlb_vaddr, 0, 16 * 1024);

	do {
		map.pa = *phys_addr;
		map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_IO_SEC);
		map.region_size = CORE_MMU_DEVICE_SIZE;
		map.size = size_area;
		map.type = MEM_AREA_IO_SEC;
		map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW |
				TEE_MATTR_GLOBAL | TEE_MATTR_SECURE |
				(TEE_MATTR_CACHE_NONCACHE <<
					TEE_MATTR_CACHE_SHIFT);
		map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);
	} while (*(++phys_addr));

#ifdef CFG_MX7
	/* Note IRAM_S_BASE is not 1M aligned, so take care */
	map.pa = ROUNDDOWN(IRAM_S_BASE, CORE_MMU_DEVICE_SIZE);
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_TEE_COHERENT);
	map.region_size = CORE_MMU_DEVICE_SIZE;
	map.size = CORE_MMU_DEVICE_SIZE;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				TEE_MATTR_SECURE | TEE_MATTR_PX;
	map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);

	map.pa = GIC_BASE;
	map.va = (vaddr_t)phys_to_virt((paddr_t)GIC_BASE, MEM_AREA_IO_SEC);
	map.region_size = CORE_MMU_DEVICE_SIZE;
	map.size = CORE_MMU_DEVICE_SIZE;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				TEE_MATTR_SECURE | TEE_MATTR_PX;
	map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);


	/*
	 * Note: No map DRAM space, DRAM is in auto-selfrefresh,
	 * If map DRAM in to MMU, mmu will access DRAM which
	 * hang system.
	 */
#endif
#ifdef CFG_MX7ULP
	map.pa = M4_AIPS_BASE;
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_IO_SEC);
	map.region_size = 0x100000;
	map.size = 0x100000;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				 TEE_MATTR_SECURE;
	map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);

	map.pa = ROUNDDOWN(IRAM_BASE, 0x100000);
	map.va = (vaddr_t)phys_to_virt(map.pa, MEM_AREA_TEE_COHERENT);
	map.region_size = 0x100000;
	map.size = 0x100000;
	map.type = MEM_AREA_TEE_COHERENT;
	map.attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_PRW | TEE_MATTR_GLOBAL |
				TEE_MATTR_SECURE | TEE_MATTR_PX;
	map_memarea_sections(&map, (uint32_t *)iram_tlb_vaddr);

	/*
	 * We no need to give GIC a standalone entry, because AIPS0 has
	 * already included GIC space. If not, map_memarea will
	 * panic.
	 *
	 * Note: No map DRAM space, DRAM is in auto-selfrefresh,
	 * If map DRAM in to MMU, mmu will access DRAM which
	 * hang system.
	 */
#endif

	return TEE_SUCCESS;
}
#endif

service_init(init_ocram);
