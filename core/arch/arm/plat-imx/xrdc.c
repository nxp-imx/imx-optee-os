// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 */
#include <imx.h>
#include <initcall.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>

#include "xrdc.h"

#define XRDC_NB_REGION_MAX		16
#define XRDC_SZ_SIZE(mod)		((1 << (mod + 1)) - 1)

/**
 * XRDC hardware configuration
 */
static uint8_t npac;
static uint8_t nmrc;
static uint8_t nmstr;
static uint8_t ndid;

/**
 * XRDC - Master Domain Assignment Controller
 *
 * The MDAC submodule is responsible for the generation of the Domain ID on
 * every memory transaction for every bus master in the device. The resulting
 * domain ID and {non-secure, privileged} signals are generated and the treated
 * as address attributes and associated with each transaction as it moves
 * through the system.
 *
 * There are two type of domain assignments:
 * - Processor-core domain assignment (DFMT0: CM4CODE, CM4SYS, CA7)
 * - Non-processor domain assignment (DFMT1: CM4DMA, LCDIF, GPU3D, CA7DMA,
 *	AXBS2NIC1, CAAM, USB0/1, VIU, SDHC0, SDHC1, GPU2D)
 *
 * Processor-core masters typically support one or more domain definition
 * (w0 - w1).
 * Non-processor masters support a single domain definition (w0).
 *
 */
static const struct mda_setting mda_setting_7ulp[] = {
	/* Domain 0: M4 */
	{MDA_CM4CODE,	MDA_DOMAIN_0,	0},
	{MDA_CM4SYS,	MDA_DOMAIN_0,	0},
	{MDA_CM4DMA,	MDA_DOMAIN_0,	0},
	/* Domain 1: CA7 */
	{MDA_CA7,	MDA_DOMAIN_1,	0},
	{MDA_CA7DMA,	MDA_DOMAIN_1,	0},
	{MDA_AXBS2NIC1,	MDA_DOMAIN_1,	0},
	{MDA_CAAM,	MDA_DOMAIN_1,	0},
	{(-1),		0,		0},
};

/**
 * XRDC - Memory region DxACP evaluation
 *
 * 1/ If the access does not hit in any region descriptor, an access error is
 * reported.
 *
 * 2/ If the access hits in a single region descriptor and that region signals
 * a domain violation, then an access error is reported.
 *
 * 3/ If the access hits in multiple (overlapping) regions and all regions
 * signal violations, then an access error is reported.
 * The priority is given to permission GRANTING over access denying for
 * overlapping regions.
 *
 * Be careful when overlapping secure and non-secure memory regions !
 *
 * Regions base addresses must be aligned on the region size.
 *
 */
static const struct mrc_setting mrc_setting_7ulp[] = {
	/*
	 * Tightly Couple Memories - M4 SRAM
	 *
	 * Region 0: 0x1FFD0000 - 0x1FFDFFFF NS
	 * Region 1: 0x1FFE0000 - 0x1FFFFFFF NS (0x1FFFC000
	 *					- 0x1FFFFFFF disabled)
	 * Region 2: 0x1FFFC000 - 0x1FFFFFFF Secure Optee PM (LVL2-Secure Priv)
	 * Region 3: 0x20000000 - 0x2000FFFF NS
	 */
	{MRC_M4_TCM, MRC_REGION_0, M4_SRAM_L_BASE, XRDC_REGION_SZ_64K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},
	{MRC_M4_TCM, MRC_REGION_1,
		M4_SRAM_L_BASE + XRDC_SZ_SIZE(XRDC_REGION_SZ_64K) + 1,
		XRDC_REGION_SZ_128K, XRDC_SUBREGION_DIS_7,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},
	{MRC_M4_TCM, MRC_REGION_2, LP_OCRAM_START, XRDC_REGION_SZ_16K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL0},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL2},
			{(-1), 0}, /* End */
		},
	},
	{MRC_M4_TCM, MRC_REGION_3, M4_SRAM_U_BASE, XRDC_REGION_SZ_64K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * Quad SPI Interface
	 *
	 * Region 0: 0xC0000000 - 0xC000FFFF NS
	 */
	{MRC_QSPI, MRC_REGION_0, QSPI_BASE, XRDC_REGION_SZ_64K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * SRAM0
	 *
	 * Region 0: 0x2F000000 - 0x2F01FFFF NS
	 */
	{MRC_SRAM0, MRC_REGION_0, SRAM0_BASE, XRDC_REGION_SZ_128K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * SecureRAM
	 *
	 * Region 0: 0x26000000 - 0x26007FFF NS
	 */
	{MRC_SECRAM, MRC_REGION_0, SECRAM_BASE,	XRDC_REGION_SZ_32K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * FlexBus
	 *
	 * Region 0: 0xB0000000 - 0xBFFFFFFF NS
	 */
	{MRC_FLEXBUS, MRC_REGION_0, FLEXBUS_BASE, XRDC_REGION_SZ_256M, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * SRAM1
	 *
	 * Region 0: 0x2F020000 - 0x2F03FFFF NS
	 */
	{MRC_SRAM1, MRC_REGION_0, SRAM1_BASE, XRDC_REGION_SZ_128K, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},

	/*
	 * MMDC
	 *
	 * Region 0: 0x60000000 - 0x6FFFFFFF NS (0x64000000
	 *					- 0x66000000 disabled)
	 * Region 1: 0x64000000 - 0x65BFFFFF Secure Optee RAM (LVL3-Secure User)
	 * Region 2: 0x65C00000 - 0x65FFFFFF NS Shared Memory
	 * Region 3: 0x70000000 - 0x7FFFFFFF NS
	 * Region 4: 0x80000000 - 0x9FFFFFFF NS
	 */
	{MRC_MMDC, MRC_REGION_0, DRAM0_BASE, XRDC_REGION_SZ_256M,
		XRDC_SUBREGION_DIS_2,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},
	{MRC_MMDC, MRC_REGION_1, CFG_TZDRAM_START, XRDC_REGION_SZ_32M, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL0},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL3},
			{(-1), 0},
		},
	},
	{MRC_MMDC, MRC_REGION_2, CFG_SHMEM_START, XRDC_REGION_SZ_4M, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0},
		},
	},
	{MRC_MMDC, MRC_REGION_3,
		DRAM0_BASE + XRDC_SZ_SIZE(XRDC_REGION_SZ_256M) + 1,
		XRDC_REGION_SZ_256M, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},
	{MRC_MMDC, MRC_REGION_4,
		DRAM0_BASE + XRDC_SZ_SIZE(XRDC_REGION_SZ_512M) + 1,
		XRDC_REGION_SZ_512M, 0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0}, /* End */
		},
	},
	/* End */
	{(-1), 0, 0, 0, 0,
		{
			{(-1),		0},
		},
	},
};

/**
 * XRDC - Peripheral Domain Access Control
 *
 * Defines access control policies per domain for each implemented slave
 * peripheral.
 *
 */
static const struct pac_setting pac_setting_7ulp[] = {
	{CM4_AIPS0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0},
		},
	},
	{CM4_AIPS1,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0},
		},
	},
	{CA7_AHB_PBRIDGE0,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0},
		},
	},
	{CA7_AHB_PBRIDGE1,
		{
			{MDA_DOMAIN_0, XRDC_POLICY_LVL7},
			{MDA_DOMAIN_1, XRDC_POLICY_LVL7},
			{(-1), 0},
		},
	},
	{(-1),
		{
			{(-1), 0},
		},
	},
};

/**
 * @brief      Calculate policy registers
 *
 * @param[in]  policy  The policy configuration
 *
 * @return     register value, -1 if error
 */
static int xrdc_set_policy(const struct domain_policy policy[])
{
	const struct domain_policy *p = NULL;
	uint32_t val = 0;

	if (!policy)
		return -1;

	p = policy;

	while (p->domain_id >= 0) {
		val |= p->policy << (p->domain_id * 3);
		p++;
	}

	return val;
}

/**
 * @brief      Configure each memory region
 *
 * @param      xrdc_reg  The xrdc register
 * @param[in]  mrc       The region configuration
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_mrc_set_region(struct xrdc_reg_desc *xrdc_reg,
			       const struct mrc_setting *mrc)
{
	int policy;
	uint32_t val;

	if (!xrdc_reg || !mrc)
		return -1;

	/* Memory slave id valid */
	if (mrc->memory_slave > nmrc) {
		EMSG("Number of memory slave: %d", nmrc);
		return -1;
	}

	/* Check number region */
	if (mrc->region > XRDC_NB_REGION_MAX) {
		EMSG("Number region maximum: %d", XRDC_NB_REGION_MAX);
		return -1;
	}

	/* Base address must be aligned with the region size */
	if (mrc->base_addr & XRDC_SZ_SIZE(mrc->size)) {
		EMSG("Base address must be aligned with the size");
		return -1;
	}

	/* Set policies for each domain */
	policy = xrdc_set_policy(mrc->policy);
	if (policy < 0)
		return -1;

	xrdc_reg->mrgd[mrc->memory_slave][mrc->region].w0 = mrc->base_addr
						& XRDC_MRGD_W0_BASEADDR_MASK;

	val = (mrc->size << XRDC_MRGD_W1_SZ_OFFSET) & XRDC_MRGD_W1_SZ_MASK;
	val |= (mrc->subregion << XRDC_MRGD_W1_SRD_OFFSET)
		& XRDC_MRGD_W1_SRD_MASK;
	xrdc_reg->mrgd[mrc->memory_slave][mrc->region].w1 = val;
	xrdc_reg->mrgd[mrc->memory_slave][mrc->region].w2 = policy;
	xrdc_reg->mrgd[mrc->memory_slave][mrc->region].w3
						= XRDC_MRGD_W3_VLD_MASK;

	IMSG("XRDC: MRC: %d Region: %d Start: 0x%X Size: 0x%X Policies: 0x%X",
				mrc->memory_slave, mrc->region,
				(uint32_t)mrc->base_addr,
				XRDC_SZ_SIZE(mrc->size), policy);

	return 0;
}

/**
 * @brief      Configure each bus master and associated domain.
 *
 * @param      xrdc_reg  The xrdc register
 * @param[in]  mda       The master domain configuration
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_mda_set_domain(struct xrdc_reg_desc *xrdc_reg,
			       const struct mda_setting *mda)
{
	uint32_t val = 0;

	if (!xrdc_reg || !mda)
		return -1;

	/* Check bus master id */
	if (mda->bus_master > nmstr) {
		EMSG("Number of bus_master: %d", nmstr);
		return -1;
	}

	/* Check domain id */
	if (mda->domain_id > ndid) {
		EMSG("Number of domain: %d", ndid);
		return -1;
	}

	/* Check domain instance */
	if (mda->definition == 1 && (mda->bus_master != 0
					&& mda->bus_master != 1
					&& mda->bus_master != 3)) {
		EMSG("Only bus master 0-1-3 have 2 instances");
		return -1;
	}

	val |= (mda->domain_id << XRDC_MDA_DFMT0_DID_OFFSET) &
						XRDC_MDA_DFMT0_DID_MASK;
	val |= XRDC_MDA_DFMT0_VLD_MASK;

	if (mda->definition == 1)
		xrdc_reg->mda[mda->bus_master].w1 = val;
	else
		xrdc_reg->mda[mda->bus_master].w0 = val;

	IMSG("XRDC: MDA: %d Domain: %d Instance: %d", mda->bus_master,
							mda->domain_id,
							mda->definition);

	return 0;
}

/**
 * @brief      Configure each peripheral
 *
 * @param      xrdc_reg  The xrdc register
 * @param[in]  pac       The peripheral configuration
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_pac_set_peripheral(struct xrdc_reg_desc *xrdc_reg,
					const struct pac_setting *pac)
{
	int policy;

	if (!xrdc_reg || !pac)
		return -1;

	/* Check peripheral ID */
	if (pac->peripheral > npac) {
		EMSG("Number of peripheral: %d", npac);
		return -1;
	}

	policy = xrdc_set_policy(pac->policy);
	if (policy < 0)
		return -1;

	xrdc_reg->pdac[pac->peripheral].w0 = policy;
	xrdc_reg->pdac[pac->peripheral].w1 = XRDC_MDA_DFMT0_VLD_MASK;

	return 0;
}


/**
 * @brief      Initialize Peripheral Access controller submodule
 *
 * @param      xrdc_reg  The xrdc register
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_pac_init(struct xrdc_reg_desc *xrdc_reg)
{
	const struct pac_setting *pac = NULL;
	uint32_t ret = 0;

	if (soc_is_imx7ulp())
		pac = pac_setting_7ulp;
	else
		return -1;

	while (pac->peripheral >= 0) {
		ret |= xrdc_pac_set_peripheral(xrdc_reg, pac);
		pac++;
	}

	return 0;
}

/**
 * @brief      Initialize the memory region controller submodule
 *
 * @param      xrdc_reg  The xrdc register
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_mrc_init(struct xrdc_reg_desc *xrdc_reg)
{
	const struct mrc_setting *mrc = NULL;
	uint32_t ret = 0;

	if (soc_is_imx7ulp())
		mrc = mrc_setting_7ulp;
	else
		return -1;

	while (mrc->memory_slave >= 0) {
		ret |= xrdc_mrc_set_region(xrdc_reg, mrc);
		mrc++;
	}

	return ret;
}

/**
 * @brief      Initialize the Master Domain Assignment Controller submodule
 *
 * @param      xrdc_reg  The xrdc register
 *
 * @return     0 if success, -1 otherwise
 */
static int xrdc_mdac_init(struct xrdc_reg_desc *xrdc_reg)
{
	const struct mda_setting *mda = NULL;
	uint32_t ret = 0;

	if (soc_is_imx7ulp())
		mda = mda_setting_7ulp;
	else
		return -1;

	while (mda->bus_master >= 0) {
		ret |= xrdc_mda_set_domain(xrdc_reg, mda);
		mda++;
	}

	return ret;
}

/**
 * @brief      Read XRDC hardware configuration
 *
 * @param      xrdc_reg  The xrdc register
 */
static void xrdc_read_cfg(struct xrdc_reg_desc *xrdc_reg)
{
	uint32_t reg = xrdc_reg->hwcfg[0];

	npac = ((reg & XRDC_HWCFG0_NPAC_MASK) >> XRDC_HWCFG0_NPAC_OFFSET) + 1;
	nmrc = ((reg & XRDC_HWCFG0_NMRC_MASK) >> XRDC_HWCFG0_NMRC_OFFSET) + 1;
	nmstr = ((reg & XRDC_HWCFG0_NMSTR_MASK)
					>> XRDC_HWCFG0_NMSTR_OFFSET) + 1;
	ndid = ((reg & XRDC_HWCFG0_NDID_MASK) >> XRDC_HWCFG0_NDID_OFFSET) + 1;
}

static TEE_Result pm_enter_resume(enum pm_op op, uint32_t pm_hint,
		const struct pm_callback_handle *pm_handle __unused);

/**
 * @brief      Initialize XRDC module
 *
 * @return     TEE_SUCCESS, panic otherwise.
 */
static TEE_Result xrdc_init(void)
{
	struct xrdc_reg_desc *xrdc_reg = NULL;
	vaddr_t xrdc_va_base_addr;
	vaddr_t ppc_va_base_addr;
	uint32_t val;

	/* Enable XRDC clock gate */
	ppc_va_base_addr = core_mmu_get_va(PPC_BASE, MEM_AREA_IO_SEC);
	if (!ppc_va_base_addr)
		goto error;

	val = read32(ppc_va_base_addr + PPC_XRDC_OFFSET);
	val |= PPC_XRDC_CGC_MASK;
	write32(val, ppc_va_base_addr + PPC_XRDC_OFFSET);

	/* Get xrdc registers */
	xrdc_va_base_addr = core_mmu_get_va(XRDC_BASE, MEM_AREA_IO_SEC);
	if (!xrdc_va_base_addr)
		goto error;
	else
		xrdc_reg = (struct xrdc_reg_desc *)xrdc_va_base_addr;

	/* Read XRDC configuration */
	xrdc_read_cfg(xrdc_reg);

	/* Initialize master domain assignment controller */
	if (xrdc_mdac_init(xrdc_reg))
		goto error;

	/* Initialize memory region controller */
	if (xrdc_mrc_init(xrdc_reg))
		goto error;

	/* Initialize peripheral access controller */
	if (xrdc_pac_init(xrdc_reg))
		goto error;

	/* Register pm callbacks */
	register_pm_driver_cb(pm_enter_resume, NULL);

	/*
	 * Enable XRDC.
	 * This register must NOT be locked. Disabling the XRDC is needed
	 * for suspend/resume.
	 */
	xrdc_reg->cr = XRDC_CR_GVLD_MASK;

	return TEE_SUCCESS;
error:
	panic("XRDC configuration failed");
}
service_init(xrdc_init);

/**
 * @brief      XRDC state resume. During suspend, registers related to memory
 *             region controller are wiped. The XRDC must be reinitialized.
 *
 * @param[in]  pm_hint  The pm hint
 *
 * @return     TEE_SUCCESS if XRDC resume is successful, TEE_ERROR_GENERIC
 *             otherwise
 */
static inline TEE_Result pm_resume(uint32_t pm_hint)
{
	if (pm_hint == PM_HINT_CONTEXT_STATE)
		return xrdc_init();

	return TEE_SUCCESS;
}

/**
 * @brief      XRDC state suspend. Before suspend, XRDC needs to be disabled.
 *             During suspend, registers related to memory region controller are
 *             wiped. When resuming, MMDC access does not hit any region
 *             descriptor because MRC registers are wiped. This results in an
 *             access error.
 *
 * @param[in]  pm_hint  The pm hint
 *
 * @return     TEE_SUCCESS if XRDC suspend is successful, TEE_ERROR_GENERIC
 *             otherwise
 */
static TEE_Result pm_enter(uint32_t pm_hint)
{
	struct xrdc_reg_desc *xrdc_reg = NULL;
	vaddr_t xrdc_va_base_addr;

	if (pm_hint == PM_HINT_CONTEXT_STATE) {
		/* Get xrdc registers */
		xrdc_va_base_addr = core_mmu_get_va(XRDC_BASE, MEM_AREA_IO_SEC);
		if (!xrdc_va_base_addr)
			return TEE_ERROR_GENERIC;

		xrdc_reg = (struct xrdc_reg_desc *)xrdc_va_base_addr;

		/* Disable XRDC */
		xrdc_reg->cr &= ~XRDC_CR_GVLD_MASK;

		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}

/**
 * @brief   Power Management Callback function executed when system
 *          enter or resume from a power mode
 *
 * @param[in] op        Operation mode SUSPEND/RESUME
 * @param[in] pm_hint   Power mode type
 * @param[in] pm_handle Driver private handle (not used)
 *
 * @retval TEE_SUCCESS       Success
 * @retval TEE_GENERIC_ERROR Error during power procedure
 */
static TEE_Result pm_enter_resume(enum pm_op op, uint32_t pm_hint,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_SUSPEND)
		return pm_enter(pm_hint);
	else
		return pm_resume(pm_hint);
}

/**
 * @brief      Disable XRDC before reboot.
 *             During reboot, registers related to memory region controller are
 *             wiped. During restart, MMDC access does not hit any region
 *             descriptor because MRC registers are wiped. This results in an
 *             access error.
 */
void xrdc_reset(void)
{
	struct xrdc_reg_desc *xrdc_reg = NULL;
	vaddr_t xrdc_va_base_addr;

	/* Get xrdc registers */
	xrdc_va_base_addr = core_mmu_get_va(XRDC_BASE, MEM_AREA_IO_SEC);
	if (!xrdc_va_base_addr)
		return;

	xrdc_reg = (struct xrdc_reg_desc *)xrdc_va_base_addr;

	/* Disable XRDC */
	xrdc_reg->cr &= ~XRDC_CR_GVLD_MASK;
}
