/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 */

/**
 * PPC - Peripheral Clock Control
 */
#define PPC_XRDC_OFFSET				0x50
#define PPC_XRDC_CGC_OFFSET			30
#define PPC_XRDC_CGC_MASK			0x40000000

/**
 * CR - Control Register
 */
#define XRDC_CR_GVLD_OFFSET			0
#define XRDC_CR_GVLD_MASK			0x1
#define XRDC_CR_HRL_OFFSET			1
#define XRDC_CR_HRL_MASK			0x1E
#define XRDC_CR_MRF_OFFSET			7
#define XRDC_CR_MRF_MASK			0x80
#define XRDC_CR_VAW_OFFSET			8
#define XRDC_CR_VAW_MASK			0x100
#define XRDC_CR_LK1_OFFSET			30
#define XRDC_CR_LK1_MASK			0x40000000

/**
 * HWCFG0 - Hardware Control Register 0
 */
#define XRDC_HWCFG0_NDID_OFFSET			0
#define XRDC_HWCFG0_NDID_MASK			0xFF
#define XRDC_HWCFG0_NMSTR_OFFSET		8
#define XRDC_HWCFG0_NMSTR_MASK			0xFF00
#define XRDC_HWCFG0_NMRC_OFFSET			16
#define XRDC_HWCFG0_NMRC_MASK			0xFF0000
#define XRDC_HWCFG0_NPAC_OFFSET			24
#define XRDC_HWCFG0_NPAC_MASK			0xF000000
#define XRDC_HWCFG0_MID_OFFSET			28
#define XRDC_HWCFG0_MID_MASK			0xF0000000

/**
 * HWCFG1 - Hardware Control Register 1
 */
#define XRDC_HWCFG1_DID_OFFSET			0
#define XRDC_HWCFG1_DID_MASK			0xF

/**
 * HWCFG2 - Hardware Control Register 2
 */
#define XRDC_HWCFG2_PIDP0_OFFSET		0
#define XRDC_HWCFG2_PID01_OFFSET		1
#define XRDC_HWCFG2_PIDP2_OFFSET		2
#define XRDC_HWCFG2_PIDP3_OFFSET		3
#define XRDC_HWCFG2_PIDP4_OFFSET		4
#define XRDC_HWCFG2_PIDP5_OFFSET		5
#define XRDC_HWCFG2_PIDP6_OFFSET		6
#define XRDC_HWCFG2_PIDP7_OFFSET		7
#define XRDC_HWCFG2_PIDP8_OFFSET		8
#define XRDC_HWCFG2_PIDP9_OFFSET		9
#define XRDC_HWCFG2_PIDP10_OFFSET		10
#define XRDC_HWCFG2_PIDP11_OFFSET		11
#define XRDC_HWCFG2_PIDP12_OFFSET		12
#define XRDC_HWCFG2_PIDP13_OFFSET		13
#define XRDC_HWCFG2_PIDP14_OFFSET		14
#define XRDC_HWCFG2_PIDP15_OFFSET		15
#define XRDC_HWCFG2_PIDP16_OFFSET		16
#define XRDC_HWCFG2_PIDP17_OFFSET		17
#define XRDC_HWCFG2_PIDP18_OFFSET		18
#define XRDC_HWCFG2_PIDP19_OFFSET		19
#define XRDC_HWCFG2_PIDP20_OFFSET		20
#define XRDC_HWCFG2_PIDP21_OFFSET		21
#define XRDC_HWCFG2_PIDP22_OFFSET		22
#define XRDC_HWCFG2_PIDP23_OFFSET		23
#define XRDC_HWCFG2_PIDP24_OFFSET		24
#define XRDC_HWCFG2_PIDP25_OFFSET		25
#define XRDC_HWCFG2_PIDP26_OFFSET		26
#define XRDC_HWCFG2_PIDP27_OFFSET		27
#define XRDC_HWCFG2_PIDP28_OFFSET		28
#define XRDC_HWCFG2_PIDP29_OFFSET		29
#define XRDC_HWCFG2_PIDP30_OFFSET		30
#define XRDC_HWCFG2_PIDP31_OFFSET		31

/*
 * MDACFG - Master Domain Assignment Configuration
 */
#define XRDC_MDACFG_NMDAR_OFFSET		0
#define XRDC_MDACFG_NMDAR_MASK			0xF
#define XRDC_MDACFG_NCM_OFFSET			4
#define XRDC_MDACFG_NCM_MASK			0x80

/**
 * MRCFG - Memory Region Configuration
 */
#define XRDC_MRCFG_NMRGD_OFFSET			0
#define XRDC_MRCFG_NMRGD_MASK			0x1F

/**
 * DERRLOC - Domain Error Location
 */
#define XRDC_DERRLOC_MRCINST_OFFSET		0
#define XRDC_DERRLOC_MRCINST_MASK		0xFFFF
#define XRDC_DERRLOC_PACINST_OFFSET		16
#define XRDC_DERRLOC_PACINST_MASK		0xF0000

/**
 * DERR - Domain Error Words
 */
#define XRDC_DERR_W0_EADDR_OFFSET		0
#define XRDC_DERR_W0_EADDR_MASK			0xFFFFFFFF
#define XRDC_DERR_W1_EDID_OFFSET		0
#define XRDC_DERR_W1_EDID_MASK			0xF
#define XRDC_DERR_W1_EATR_OFFSET		8
#define XRDC_DERR_W1_EATR_MASK			0x700
#define XRDC_DERR_W1_ERW_OFFSET			11
#define XRDC_DERR_W1_ERW_MASK			0x800
#define XRDC_DERR_W1_EPORT_OFFSET		24
#define XRDC_DERR_W1_EPORT_MASK			0x7000000
#define XRDC_DERR_W1_EST_OFFSET			30
#define XRDC_DERR_W1_EST_MASK			0xC0000000
#define XRDC_DERR_W3_RECR_OFFSET		30
#define XRDC_DERR_W3_RECR_MASK			0xC0000000

/**
 * PID - Process Identifier
 */
#define XRDC_PID_PID_OFFSET			0
#define XRDC_PID_PID_MASK			0x3F
#define XRDC_PID_LMNUM_OFFSET			16
#define XRDC_PID_LMNUM_MASK			0x3F0000
#define XRDC_PID_ELK22H_OFFSET			24
#define XRDC_PID_ELK22H_MASK			0x1000000
#define XRDC_PID_TSM_OFFSET			28
#define XRDC_PID_TSM_MASK			0x10000000
#define XRDC_PID_LK2_OFFSET			29
#define XRDC_PID_LK2_MASK			0x60000000

/**
 * MDA - Master Domain Assignment DFMT0
 */
#define XRDC_MDA_DFMT0_DID_OFFSET		0
#define XRDC_MDA_DFMT0_DID_MASK			0x7
#define XRDC_MDA_DFMT0_DIDS_OFFSET		4
#define XRDC_MDA_DFMT0_DIDS_MASK		0x30
#define XRDC_MDA_DFMT0_PE_OFFSET		6
#define XRDC_MDA_DFMT0_PE_MASK			0xC0
#define XRDC_MDA_DFMT0_PIDM_OFFSET		8
#define XRDC_MDA_DFMT0_PIDM_MASK		0x3F00
#define XRDC_MDA_DFMT0_PID_OFFSET		16
#define XRDC_MDA_DFMT0_PID_MASK			0x3F0000
#define XRDC_MDA_DFMT0_LK1_OFFSET		30
#define XRDC_MDA_DFMT0_LK1_MASK			0x40000000
#define XRDC_MDA_DFMT0_VLD_OFFSET		31
#define XRDC_MDA_DFMT0_VLD_MASK			0x80000000

/**
 * MDA - Master Domain Assignment DFMT1
 */
#define XRDC_MDA_DFMT1_DID_OFFSET		0
#define XRDC_MDA_DFMT1_DID_MASK			0x7
#define XRDC_MDA_DFMT1_PA_OFFSET		4
#define XRDC_MDA_DFMT1_PA_MASK			0x30
#define XRDC_MDA_DFMT1_SA_OFFSET		6
#define XRDC_MDA_DFMT1_SA_MASK			0xC0
#define XRDC_MDA_DFMT1_DIDB_OFFSET		8
#define XRDC_MDA_DFMT1_DIDB_MASK		0x100
#define XRDC_MDA_DFMT1_LPID_OFFSET		24
#define XRDC_MDA_DFMT1_LPID_MASK		0xF000000
#define XRDC_MDA_DFMT1_LK1_OFFSET		30
#define XRDC_MDA_DFMT1_LK1_MASK			0x40000000
#define XRDC_MDA_DFMT1_VLD_OFFSET		31
#define XRDC_MDA_DFMT1_VLD_MASK			0x80000000

/**
 * PDAC - Peripheral Domain Access Control
 */
#define XRDC_PDAC_W0_D0ACP_OFFSET		0
#define XRDC_PDAC_W0_D0ACP_MASK			0x7
#define XRDC_PDAC_W0_D1ACP_OFFSET		3
#define XRDC_PDAC_W0_D1ACP_MASK			0x38
#define XRDC_PDAC_W0_D2ACP_OFFSET		6
#define XRDC_PDAC_W0_D2ACP_MASK			0x1C0
#define XRDC_PDAC_W0_D3ACP_OFFSET		9
#define XRDC_PDAC_W0_D3ACP_MASK			0xE00
#define XRDC_PDAC_W0_D4ACP_OFFSET		12
#define XRDC_PDAC_W0_D4ACP_MASK			0x7000
#define XRDC_PDAC_W0_D5ACP_OFFSET		15
#define XRDC_PDAC_W0_D5ACP_MASK			0x38000
#define XRDC_PDAC_W0_D6ACP_OFFSET		18
#define XRDC_PDAC_W0_D6ACP_MASK			0x1C8000
#define XRDC_PDAC_W0_D7ACP_OFFSET		21
#define XRDC_PDAC_W0_D7ACP_MASK			0xE00000
#define XRDC_PDAC_W0_SNUM_OFFSET		24
#define XRDC_PDAC_W0_SNUM_MASK			0xF000000
#define XRDC_PDAC_W0_SE_OFFSET			30
#define XRDC_PDAC_W0_SE_MASK			0x40000000

/**
 * MRGD - Memory Region Descriptor
 */
#define XRDC_MRGD_W0_BASEADDR_OFFSET		5
#define XRDC_MRGD_W0_BASEADDR_MASK		0xFFFFFFE0
#define XRDC_MRGD_W1_SRD_OFFSET			0
#define XRDC_MRGD_W1_SRD_MASK			0xFF
#define XRDC_MRGD_W1_SZ_OFFSET			8
#define XRDC_MRGD_W1_SZ_MASK			0x1F00
#define XRDC_MRGD_W2_D0ACP_OFFSET		0
#define XRDC_MRGD_W2_D0ACP_MASK			0x7
#define XRDC_MRGD_W2_D1ACP_OFFSET		3
#define XRDC_MRGD_W2_D1ACP_MASK			0x38
#define XRDC_MRGD_W2_D2ACP_OFFSET		6
#define XRDC_MRGD_W2_D2ACP_MASK			0x1C0
#define XRDC_MRGD_W2_D3ACP_OFFSET		9
#define XRDC_MRGD_W2_D3ACP_MASK			0xE00
#define XRDC_MRGD_W2_D4ACP_OFFSET		12
#define XRDC_MRGD_W2_D4ACP_MASK			0x7000
#define XRDC_MRGD_W2_D5ACP_OFFSET		15
#define XRDC_MRGD_W2_D5ACP_MASK			0x38000
#define XRDC_MRGD_W2_D6ACP_OFFSET		18
#define XRDC_MRGD_W2_D6ACP_MASK			0x1C8000
#define XRDC_MRGD_W2_D7ACP_OFFSET		21
#define XRDC_MRGD_W2_D7ACP_MASK			0xE00000
#define XRDC_MRGD_W2_SNUM_OFFSET		24
#define XRDC_MRGD_W2_SNUM_MASK			0xF000000
#define XRDC_MRGD_W2_SE_OFFSET			30
#define XRDC_MRGD_W2_SE_MASK			0x40000000
#define XRDC_MRGD_W3_LK2_OFFSET			29
#define XRDC_MRGD_W3_LK2_MASK			0x60000000
#define XRDC_MRGD_W3_VLD_OFFSET			31
#define XRDC_MRGD_W3_VLD_MASK			0x80000000

/**
 * MRC Subregion Enable-Disable
 */
#define XRDC_SUBREGION_DIS_0			BIT(0)
#define XRDC_SUBREGION_DIS_1			BIT(1)
#define XRDC_SUBREGION_DIS_2			BIT(2)
#define XRDC_SUBREGION_DIS_3			BIT(3)
#define XRDC_SUBREGION_DIS_4			BIT(4)
#define XRDC_SUBREGION_DIS_5			BIT(5)
#define XRDC_SUBREGION_DIS_6			BIT(6)
#define XRDC_SUBREGION_DIS_7			BIT(7)

/**
 * XRDC - Domain Access Control Policy
 *
 *		SecPriv		SecUser		NSecPriv	NSecUser
 * LVL7-111	RW		RW		RW		RW
 * LVL6-110	RW		RW		RW		None
 * LVL5-101	RW		RW		R		R
 * LVL4-100	RW		RW		R		None
 * LVL3-011	RW		RW		None		None
 * LVL2-010	RW		None		None		None
 * LVL1-001	R		R		None		None
 * LVL0-000	None		None		None		None
 */
enum xrdc_policy {
	XRDC_POLICY_LVL0 = 0x0,
	XRDC_POLICY_LVL1 = 0x1,
	XRDC_POLICY_LVL2 = 0x2,
	XRDC_POLICY_LVL3 = 0x3,
	XRDC_POLICY_LVL4 = 0x4,
	XRDC_POLICY_LVL5 = 0x5,
	XRDC_POLICY_LVL6 = 0x6,
	XRDC_POLICY_LVL7 = 0x7,
};

/**
 * SZ - Memory region sizes
 */
enum xrdc_region_size {
	XRDC_REGION_SZ_32B	= 4,
	XRDC_REGION_SZ_64B	= 5,
	XRDC_REGION_SZ_128B	= 6,
	XRDC_REGION_SZ_256B	= 7,
	XRDC_REGION_SZ_512B	= 8,
	XRDC_REGION_SZ_1K	= 9,
	XRDC_REGION_SZ_2K	= 10,
	XRDC_REGION_SZ_4K	= 11,
	XRDC_REGION_SZ_8K	= 12,
	XRDC_REGION_SZ_16K	= 13,
	XRDC_REGION_SZ_32K	= 14,
	XRDC_REGION_SZ_64K	= 15,
	XRDC_REGION_SZ_128K	= 16,
	XRDC_REGION_SZ_256K	= 17,
	XRDC_REGION_SZ_512K	= 18,
	XRDC_REGION_SZ_1M	= 19,
	XRDC_REGION_SZ_2M	= 20,
	XRDC_REGION_SZ_4M	= 21,
	XRDC_REGION_SZ_8M	= 22,
	XRDC_REGION_SZ_16M	= 23,
	XRDC_REGION_SZ_32M	= 24,
	XRDC_REGION_SZ_64M	= 25,
	XRDC_REGION_SZ_128M	= 26,
	XRDC_REGION_SZ_256M	= 27,
	XRDC_REGION_SZ_512M	= 28,
	XRDC_REGION_SZ_1G	= 29,
	XRDC_REGION_SZ_2G	= 30,
	XRDC_REGION_SZ_4G	= 31,
};

/**
 * MDA - Domain ID
 */
enum mda_domain_id {
	MDA_DOMAIN_0 = 0,
	MDA_DOMAIN_1 = 1,
	MDA_DOMAIN_2 = 2,
	MDA_DOMAIN_3 = 3,
	MDA_DOMAIN_4 = 4,
	MDA_DOMAIN_5 = 5,
	MDA_DOMAIN_6 = 6,
	MDA_DOMAIN_7 = 7,
};

/**
 * MRC - Slave memory
 */
enum mrc_slave_memory {
	MRC_M4_TCM = 0,
	MRC_QSPI,
	MRC_SRAM0,
	MRC_SECRAM,
	MRC_FLEXBUS,
	MRC_SRAM1,
	MRC_MMDC,
};

/**
 * MRC - Region Number
 */
enum mrc_region_number {
	MRC_REGION_0 = 0,
	MRC_REGION_1,
	MRC_REGION_2,
	MRC_REGION_3,
	MRC_REGION_4,
	MRC_REGION_5,
	MRC_REGION_6,
	MRC_REGION_7,
	MRC_REGION_8,
	MRC_REGION_9,
	MRC_REGION_10,
	MRC_REGION_11,
	MRC_REGION_12,
	MRC_REGION_13,
	MRC_REGION_14,
	MRC_REGION_15,
};

/**
 *  MDA - Bus Master
 */
enum mda_bus_master {
	MDA_CM4CODE = 0,
	MDA_CM4SYS,
	MDA_CM4DMA,
	MDA_CA7,
	MDA_LCDIF,
	MDA_GPU3D,
	MDA_CA7DMA,
	MDA_AXBS2NIC1,
	MDA_CAAM,
	MDA_USB0_1,
	MDA_VIU,
	MDA_SDHC0,
	MDA_SDHC1,
	MDA_GPU2D,
};

/**
 * PAC - Peripheral Access Control
 */
enum pac_periph {
	CM4_AIPS0 = 0,
	CM4_AIPS1,
	CA7_AHB_PBRIDGE0,
	CA7_AHB_PBRIDGE1,
};

/**
 * @brief      Domain policies
 */
struct domain_policy {
	int				domain_id;
	uint8_t				policy;
};

/**
 * @brief      Master domain assignment setting
 */
struct mda_setting {
	int				bus_master;
	uint8_t				domain_id;
	uint8_t				definition;
};

/**
 * @brief      Memory region controller setting
 */
struct mrc_setting {
	int				memory_slave;
	uint32_t			region;
	paddr_t				base_addr;
	uint32_t			size;
	uint8_t				subregion;
	const struct domain_policy	policy[8];
};

/**
 * @brief      Peripheral access controller setting
 */
struct pac_setting {
	int				peripheral;
	const struct domain_policy	policy[8];
};

/**
 * @brief      XRDC Registers
 */
struct xrdc_reg_desc {
	/* Control registers		0x00 */
	uint32_t cr;
	uint8_t reserved0[236];

	/* Hardware control register	0xF0 */
	uint32_t hwcfg[3];
	uint8_t reserved1[4];

	/* Master domain assignment	0x100 */
	uint8_t mdacfg[14];
	uint8_t reserved2[50];

	/* Memory region configuration	0x140 */
	uint8_t mrcfg[7];
	uint8_t reserved3[185];

	/* Domain error location	0x200 */
	uint32_t derrloc[8];
	uint8_t reserved4[480];

	/* Domain error word		0x400 */
	uint32_t derr[20][4];
	uint8_t res5[448];

	/* Process identifier		0x700 */
	uint32_t pid[14];
	uint8_t res6[200];

	/* Master domain assignment	0x800 */
	/* DFMT0: mda[0-1-3].w0-1 */
	/* DFMT1: mda[2-4-5-6-7-8-9-10-11-12-13].w0 */
	struct {
		uint32_t w0;
		uint32_t w1;
		uint32_t w2_unused;
		uint32_t w3_unused;
		uint32_t w4_unused;
		uint32_t w5_unused;
		uint32_t w6_unused;
		uint32_t w7_unused;
	} mda[14];
	uint8_t res10[1598];

	/* Peripheral domain access control 0x1004 */
	struct {
		uint32_t w0;
		uint32_t w1;
	} pdac[512];

	/* Memory region descriptor	0x2000 */
	struct {
		uint32_t w0;
		uint32_t w1;
		uint32_t w2;
		uint32_t w3;
		uint32_t w4_unused;
		uint32_t w5_unused;
		uint32_t w6_unused;
		uint32_t w7_unused;
	} mrgd[7][16];
};
