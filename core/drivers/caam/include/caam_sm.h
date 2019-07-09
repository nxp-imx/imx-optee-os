/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_sm.h
 *
 * @brief   CAAM Secure memory module header.
 */
#ifndef __CAAM_SM_H__
#define __CAAM_SM_H__

#include "caam_status.h"

/* Job ring secure memory virtual base address register */
#define JRx_SMVBAR(jr)			(0x184 + (0x8 * jr))

/* Secure memory command register */
#define JRx_SMCR(jr_addr)		(jr_addr + 0x0BE4)
#define SMCR_CMD_OFF			0
#define SMCR_CMD_MASK			SHIFT_U32(0xF, SMCR_CMD_OFF)
#define SMCR_PRTN_OFF			8
#define SMCR_PRTN_MASK			SHIFT_U32(0xF, SMCR_PRTN_OFF)
#define SMCR_PAGE_OFF			16
#define SMCR_PAGE_MASK			SHIFT_U32(0xFFFF, SMCR_PAGE_OFF)
#define SMCR_PRTN(smcr)			((smcr << SMCR_PRTN_OFF)	\
						& SMCR_PRTN_MASK)
#define SMCR_PAGE(smcr)			((smcr << SMCR_PAGE_OFF)	\
						& SMCR_PAGE_MASK)
#define SMCR_CMD(smcr)			((smcr << SMCR_CMD_OFF)		\
						& SMCR_CMD_MASK)
#define CMD_PAGE_ALLOC			0x1
#define CMD_PAGE_DEALLOC		0x2
#define CMD_PART_DEALLOC		0x3
#define CMD_PAGE_INQ			0x5

/* Secure memory command status register */
#define JRx_SMCSR(jr_addr)		(jr_addr + 0x0BEC)
#define SMCSR_CERR_OFF			14
#define SMCSR_CERR_MASK			SHIFT_U32(0x3, SMCSR_CERR_OFF)
#define SMCSR_AERR_OFF			12
#define SMCSR_AERR_MASK			SHIFT_U32(0x3, SMCSR_AERR_OFF)
#define SMCSR_PO_OFF			6
#define SMCSR_PO_MASK			SHIFT_U32(0x3, SMCSR_PO_OFF)
#define SMCSR_CERR(smcsr)		((smcsr & SMCSR_CERR_MASK)	\
						>> SMCSR_CERR_OFF)
#define SMCSR_AERR(smcsr)		((smcsr & SMCSR_AERR_MASK)	\
						>> SMCSR_AERR_OFF)
#define SMCSR_PO(smcsr)			((smcsr & SMCSR_PO_MASK)	\
						>> SMCSR_PO_OFF)
#define SMCSR_PO_AVAIL			0x0
#define SMCSR_PO_NOT_EXIST		0x1
#define SMCSR_PO_OWNED_OTHER		0x2
#define SMCSR_PO_OWNED			0x3
#define SMCSR_CERR_NO_ERROR		0x00
#define SMCSR_CERR_NOT_COMPL		0x01
#define SMCSR_AERR_NO_ERROR		0x00
#define SMCSR_AERR_PAGE_AVAIL_ERROR	0x02
#define SMCSR_AERR_PART_OWNER_ERROR	0x03

/* Secure memory partition owner register */
#define JRx_SMPO(jr_addr)		(jr_addr + 0x0FBC)
#define POx_OFF(prtn)			(prtn * 2)
#define POx_OWNER(prtn)			SHIFT_U32(0x3, POx_OFF(prtn))
#define SMPO_POx_AVAIL			0x0
#define SMPO_POx_NOT_EXIST		0x1
#define SMPO_POx_OWNED_OTHER		0x2
#define SMPO_POx_OWNED			0x3

/* Secure memory version ID register SMVID_MS */
#define SMVID_MS			(0x0FD8)

/* Secure memory version ID register SMVID_LS */
#define SMVID_LS			(0x0FDC)

/* Secure memory access permissions register */
#define PG0_SMAPR(x)			(x + 0x0A04)
#define JRx_SMAPR(x, y)			(x + 0x0A04 + (y * 16))
#define SMAPR_CSP			BIT(15)
#define SMAPR_SMAP_LOCK			BIT(13)
#define SMAPR_SMAG_LOCK			BIT(12)
#define SMAPR_G1_SMBLOB			BIT(3)

/* Secure memory access group register */
#define PG0_SMAG2(jr_addr)		(jr_addr + 0x0A08)
#define PG0_SMAG1(jr_addr)		(jr_addr + 0x0A0C)
#define JRx_SMAG2(jr_addr, prtn)	(jr_addr + 0x0A08 + (prtn * 16))
#define JRx_SMAG1(jr_addr, prtn)	(jr_addr + 0x0A0C + (prtn * 16))
#define MID_A7_OFF			0x1
#define MID_A7				SHIFT_U32(0x1, MID_A7_OFF)

/* Secure memory version ID */
#define PSIZ_OFF			16
#define PSIZ_MASK			SHIFT_U32(0x7, PSIZ_OFF)
#define MAX_NPAG_OFF			16
#define MAX_NPAG_MASK			SHIFT_U32(0x3FF, MAX_NPAG_OFF)
#define NPRT_OFF			12
#define NPRT_MASK			SHIFT_U32(0xF, NPRT_OFF)

/**
 * @brief      Secure memory partition
 */
enum sm_partition {
	PARTITION_0 = 0,
	PARTITION_1,
	PARTITION_2,
	PARTITION_3,
	PARTITION_4,
	PARTITION_5,
	PARTITION_6,
	PARTITION_7,
};

/**
 * @brief      Secure memory page
 */
enum sm_page {
	PAGE_0 = 0,
	PAGE_1,
	PAGE_2,
	PAGE_3,
	PAGE_4,
	PAGE_5,
	PAGE_6,
	PAGE_7,
};

/**
 * @brief      Secure memory data
 */
struct sm_data {
	paddr_t sm_dma_addr;	///< Secure memory base address
	vaddr_t sm_va;		///< Secure memory virtual base address
	uint32_t partition;	///< Partition number
	uint32_t page;		///< Page number
	uint32_t page_size;	///< Page size
};

/**
 * @brief	CAAM Secure memory module initialization
 *
 * @param[in]	jr_cfg	JR configuration structure
 *
 * @retval	CAAM_OUT_MEMORY
 * @retval	CAAM_FAILURE
 * @retval	CAAM_NO_ERROR
 */
enum CAAM_Status caam_sm_init(struct jr_cfg *jr_cfg);

/**
 * @brief      Allocate one page to one partition in the CAAM secure memory.
 *             By default, group access and permission access are not
 *             restricted.
 *
 * @param      sm         secure memory data
 * @param[in]  partition  partition
 * @param[in]  page       page
 *
 * @retval     CAAM_NO_ERROR	Success
 * @retval     CAAM_FAILURE     An error occurred
 * @retval     CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_sm_alloc(struct sm_data **sm, uint8_t partition,
			       uint8_t page);

/**
 * @brief      Free secure memory partition and pages associated with the
 *             partition.
 *
 * @param      sm       secure memory data
 *
 * @retval     CAAM_NO_ERROR	Success
 * @retval     CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_sm_free(struct sm_data *sm);

/**
 * @brief	Set access rights to allocated partition
 *
 * @param[in] sm	secure memory data
 * @param[in] map	SMAP register value
 *
 * @retval CAAM_BAD_PARAM
 * @retval CAAM_FAILURE
 * @retval CAAM_NO_ERROR
 */
enum CAAM_Status caam_sm_set_access_perm(struct sm_data *sm, uint32_t map);

#endif /* __CAAM_SM_H__ */
