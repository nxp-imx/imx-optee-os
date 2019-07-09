// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    caam_sm.c
 *
 * @brief   CAAM Secure Memory manager.\n
 *          Implementation of CAAM secure memory
 */

/* Global includes */
#include <mm/core_memprot.h>
#include <string.h>

/* Local includes */
#include "desc_helper.h"
#include "caam_io.h"
#include "caam_jr.h"
#include "caam_sm.h"

/* Utils includes */
#include "utils_mem.h"

/**
 * Debug Macros
 */
//#define SM_DEBUG
#ifdef SM_DEBUG
#define SM_TRACE		DRV_TRACE
#else
#define SM_TRACE(...)
#endif

/**
 * @brief Secure memory module private data
 */
struct sm_privdata {
	vaddr_t baseaddr;		///< Secure memory base address

	uint32_t number_partitions;	///< Maximum number of partitions
	uint32_t number_pages;		///< Maximum number of pages
	uint32_t page_size;		///< Pages size

	vaddr_t ctrl_addr;		///< CAAM base address
	vaddr_t jr_addr;		///< Job ring base address
	uint8_t jr_id;			///< Job ring ID
};

/**
 * @brief   Secure memory module private data reference
 */
static struct sm_privdata *sm_privdata;

/**
 * @brief	Get the DMA address
 *
 * @param[in] caam_addr		CAAM base address
 * @param[in] page		Page number of the requested DMA address
 * @param[in] jr_id		Job ring number
 *
 * @return    DMA address
 */
static vaddr_t get_dma_addr(vaddr_t caam_addr, uint32_t page, uint8_t jr_id)
{
	/*
	 * Secure Memory Virtual Base Address. This field contains the upper
	 * bits of the base address of Secure Memory in this Job Ring's virtual
	 * address space. Since the base address of Secure Memory must be on a
	 * 64 kbyte boundary, the least significant 16 bits are omitted. That
	 * is, the full address is SMVBA followed by 0000h.
	 */

	paddr_t addr;

	addr = (get32(caam_addr + JRx_SMVBAR(jr_id)) << 16) +
	       (page * sm_privdata->page_size);

	SM_TRACE("DMA address for page %d JR%d 0x%08" PRIx32 "", page, jr_id,
		 addr);

	return addr;
}

/**
 * @brief	Get the page virtual address
 *
 * @param[in] page	Page number of the requested page address
 *
 * @return    page virtual address
 */
static vaddr_t get_page_va(uint32_t page)
{
	return (vaddr_t)(sm_privdata->baseaddr + page * sm_privdata->page_size);
}

/**
 * @brief	Check if the partition given is already allocated
 *
 * @param[in] jr_addr	JR base address
 * @param[in] partition	Partition number
 *
 * @return    Partition status register
 */
static uint32_t is_prtn_alloc(vaddr_t jr_addr, uint32_t partition)
{
	uint32_t status = (get32(JRx_SMPO(jr_addr)) & POx_OWNER(partition)) >>
			  POx_OFF(partition);
	return status;
}

/**
 * @brief	Execute secure memory commands
 *
 * @param[in] jr_addr	JR base address
 * @param[in] cmd	Command
 *
 * @return    Partition status register
 */
static uint32_t smcr_cmd(vaddr_t jr_addr, uint32_t cmd)
{
	uint32_t reg;

	/* Send cmd */
	put32(JRx_SMCR(jr_addr), cmd);

	/* Wait for the command to complete */
	do {
		reg = get32(JRx_SMCSR(jr_addr));
	} while (SMCSR_CERR(reg) == SMCSR_CERR_NOT_COMPL);

	/* Send back status command register */
	return reg;
}

/**
 * @brief Set the access perm map object
 *
 * @param[in] jr_addr	JR base address
 * @param[in] partition	Partition number
 * @param[in] map	SMAP register value
 */
static void set_access_perm_map(vaddr_t jr_addr, uint32_t partition,
				uint32_t map)
{
	put32(JRx_SMAPR(jr_addr, partition), map);
}

/**
 * @brief	Set the access group object
 *
 * @param[in] jr_addr		JR base address
 * @param[in] partition		Partition number
 * @param[in] mag2		SMAG2 register value
 * @param[in] mag1		SMAG1 register value
 */
static void set_access_group(vaddr_t jr_addr, uint32_t partition, uint32_t mag2,
			     uint32_t mag1)
{
	put32(JRx_SMAG1(jr_addr, partition), mag1);
	put32(JRx_SMAG2(jr_addr, partition), mag2);
}

/**
 * @brief	Allocate partition in CAAM secure memory
 *
 * @param[out] sm		Allocated partition data
 * @param[in] partition		Parition number
 * @param[in] page		Page number
 *
 * @retval	CAAM_FAILURE	Error while allocating
 * @retval	CAAM_OUT_MEMORY Out of memory
 * @retval	CAAM_NO_ERROR	Success
 */
enum CAAM_Status caam_sm_alloc(struct sm_data **sm, uint8_t partition,
			       uint8_t page)
{
	struct sm_data *_sm;
	uint32_t status;

	/* Is partition already allocated? */
	status = is_prtn_alloc(sm_privdata->jr_addr, partition);
	if (status != SMPO_POx_AVAIL) {
		SM_TRACE("Partition %d not available", partition);
		return CAAM_FAILURE;
	}

	/* Set full access partition rights by defaults */
	set_access_group(sm_privdata->jr_addr, partition, 0xF, 0xF);
	set_access_perm_map(sm_privdata->jr_addr, partition, 0xFF);

	/* Is the page allocated? */
	status = smcr_cmd(sm_privdata->jr_addr,
			  SMCR_PAGE(page) | SMCR_CMD(CMD_PAGE_INQ));
	if (SMCSR_PO(status) != SMCSR_PO_AVAIL) {
		SM_TRACE("Page not available 0x%08" PRIx32 "",
			 SMCSR_PO(status));
		return CAAM_FAILURE;
	}

	/* Allocate page to partition */
	status = smcr_cmd(sm_privdata->jr_addr,
			  SMCR_PAGE(page) | SMCR_PRTN(partition) |
				  SMCR_CMD(CMD_PAGE_ALLOC));
	if (SMCSR_AERR(status) != SMCSR_AERR_NO_ERROR) {
		SM_TRACE("Page allocation error: 0x%08" PRIx32 "",
			 SMCSR_AERR(status));
		return CAAM_FAILURE;
	}

	/* Update secure memory info */
	_sm = (struct sm_data *)caam_alloc(sizeof(struct sm_data));
	if (!_sm) {
		SM_TRACE("Cannot allocated sm_data");
		return CAAM_OUT_MEMORY;
	}

	_sm->page = page;
	_sm->partition = partition;
	_sm->sm_dma_addr = get_dma_addr(sm_privdata->ctrl_addr, _sm->page,
					sm_privdata->jr_id);
	_sm->sm_va = get_page_va(_sm->page);
	_sm->page_size = sm_privdata->page_size;

	*sm = _sm;

	SM_TRACE("Partition %d Page %d allocated @ 0x%08" PRIx32 "",
		 _sm->partition, _sm->page, _sm->sm_va);

	return CAAM_NO_ERROR;
}

/**
 * @brief	Free secure memory partition
 *
 * @param[in] sm	Partition data
 *
 * @retval	CAAM_FAILURE	Error while freeing partition
 * @retval	CAAM_NO_ERROR	Success
 */
enum CAAM_Status caam_sm_free(struct sm_data *sm)
{
	uint32_t status;

	if (!sm) {
		SM_TRACE("No secure memory allocated");
		return CAAM_FAILURE;
	}

	/*
	 * De-allocate partition. It automatically releases partition's pages
	 * to the pool of available pages. if the partition if marked as CSP,
	 * pages will be zeroized. If the partition is marked as PSP,
	 * partition and pages will not be de-allocated and a PSP will be
	 * returned
	 */

	/* Is the partition owned by the entity? */
	status = is_prtn_alloc(sm_privdata->jr_addr, sm->partition);
	if (status != SMPO_POx_OWNED) {
		SM_TRACE("Cannot free partition, not owned by entity");
		return CAAM_FAILURE;
	}

	/*
	 * De-allocate partition. It will also de-allocate pages all pages
	 * allocated to that partition
	 */
	status = smcr_cmd(sm_privdata->jr_addr, SMCR_PRTN(sm->partition) |
					   SMCR_CMD(CMD_PART_DEALLOC));
	if (SMCSR_CERR(status) != SMCSR_CERR_NO_ERROR) {
		SM_TRACE("Partition de-allocation error");
		return CAAM_FAILURE;
	}

	/* Update JR info */
	caam_free(sm);

	SM_TRACE("Secure mem de-allocated");

	return CAAM_NO_ERROR;
}

/**
 * @brief	Set access rights to allocated partition
 *
 * @param[in] sm	Partition data
 * @param[in] map	SMAP register value
 *
 * @retval CAAM_BAD_PARAM
 * @retval CAAM_FAILURE
 * @retval CAAM_NO_ERROR
 */
enum CAAM_Status caam_sm_set_access_perm(struct sm_data *sm, uint32_t map)
{
	uint32_t status;

	if (!sm) {
		SM_TRACE("No secure memory allocated");
		return CAAM_BAD_PARAM;
	}

	/* Is the partition owned by the entity? */
	status = is_prtn_alloc(sm_privdata->jr_addr, sm->partition);
	if (status != SMPO_POx_OWNED) {
		SM_TRACE("Partition not owned by entity");
		return CAAM_FAILURE;
	}

	/* Add Cortex A7 to group 1 */
	set_access_group(sm_privdata->jr_addr, sm->partition, 0x0, MID_A7);

	/* Set permission */
	set_access_perm_map(sm_privdata->jr_addr, sm->partition, map);

	return CAAM_NO_ERROR;
}

/**
 * @brief	CAAM Secure memory module initialization
 *
 * @param[in]	jr_cfg	JR configuration structure
 *
 * @retval	CAAM_OUT_MEMORY
 * @retval	CAAM_FAILURE
 * @retval	CAAM_NO_ERROR
 */
enum CAAM_Status caam_sm_init(struct jr_cfg *jr_cfg)
{
	enum CAAM_Status retstatus;

	/* Allocate the secure memory private data */
	sm_privdata = caam_alloc(sizeof(struct sm_privdata));
	if (!sm_privdata) {
		SM_TRACE("Private Data allocation error");
		retstatus = CAAM_OUT_MEMORY;
		goto end_alloc;
	}

	/* Get job ring infos */
	sm_privdata->ctrl_addr = jr_cfg->base;
	sm_privdata->jr_addr = jr_cfg->base + jr_cfg->offset;
	sm_privdata->jr_id =
		(jr_cfg->offset - CFG_JR_BLOCK_SIZE) / CFG_JR_BLOCK_SIZE;

	SM_TRACE("sm_privdata->ctrl_addr = 0x" PRIxVA, sm_privdata->ctrl_addr);
	SM_TRACE("sm_privdata->jr_addr = 0x" PRIxVA, sm_privdata->jr_addr);
	SM_TRACE("sm_privdata->jr_id = %d" sm_privdata->jr_id);

	/* Get secure memory properties */
	sm_privdata->page_size =
		0x1
		<< (((get32(jr_cfg->base + SMVID_LS) & PSIZ_MASK) >> PSIZ_OFF) +
		    10);
	sm_privdata->number_pages =
		((get32(jr_cfg->base + SMVID_MS) & MAX_NPAG_MASK) >>
		 MAX_NPAG_OFF) +
		1;
	sm_privdata->number_partitions =
		(get32(jr_cfg->base + SMVID_MS) & NPRT_MASK) >> NPRT_OFF;

	SM_TRACE("Secure memory page size: 0x%08" PRIx32 "",
		 sm_privdata->page_size);
	SM_TRACE("Secure memory page number: %d", sm_privdata->number_pages);
	SM_TRACE("Secure memory page partition: %d",
		 sm_privdata->number_partitions);

	/* Get page virtual address */
	sm_privdata->baseaddr =
		(vaddr_t)phys_to_virt(SECMEM_BASE, MEM_AREA_IO_SEC);
	if (!sm_privdata->baseaddr) {
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, SECMEM_BASE,
					  CORE_MMU_DEVICE_SIZE)) {
			EMSG("Unable to map CAAM secure memory registers");
			return CAAM_FAILURE;
		}

		sm_privdata->baseaddr =
			(vaddr_t)phys_to_virt(SECMEM_BASE, MEM_AREA_IO_SEC);
	}

	retstatus = CAAM_NO_ERROR;

end_alloc:
	if (retstatus != CAAM_NO_ERROR)
		caam_free(sm_privdata);

	return retstatus;
}
