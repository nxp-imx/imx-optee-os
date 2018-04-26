// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2017-2018 NXP
 *
 * @file    caam_rng.c
 *
 * @brief   CAAM Random Number Generator manager.\n
 *          Implementation of RNG functions
 */

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "caam_rng.h"

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_rng.h"

/*
 * Debug Macros
 */
#define RNG_DEBUG
#ifdef RNG_DEBUG
#define DUMP_DESC
#define RNG_TRACE		DRV_TRACE
#else
#define RNG_TRACE(...)
#endif

#ifdef DUMP_DESC
#define RNG_DUMPDESC(desc)	{RNG_TRACE("RNG Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define RNG_DUMPDESC(desc)
#endif

/**
 * @brief   RNG module private data
 */
struct rng_privdata {
	vaddr_t baseaddr;      ///< RNG base address
	bool    instantiated;  ///< Flag indicating RNG instantiated
};

static struct rng_privdata *rng_privdata;

/**
 * @brief   Prepares the instantiation descriptor
 *
 * @param[in]     nbSH       Number of the State Handle
 * @param[in]     sh_status  State Handles status
 * @param[in/out] desc       Reference to the descriptor
 */
static void prepare_inst_desc(uint32_t nbSH, uint32_t sh_status,
							 descPointer_t desc)
{
	descPointer_t pdesc     = desc;
	bool          key_loaded;
	uint8_t       desc_size = 1;
	uint8_t       sh_idx    = 0;
	uint8_t       nbMaxSh   = nbSH;

	/* Read the SH and secure key status */
	key_loaded = hal_rng_key_loaded(rng_privdata->baseaddr);
	RNG_TRACE("RNG SH Status 0x%08"PRIx32" - Key Status %d",
					sh_status, key_loaded);

	while (sh_status & (1 << sh_idx))
		sh_idx++;

	RNG_TRACE("Instantiation start at SH%d (%d)", sh_idx, nbMaxSh);

	/* Don't set the descriptor header now */
	pdesc++;

	/* First State Handle to instantiate */
	*pdesc++ = RNG_SH_INST(sh_idx);
	desc_size++;
	/* Next State Handle */
	sh_idx++;

	while (sh_idx < nbMaxSh) {
		if (!(sh_status & (1 << sh_idx))) {
			/*
			 * If there is more SH to instantiate, add a wait loop
			 * followed by a reset the done status to execute next
			 * command
			 */
			*pdesc++ = JUMP_C1_LOCAL(TST_ALL_COND_TRUE,
					JUMP_TST_COND(NONE), 1);
			*pdesc++ = LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
					sizeof(uint32_t));
			*pdesc++ = 1;
			*pdesc++ = RNG_SH_INST(sh_idx);
			desc_size += 4;

		}
		/* Next State Handle */
		sh_idx++;
	}

	/* Load the Key if needed */
	if (key_loaded == false) {
		/*
		 * Add a wait loop followed by a reset the done status
		 * to execute next command
		 */
		*pdesc++ = JUMP_C1_LOCAL(TST_ALL_COND_TRUE,
				JUMP_TST_COND(NONE), 1);
		*pdesc++ = LD_NOCLASS_IMM(REG_CLEAR_WRITTEN,
				sizeof(uint32_t));
		*pdesc++ = 1;

		*pdesc = RNG_GEN_SECKEYS;
		desc_size += 4;
	}

	/* Add the Descriptor Header with the length of the descriptor */
	desc[0] = DESC_HEADER(desc_size);

	RNG_DUMPDESC(desc);
}
/**
 * @brief   Instantiates the RNG State Handles if not already done
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of Memory
 */
static enum CAAM_Status do_instantiation(void)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	struct jr_jobctx jobctx = {0};
	descPointer_t    desc = NULL;
	uint32_t         sh_status;
	uint32_t         nbSH;
	uint32_t         sh_mask;
	uint32_t         inc_delay = 0;

	RNG_TRACE("RNG Instantation");

	/* Check if RNG is already instantiated */
	if (hal_rng_instantiated(rng_privdata->baseaddr)) {
		RNG_TRACE("RNG already instantiated");
		retstatus = CAAM_NO_ERROR;
		goto end_inst;
	}

	/*
	 * RNG needs to be instantiated. Allocate and prepare the
	 * Job Descriptor
	 */

	/* Calculate the State Handles bit mask */
	nbSH = hal_rng_get_nbSH(rng_privdata->baseaddr);
	sh_mask = (1 << nbSH) - 1;

	/*
	 * The maximum size of the descriptor is:
	 *    |----------------------|
	 *    | Header               | = 1
	 *    |----------------------|
	 *    | First instantation   | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    |       Repeat (nbSH - 1)
	 *    |                      | = 2
	 *    |----------------------|
	 *	  | next SH instantation | = 1
	 *    |----------------------|-------------------------
	 *    | wait complete        | = 1
	 *    |----------------------|
	 *    | Clear done status    | = 2
	 *    |                      |
	 *    |----------------------|
	 *	  | Generate Secure Keys | = 1
	 *    |----------------------|
	 */
	desc = caam_alloc_desc(1 + nbSH + ((nbSH - 1) * 3) + 4 + 1);
	if (!desc) {
		RNG_TRACE("Descriptor Allocation error");
		retstatus = CAAM_OUT_MEMORY;
		goto end_inst;
	}

	jobctx.desc = desc;

	do {
		/* Check if all State Handles are instantiated */
		sh_status  = hal_rng_get_statusSH(rng_privdata->baseaddr);
		if ((sh_status & sh_mask) == sh_mask) {
			RNG_TRACE("RNG All SH are instantiated (0x%08"PRIx32")",
					sh_status);
			retstatus = CAAM_NO_ERROR;
			goto end_inst;
		}

		if (sh_status == 0) {
			retstatus = hal_rng_kick(rng_privdata->baseaddr,
						inc_delay);
			RNG_TRACE("RNG Kick (inc=%d) ret 0x%08"PRIx32"",
						inc_delay, retstatus);
			if (retstatus == CAAM_OUT_OF_BOUND) {
				retstatus = CAAM_FAILURE;
				goto end_inst;
			}
			inc_delay += 200;
		}

		prepare_inst_desc(nbSH, sh_status, desc);

		retstatus = caam_jr_enqueue(&jobctx, NULL);
		RNG_TRACE("RNG Job returned 0x%08"PRIx32"", retstatus);

		if (retstatus == CAAM_NO_ERROR) {
			RNG_TRACE("RNG Job status 0x%08"PRIx32"",
				jobctx.status);
		} else {
			goto end_inst;
		}
	} while (retstatus == CAAM_NO_ERROR);

	retstatus = CAAM_NO_ERROR;

end_inst:
	if (retstatus == CAAM_NO_ERROR)
		rng_privdata->instantiated = true;

	caam_free_desc((void **)&desc);

	RNG_TRACE("RNG Instantiation return 0x%08"PRIx32"", retstatus);

	return retstatus;
}

/**
 * @brief   Initialize the RNG module and do the instantation of the
 *          State Handles if not done
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_rng_init(vaddr_t ctrl_addr)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	RNG_TRACE("Initialization");

	/* Allocate the Module resources */
	rng_privdata = caam_alloc(sizeof(struct rng_privdata));
	if (!rng_privdata) {
		RNG_TRACE("Private Data allocation error");
		retstatus = CAAM_OUT_MEMORY;
		goto end_init;
	}

	rng_privdata->baseaddr     = ctrl_addr;
	rng_privdata->instantiated = false;

	retstatus = do_instantiation();

end_init:
	if (retstatus != CAAM_NO_ERROR)
		caam_free((void **)&rng_privdata);

	return retstatus;
}

