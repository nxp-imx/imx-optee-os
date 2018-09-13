// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    caam_math.c
 *
 * @brief   CAAM Mathematical Operation manager.\n
 *          Implementation of Mathematical operation using
 *			CAAM's MATH function
 */

/* Global includes */
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_math.h>

/* Local includes */
#include "common.h"
#include "caam_acipher.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"

/*
 * Debug Macros
 */
//#define MATH_DEBUG
#ifdef MATH_DEBUG
#define DUMP_DESC
#define DUMP_BUF
#define MATH_TRACE		DRV_TRACE
#else
#define MATH_TRACE(...)
#endif

#ifdef DUMP_DESC
#define MATH_DUMPDESC(desc)	{MATH_TRACE("MATH Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define MATH_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define MATH_DUMPBUF	DRV_DUMPBUF
#else
#define MATH_DUMPBUF(...)
#endif

/**
 * @brief   MATH operation A xor B modulus n
 *
 * @param[in/out] data  operation data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_xor_mod_n(struct imxcrypt_mod_op *data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	enum CAAM_Status retstatus;

	struct jr_jobctx jobctx  = {0};
	descPointer_t    desc    = NULL;
	uint8_t          desclen = 1;

	int realloc = 0;
	struct caambuf res_align = {0};

	paddr_t paddr_A;
	paddr_t paddr_B;

	MATH_TRACE("(A xor B) mod n");

	paddr_A = virt_to_phys(data->A.data);
	paddr_B = virt_to_phys(data->B.data);

	if ((!paddr_A) || (!paddr_B))
		return ret;

	/*
	 * ReAllocate the cipher result buffer with a maximum size
	 * of the Key Modulus's size (N) if not cache aligned
	 */
	realloc = caam_realloc_align(data->result.data,
				&res_align, data->result.length);
	if (realloc == (-1)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_xor_mod_n;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(11);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_xor_mod_n;
	}

	/* Load in N Modulus Size */
	desc[desclen++] = LD_IMM(CLASS_1, REG_PKHA_N_SIZE, 4);
	desc[desclen++] = data->N.length;

	/* Load in A f irst value */
	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_A, NOACTION, data->A.length);
	desc[desclen++] = paddr_A;

	/* Load in B second value */
	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_B, NOACTION, data->B.length);
	desc[desclen++] = paddr_B;

	/* Operation B = A xor B mod n */
	desc[desclen++] = PKHA_F2M_OP(MOD_ADD_A_B, B);

	/* Store the result */
	desc[desclen++] = FIFO_ST(PKHA_B, data->result.length);
	desc[desclen++] = res_align.paddr;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);
	MATH_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, data->A.data, data->A.length);
	cache_operation(TEE_CACHECLEAN, data->B.data, data->B.length);

	if (res_align.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, res_align.data,
				data->result.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		/* Ensure that result is correct in cache */
		if (res_align.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, res_align.data,
					data->result.length);

		if (realloc)
			memcpy(data->result.data, res_align.data,
				data->result.length);

		MATH_DUMPBUF("Output", data->result.data, data->result.length);
		ret = TEE_SUCCESS;
	} else {
		MATH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
	}

end_xor_mod_n:
	caam_free_desc(&desc);

	if (realloc == 1)
		caam_free_buf(&res_align);

	return ret;
}

/**
 * @brief   Registration of the MATH Driver
 */
struct imxcrypt_math driver_math = {
	.xor_mod_n = &do_xor_mod_n,
};

/**
 * @brief   Initialize the MATH module
 *l
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_math_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	if (imxcrypt_register(CRYPTO_MATH_HW, &driver_math) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
