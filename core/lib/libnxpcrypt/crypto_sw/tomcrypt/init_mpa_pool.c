// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    init_map_pool.c
 *
 * @brief   NXP Cryptographic software library initialisation of the
 *          mpa memory pool used by LibTomCrypt to allocate big numbers.
 */

/* Local includes */
#include "local.h"

/* Library TomCrypt includes */
#include <tomcrypt_mpa.h>

/**
 * @brief   Maximum Number of variables of maximum size
 *          \a LTC_MAX_BITS_PER_VARIABLEin the memory pool
 */
#define LTC_VARIABLE_NUMBER         50

/**
 * @brief   Size of the scratch memory pool
 */
#define LTC_MEMPOOL_U32_SIZE  \
			mpa_scratch_mem_size_in_U32(LTC_VARIABLE_NUMBER, \
			LTC_MAX_BITS_PER_VARIABLE)

#if defined(CFG_WITH_PAGER)
#include <mm/core_mmu.h>
#include <mm/tee_pager.h>
#include <util.h>

/* allocate pageable_zi vmem for mpa scratch memory pool */
static struct mempool *get_mpa_scratch_memory_pool(void)
{
	size_t size;
	void *data;

	size = ROUNDUP((LTC_MEMPOOL_U32_SIZE * sizeof(uint32_t)),
		        SMALL_PAGE_SIZE);
	data = tee_pager_alloc(size, 0);
	if (!data)
		panic();

	return mempool_alloc_pool(data, size, tee_pager_release_phys);
}
#else /* CFG_WITH_PAGER */
static struct mempool *get_mpa_scratch_memory_pool(void)
{
	static uint32_t data[LTC_MEMPOOL_U32_SIZE] __aligned(__alignof__(long));
	return mempool_alloc_pool(data, sizeof(data), NULL);
}
#endif
/**
 * @brief   Allocation and setup the scratch memory pool used by LibTomCrypt
 *
 * @retval  0   if success
 * @retval (-1) otherwise
 */
int libsoft_mpa_init(void)
{
	int ret = (-1);
	static mpa_scratch_mem_base mem;

	/*
	 * The default size (bits) of a big number that will be required it
	 * equals the max size of the computation (for example 4096 bits),
	 * multiplied by 2 to allow overflow in computation
	 */
	mem.bn_bits = CFG_CORE_BIGNUM_MAX_BITS * 2;
	mem.pool = get_mpa_scratch_memory_pool();
	if (mem.pool) {
		init_mpa_tomcrypt(&mem);
		ret = 0;
	}

	return ret;
}


