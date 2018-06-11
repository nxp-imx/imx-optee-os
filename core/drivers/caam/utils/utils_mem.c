// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    utils_mem.c
 *
 * @brief   Memory management utilities.\n
 *          Primitive to allocate, free memory.
 */

/* Global includes */
#include <arm.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <string.h>

/* Local includes */
#include "common.h"

/* Utils includes */
#include "utils_mem.h"

#define MEM_DEBUG
#ifdef MEM_DEBUG
#define MEM_TRACE		DRV_TRACE
#else
#define MEM_TRACE(...)
#endif

/**
 * @brief   Definition of some armv7 Cache Size Register fields
 */
#define CCSIDR_LINESIZE_SHIFT	0
#define CCSIDR_LINESIZE_MASK	0x7

/**
 * @brief   CAAM Descriptor address alignement
 */
#ifdef ARM64
#define DESC_START_ALIGN	(64 / 8)
#else
#define DESC_START_ALIGN	(32 / 8)
#endif

/**
 * @brief   Cache line size in bytes
 */
static uint16_t cacheline_size;

/**
 * @brief   Read the system cache line size.\n
 *          Get the value from the ARM system configration register
 */
static void read_cacheline_size(void)
{
	uint32_t value;

#ifdef ARM64
	asm volatile ("mrs %0, ctr_el0" : "=r" (value));
	cacheline_size = 4 << ((value >> CTR_DMINLINE_SHIFT)
						& CTR_DMINLINE_MASK);
#else
	asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r" (value));
	cacheline_size = 4 << (((value >> CCSIDR_LINESIZE_SHIFT)
						& CCSIDR_LINESIZE_MASK) + 2);
#endif
	MEM_TRACE("System Cache Line size = %d bytes", cacheline_size);
}

/**
 * @brief   Allocate normal memory and initialize it with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

/**
 * @brief   Allocate memory aligned with a cache line and initialize it
 *          with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc_align(size_t size)
{
	void *ptr;

	ptr = memalign(cacheline_size, ROUNDUP(size, cacheline_size));
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

/**
 * @brief   Free allocated memory
 *
 * @param[in] ptr  reference to the object to free
 *
 */
void caam_free(void **ptr)
{
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
}

/**
 * @brief   Allocate Job descriptor and initialize it with 0s
 *
 * @param[in] nbEntries  Number of descriptor entries
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
descPointer_t caam_alloc_desc(uint8_t nbEntries)
{
	void *ptr;

	ptr = memalign(DESC_START_ALIGN, DESC_SZBYTES(nbEntries));
	if (ptr)
		memset(ptr, 0, DESC_SZBYTES(nbEntries));

	return ptr;
}

/**
 * @brief   Free descriptor
 *
 * @param[in] ptr  Reference to the descriptor to free
 *
 */
void caam_free_desc(descPointer_t *ptr)
{
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
}

/**
 * @brief   Allocate internal driver buffer and initialize it with 0s
 *
 * @param[in/out] buf   buffer to allocate
 * @param[in]     size  size in bytes of the memory to allocate
 *
 * @retval  CAAM_NO_ERROR		Success
 * @retval  CAAM_OUT_MEMORY		Allocation error
 */
enum CAAM_Status caam_alloc_buf(struct caambuf *buf, size_t size)
{
	buf->data = caam_alloc(size);

	if (!buf->data)
		return CAAM_OUT_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		caam_free_buf(buf);
		return CAAM_OUT_MEMORY;
	}

	buf->length = size;
	return CAAM_NO_ERROR;
}

/**
 * @brief   Allocate internal driver buffer aligned with a cache line
 *          and initialize it with 0s
 *
 * @param[in/out] buf   buffer to allocate
 * @param[in]     size  size in bytes of the memory to allocate
 *
 * @retval  CAAM_NO_ERROR		Success
 * @retval  CAAM_OUT_MEMORY		Allocation error
 */
enum CAAM_Status caam_alloc_align_buf(struct caambuf *buf, size_t size)
{
	buf->data = caam_alloc_align(size);

	if (!buf->data)
		return CAAM_OUT_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		caam_free_buf(buf);
		return CAAM_OUT_MEMORY;
	}

	buf->length = size;
	return CAAM_NO_ERROR;
}

/**
 * @brief   Free internal driver buffer allocated memory
 *
 * @param[in/out] buf   buffer to free
 *
 */
void caam_free_buf(struct caambuf *buf)
{
	if (buf) {
		if (buf->data) {
			free(buf->data);
			buf->data = NULL;
		}

		buf->length = 0;
		buf->paddr  = 0;
	}
}

/**
 * @brief   Memory utilities initialization
 *
 * @retval  CAAM_NO_ERROR   Success
 */
enum CAAM_Status caam_mem_init(void)
{
	read_cacheline_size();

	return CAAM_NO_ERROR;
}

