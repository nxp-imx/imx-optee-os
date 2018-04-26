/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    utils_mem.h
 *
 * @brief   Memory management utilities.\n
 *          Primitive to allocate, free memory.
 */

#ifndef __UTILS_MEM_H__
#define __UTILS_MEM_H__

/**
 * @brief   Allocate normal memory and initialize it with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc(size_t size);

/**
 * @brief   Allocate memory aligned with a cache line and initialize it
 *          with 0s
 *
 * @param[in] size  size in bytes of the memory to allocate
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc_align(size_t size);

/**
 * @brief   Free allocated memory
 *
 * @param[in] ptr  reference to the object to free
 *
 */
void caam_free(void **ptr);

/**
 * @brief   Allocate Job descriptor and initialize it with 0s
 *
 * @param[in] nbEntries  Number of descriptor entries
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
void *caam_alloc_desc(uint8_t nbEntries);

/**
 * @brief   Free descriptor
 *
 * @param[in] ptr  Reference to the descriptor to free
 *
 */
void caam_free_desc(void **ptr);

/**
 * @brief   Memory utilities initialization
 *
 * @retval  CAAM_NO_ERROR   Success
 */
enum CAAM_Status caam_mem_init(void);

#endif /* __UTILS_MEM_H__ */
