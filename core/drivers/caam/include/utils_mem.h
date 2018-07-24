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

#ifdef CFG_IMXCRYPT
/* Library i.MX includes */
#include <libimxcrypt.h>
#endif

/* Local includes */
#include "common.h"

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
void caam_free(void *ptr);

/**
 * @brief   Allocate Job descriptor and initialize it with 0s
 *
 * @param[in] nbEntries  Number of descriptor entries
 *
 * @retval  address of the memory block allocated
 * @retval  NULL if allocation error
 */
descPointer_t caam_alloc_desc(uint8_t nbEntries);

/**
 * @brief   Free descriptor
 *
 * @param[in] ptr  Reference to the descriptor to free
 *
 */
void caam_free_desc(descPointer_t *ptr);

/**
 * @brief   Allocate internal driver buffer and initialize it with 0s
 *
 * @param[in/out] buf   buffer to allocate
 * @param[in]     size  size in bytes of the memory to allocate
 *
 * @retval  CAAM_NO_ERROR		Success
 * @retval  CAAM_OUT_MEMORY		Allocation error
 */
enum CAAM_Status caam_alloc_buf(struct caambuf *buf, size_t size);

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
enum CAAM_Status caam_alloc_align_buf(struct caambuf *buf, size_t size);

/**
 * @brief   Free internal driver buffer allocated memory
 *
 * @param[in/out] buf   buffer to free
 *
 */
void caam_free_buf(struct caambuf *buf);

/**
 * @brief   Free data of type struct sgtbuf
 *
 * @parm[in/out] data    Data sgtbuf to free
 */
void caam_sgtbuf_free(struct sgtbuf *data);

/**
 * @brief   Allocate data of type struct sgtbuf
 *
 * @parm[in/out] data    Data sgtbuf to fill
 *
 * @retval CAAM_NO_ERROR    Success
 * @retval CAAM_OUT_MEMORY  Allocation error
 * @retval CAAM_BAD_PARAM   Bad parameters
 */
enum CAAM_Status caam_sgtbuf_alloc(struct sgtbuf *data);

#ifdef CFG_IMXCRYPT
/**
 * @brief   Copy source data into the block buffer
 *
 * @param[in/out] block  Block buffer
 * @param[in]     src    Source to copy
 * @param[in]     offset Source offset to start
 *
 * @retval CAAM_NO_ERROR       Success
 * @retval CAAM_OUT_MEMORY     Out of memory
 */
enum CAAM_Status caam_cpy_block_src(struct caamblock *block,
			struct imxcrypt_buf *src,
			size_t offset);
#endif

/**
 * @brief   Memory utilities initialization
 *
 * @retval  CAAM_NO_ERROR   Success
 */
enum CAAM_Status caam_mem_init(void);

#endif /* __UTILS_MEM_H__ */
