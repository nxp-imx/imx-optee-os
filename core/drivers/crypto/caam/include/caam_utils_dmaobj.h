/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 *
 * CAAM DMA data object utilities include file.
 */
#ifndef __CAAM_UTILS_DMAOBJ_H__
#define __CAAM_UTILS_DMAOBJ_H__

#include <caam_types.h>
#include <caam_utils_sgt.h>
#include <tee_api_types.h>

/*
 * CAAM DMA Object type
 * Keep the original data/length reference
 * If needed, reallocate a new buffer to be used by the CAAM
 * If needed, create a CAAM SGT object for the CAAM
 */
struct caamdmaobj {
	struct {
		uint8_t *data; /* Original data buffer */
		size_t length; /* Original data length */
	} orig;

	struct caambuf dmabuf;	  /* DMA buffer - original or reallocated */
	struct caamsgtbuf sgtbuf; /* CAAM SGT or Buffer object */
	unsigned int type;	  /* Encoded type of the object */
};

/*
 * Initialize a CAAM DMA object of type input data.
 * If necessary, a new CAAM Buffer is reallocated if given @data is not
 * accessible by the CAAM DMA and input data copied into.
 * If necessary, a CAAM SGT Object is constructed if physical area is not
 * contiguous.
 *
 * @obj     [out] CAAM DMA object initialized
 * @data    Input data pointer
 * @length  Length in bytes of the input data
 */
TEE_Result caam_dmaobj_init_input(struct caamdmaobj *obj, const void *data,
				  size_t len);

/*
 * Initialize a CAAM DMA object of type output data.
 * If necessary, a new CAAM Buffer is reallocated if given @data is not
 * accessible by the CAAM DMA or if the given @length is lower than
 * @min_length requested for the CAAM operation.
 * If necessary, a CAAM SGT Object is constructed if physical area is not
 * contiguous.
 *
 * @obj         [out] CAAM DMA object initialized
 * @data        Output data pointer
 * @length      Length in bytes of the output data
 * @min_length  Minimum length in bytes needed for the output data
 */
TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, void *data,
				   size_t length, size_t min_length);

/*
 * Push the data to physical memory with a cache clean or flush depending
 * on the type of data, respectively input or output.
 *
 * @obj     CAAM DMA object
 */
void caam_dmaobj_cache_push(struct caamdmaobj *obj);

/*
 * Copy the CAAM DMA object buffer to the original data buffer.
 *
 * @obj     CAAM DMA object
 */
void caam_dmaobj_copy_to_orig(struct caamdmaobj *obj);

/*
 * Copy the CAAM DMA object buffer to the original data buffer removing
 * non-significant first zeros (left zeros).
 * If all DMA object buffer is zero, left only one zero in the destination.
 *
 * @obj    CAAM DMA object
 */
void caam_dmaobj_copy_ltrim_to_orig(struct caamdmaobj *obj);

/*
 * Free the CAAM DMA object.
 * If a buffer has been reallocated, free it.
 * Free the sgtbuf object.
 *
 * @obj     CAAM DMA object
 */
void caam_dmaobj_free(struct caamdmaobj *obj);

/*
 * Create a CAAM DMA object SGT type with the block buffer @block first and
 * the CAAM DMA Object after
 *
 * @res     CAAM DMA object resulting
 * @block   CAAM Block buffer to add first
 * @obj     CAAM DMA object to add secondly
 */
TEE_Result caam_dmaobj_add_first_block(struct caamdmaobj *res,
				       struct caamblock *block,
				       struct caamdmaobj *obj);

/*
 * Derive a CAAM DMA object to a new DMA object of @length and starting at
 * @offset from given @from object.
 * There is no buffer reallocation but if necessary, a CAAM SGT Object is
 * constructed if physical area is not contiguous.
 *
 * @obj     [out] CAAM DMA object derived
 * @from    Original CAAM DMA object
 * @offset  Offset to start from
 * @length  Length in bytes of the data
 */
TEE_Result caam_dmaobj_derive(struct caamdmaobj *obj,
			      const struct caamdmaobj *from, size_t offset,
			      size_t length);

#endif /* __CAAM_UTILS_DMAOBJ_H__ */
