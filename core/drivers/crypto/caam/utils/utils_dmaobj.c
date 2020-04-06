// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * CAAM DMA data object utilities.
 */

#include <caam_trace.h>
#include <caam_utils_dmaobj.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#if !defined(CFG_CAAM_64BIT) && defined(ARM64)
#define IS_DMA_OVERFLOW(addr)                                                  \
	({                                                                     \
		__typeof__(addr) _addr = (addr);                               \
		(_addr >> 32) ? 1 : 0;                                         \
	})
#else
#define IS_DMA_OVERFLOW(addr) (0)
#endif

/*
 * Local defines used to identify Object type as:
 *  - input or output data
 *  - reallocated buffer accessible by the CAAM
 *  - SGT object created because buffer is not physical contiguous
 *  - derived object (not buffer reallocation)
 */
#define DMAOBJ_INPUT   BIT(0)
#define DMAOBJ_OUTPUT  BIT(1)
#define DMAOBJ_REALLOC BIT(2)
#define DMAOBJ_DERIVED BIT(3)

/*
 * Apply the cache operation @op to the DMA Object (SGT or buffer)
 *
 * @op    Cache operation
 * @obj   CAAM DMA object
 */
static inline void dmaobj_cache_operation(enum utee_cache_operation op,
					  struct caamdmaobj *obj)
{
	if (obj->sgtbuf.sgt_type)
		caam_sgt_cache_op(op, &obj->sgtbuf);
	else if (!obj->sgtbuf.buf->nocache)
		cache_operation(op, obj->sgtbuf.buf->data,
				obj->sgtbuf.buf->length);
}

/*
 * Go through all the @buffer space to extract all physical area used to
 * map the buffer.
 * If one of the physical area is not accessible by the CAAM DMA, returns -1
 * to indicate an error, else returns the number and the split of physical
 * areas.
 *
 * @out_pabufs  [out] Physical areas split
 * @buffer      Buffer to handle
 */
static int check_buffer_boundary(struct caambuf **out_pabufs,
				 struct caambuf *buffer)
{
	struct caambuf *pabufs = NULL;
	int nb_pa_area = -1;
	int idx = 0;
	paddr_t last_pa = 0;

	/* Get the number of physical areas used by the input buffer @data */
	nb_pa_area = caam_mem_get_pa_area(buffer, &pabufs);
	if (nb_pa_area != -1) {
		for (idx = nb_pa_area - 1; idx >= 0; idx--) {
			if (ADD_OVERFLOW(pabufs[idx].paddr, pabufs[idx].length,
					 &last_pa)) {
				nb_pa_area = -1;
				break;
			}

			if (IS_DMA_OVERFLOW(last_pa)) {
				nb_pa_area = -1;
				break;
			}
		}
	}

	if (nb_pa_area == -1) {
		caam_free(pabufs);
		pabufs = NULL;
	}

	*out_pabufs = pabufs;

	DMAOBJ_TRACE("Number of pa area = %d", nb_pa_area);
	return nb_pa_area;
}

TEE_Result caam_dmaobj_init_input(struct caamdmaobj *obj, const void *data,
				  size_t length)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf *pabufs = NULL;
	int nb_pa_area = 0;

	DMAOBJ_TRACE("Initialize Input object with data @%p of %zu bytes", data,
		     length);

	if (!data || !length || !obj)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Fill the CAAM Buffer object with the given input data */
	obj->dmabuf.paddr = virt_to_phys((void *)data);
	if (!obj->dmabuf.paddr) {
		DMAOBJ_TRACE("Object virtual address error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	obj->dmabuf.data = (void *)data;
	obj->dmabuf.length = length;
	if (!caam_mem_is_cached_buf((void *)data, length))
		obj->dmabuf.nocache = 1;

	nb_pa_area = check_buffer_boundary(&pabufs, &obj->dmabuf);
	if (nb_pa_area == -1) {
		DMAOBJ_TRACE("Allocate a new buffer");
		retstatus = caam_alloc_buf(&obj->dmabuf, length);
		if (retstatus != CAAM_NO_ERROR)
			goto end;

		obj->type = DMAOBJ_REALLOC;

		nb_pa_area = check_buffer_boundary(&pabufs, &obj->dmabuf);
		if (nb_pa_area == -1) {
			retstatus = CAAM_OUT_MEMORY;
			goto end;
		}
	}

	/* Set the object type as input */
	obj->type |= DMAOBJ_INPUT;

	/* Save the original data info */
	obj->orig.data = (void *)data;
	obj->orig.length = length;

	obj->sgtbuf.number = nb_pa_area;

	retstatus = caam_sgt_build_data(&obj->sgtbuf, &obj->dmabuf, pabufs);

	/* Input buffer reallocated, need to copy input data */
	if (retstatus == CAAM_NO_ERROR && obj->type & DMAOBJ_REALLOC)
		memcpy(obj->dmabuf.data, data, length);

end:
	caam_free(pabufs);

	DMAOBJ_TRACE("Object returns 0x%" PRIx32 " -> 0x%" PRIx32, retstatus,
		     caam_status_to_tee_result(retstatus));

	return caam_status_to_tee_result(retstatus);
}

TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, void *data,
				   size_t length, size_t min_length)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf *pabufs = NULL;
	int nb_pa_area = 0;
	int realloc = 0;

	DMAOBJ_TRACE("Initialize Output object with data @%p of %zu bytes",
		     data, length);

	if (!obj)
		return TEE_ERROR_BAD_PARAMETERS;

	if (length < min_length || !data) {
		DMAOBJ_TRACE("Output buffer too short need %zu bytes",
			     min_length);
		retstatus = caam_alloc_align_buf(&obj->dmabuf, min_length);
		if (retstatus != CAAM_NO_ERROR)
			goto end;

		realloc = 1;
	} else {
		realloc = caam_set_or_alloc_align_buf(data, &obj->dmabuf,
						      min_length);
		if (realloc == -1) {
			retstatus = CAAM_OUT_MEMORY;
			goto end;
		}
	}

	if (!realloc) {
		nb_pa_area = check_buffer_boundary(&pabufs, &obj->dmabuf);
		if (nb_pa_area == -1) {
			DMAOBJ_TRACE("Allocate a new buffer");
			retstatus =
				caam_alloc_align_buf(&obj->dmabuf, min_length);
			if (retstatus != CAAM_NO_ERROR)
				goto end;

			realloc = 1;
		}
	}

	if (realloc) {
		obj->type = DMAOBJ_REALLOC;

		nb_pa_area = check_buffer_boundary(&pabufs, &obj->dmabuf);
		if (nb_pa_area == -1) {
			retstatus = CAAM_OUT_MEMORY;
			goto end;
		}
	}

	/* Set the object type as output */
	obj->type |= DMAOBJ_OUTPUT;

	/* Save the original data info */
	obj->orig.data = (void *)data;
	obj->orig.length = length;

	obj->sgtbuf.number = nb_pa_area;

	retstatus = caam_sgt_build_data(&obj->sgtbuf, &obj->dmabuf, pabufs);

end:
	caam_free(pabufs);

	DMAOBJ_TRACE("Object returns 0x%" PRIx32 " -> 0x%" PRIx32, retstatus,
		     caam_status_to_tee_result(retstatus));

	return caam_status_to_tee_result(retstatus);
}

void caam_dmaobj_cache_push(struct caamdmaobj *obj)
{
	enum utee_cache_operation op = TEE_CACHECLEAN;

	if (obj) {
		if (obj->type & DMAOBJ_OUTPUT)
			op = TEE_CACHEFLUSH;

		dmaobj_cache_operation(op, obj);
	}
}

void caam_dmaobj_copy_to_orig(struct caamdmaobj *obj)
{
	size_t copy_size = 0;

	if (obj) {
		dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

		if (obj->type & DMAOBJ_REALLOC) {
			copy_size = MIN(obj->orig.length, obj->dmabuf.length);
			memcpy(obj->orig.data, obj->dmabuf.data, copy_size);
			obj->orig.length = copy_size;
		}
	}
}

void caam_dmaobj_copy_ltrim_to_orig(struct caamdmaobj *obj)
{
	size_t offset = 0;
	size_t copy_size = 0;

	if (obj) {
		dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

		/* Calculate the offset to start the copy */
		while (!obj->dmabuf.data[offset] && offset < obj->dmabuf.length)
			offset++;

		if (offset >= obj->dmabuf.length)
			offset = obj->dmabuf.length - 1;

		copy_size = MIN(obj->orig.length, obj->dmabuf.length - offset);
		MEM_TRACE("Copy %zu of src %zu bytes (offset = %zu)", copy_size,
			  obj->dma.length, offset);
		memcpy(obj->orig.data, &obj->dmabuf.data[offset], copy_size);

		obj->orig.length = copy_size;
	}
}

void caam_dmaobj_free(struct caamdmaobj *obj)
{
	if (obj) {
		DMAOBJ_TRACE("Free %s object with data @%p of %zu bytes",
			     obj->type & DMAOBJ_INPUT ? "Input" : "Output",
			     obj->orig.data, obj->orig.length);

		if (obj->type & DMAOBJ_REALLOC && !(obj->type & DMAOBJ_DERIVED))
			caam_free_buf(&obj->dmabuf);

		caam_sgtbuf_free(&obj->sgtbuf);
	}
}

TEE_Result caam_dmaobj_add_first_block(struct caamdmaobj *res,
				       struct caamblock *block,
				       struct caamdmaobj *obj)
{
	enum caam_status retstatus = CAAM_BAD_PARAM;

	if (!obj || !res || !block)
		goto end;

	/* Set the same DMA Object type than input @obj */
	res->type = obj->type;

	res->sgtbuf.sgt_type = true;
	res->sgtbuf.number = 2;
	res->sgtbuf.length = 0;

	retstatus = caam_sgtbuf_alloc(&res->sgtbuf);
	if (retstatus != CAAM_NO_ERROR)
		goto end;

	res->sgtbuf.buf[0].data = block->buf.data;
	res->sgtbuf.buf[0].length = block->filled;
	res->sgtbuf.buf[0].paddr = block->buf.paddr;
	res->sgtbuf.buf[0].nocache = block->buf.nocache;
	res->sgtbuf.length += block->filled;

	CAAM_SGT_ENTRY(&res->sgtbuf.sgt[0], res->sgtbuf.buf[0].paddr,
		       res->sgtbuf.buf[0].length);

	if (obj->sgtbuf.sgt_type) {
		res->sgtbuf.buf[1].data = (uint8_t *)&obj->sgtbuf;

		res->sgtbuf.length += obj->sgtbuf.length;

		CAAM_SGT_ENTRY_EXT(&res->sgtbuf.sgt[1], obj->sgtbuf.paddr,
				   obj->sgtbuf.length);
	} else {
		res->sgtbuf.buf[1].data = obj->sgtbuf.buf->data;
		res->sgtbuf.buf[1].length = obj->sgtbuf.buf->length;
		res->sgtbuf.buf[1].paddr = obj->sgtbuf.buf->paddr;
		res->sgtbuf.buf[1].nocache = obj->sgtbuf.buf->nocache;

		res->sgtbuf.length += obj->sgtbuf.buf->length;

		CAAM_SGT_ENTRY_FINAL(&res->sgtbuf.sgt[1], obj->sgtbuf.paddr,
				     obj->sgtbuf.length);
	}

	res->sgtbuf.paddr = virt_to_phys(res->sgtbuf.sgt);

	retstatus = CAAM_NO_ERROR;

end:
	return caam_status_to_tee_result(retstatus);
}

TEE_Result caam_dmaobj_derive(struct caamdmaobj *obj,
			      const struct caamdmaobj *from, size_t offset,
			      size_t length)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf *pabufs = NULL;
	int nb_pa_area = 0;
	vaddr_t start = 0;

	DMAOBJ_TRACE("Derive DMA object %p - offset %zu - length %zu bytes",
		     from, offset, length);

	if (!obj)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Set the same object type and add derived type
	 * to not free buffer if reallocated.
	 */
	obj->type = from->type | DMAOBJ_DERIVED;

	/* Derive original buffer starting at @offset of @length */
	if (ADD_OVERFLOW((vaddr_t)from->orig.data, offset, &start))
		return TEE_ERROR_OVERFLOW;
	obj->orig.data = (uint8_t *)start;
	obj->orig.length = length;

	DMAOBJ_TRACE("Object orig start @%p = @%p + %zu", obj->orig.data,
		     from->orig.data, offset);

	/* Derive DMA buffer starting at @offset of @length */
	if (ADD_OVERFLOW((vaddr_t)from->dmabuf.data, offset, &start))
		return TEE_ERROR_OVERFLOW;
	obj->dmabuf.data = (uint8_t *)start;
	obj->dmabuf.length = length;
	obj->dmabuf.nocache = from->dmabuf.nocache;
	obj->dmabuf.paddr = virt_to_phys(obj->dmabuf.data);

	DMAOBJ_TRACE("Object DMA start @%p = @%p + %zu", obj->dmabuf.data,
		     from->dmabuf.data, offset);

	nb_pa_area = check_buffer_boundary(&pabufs, &obj->dmabuf);
	if (nb_pa_area == -1) {
		retstatus = CAAM_OUT_MEMORY;
		goto end;
	}

	obj->sgtbuf.number = nb_pa_area;

	retstatus = caam_sgt_build_data(&obj->sgtbuf, &obj->dmabuf, pabufs);

end:
	caam_free(pabufs);

	DMAOBJ_TRACE("Object returns 0x%" PRIx32 " -> 0x%" PRIx32, retstatus,
		     caam_status_to_tee_result(retstatus));

	return caam_status_to_tee_result(retstatus);
}
