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
 *  - SGT object created because buffer is not physical contiguous
 *  - derived object (not buffer reallocation)
 *  - allocated origin buffer
 */
#define DMAOBJ_INPUT	  BIT(0)
#define DMAOBJ_OUTPUT	  BIT(1)
#define DMAOBJ_DERIVED	  BIT(2)
#define DMAOBJ_ALLOC_ORIG BIT(3)

/*
 * DMA Buffer entry
 *
 * @newbuf  True if list entry is a new DMA Buffer
 * @origbuf Original buffer reference
 * @dmabuf  DMA Buffer (new or original)
 * @next    Pointer to next entry
 */
struct dmabuf {
	bool newbuf;
	struct caambuf origbuf;
	struct caambuf dmabuf;

	SIMPLEQ_ENTRY(dmabuf) next;
};

/*
 * CAAM DMA private Object data
 * @type    Type of DMA Object
 * @list    List of the DMA Buffers
 */
struct priv_dmaobj {
	unsigned int type;

	SIMPLEQ_HEAD(dmalist, dmabuf) list;
};

/*
 * Reallocate a new buffer at the end of DMA Buffer list.
 * The buffer length is the one given from the @orig caambuf.
 * Return NULL if error, else the new entry in the list
 *
 * @priv    DMA Object private data
 * @orig    Original buffer reference
 */
static struct dmabuf *dmalist_insert_newbuf(struct priv_dmaobj *priv,
					    struct caambuf *orig)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct dmabuf *dmabuf = NULL;

	dmabuf = caam_calloc(sizeof(*dmabuf));
	if (dmabuf) {
		if (priv->type & DMAOBJ_INPUT)
			retstatus =
				caam_alloc_buf(&dmabuf->dmabuf, orig->length);
		else
			retstatus = caam_alloc_align_buf(&dmabuf->dmabuf,
							 orig->length);

		if (retstatus != CAAM_NO_ERROR) {
			caam_free(dmabuf);
			return NULL;
		}

		/* Save the original buffer reference */
		memcpy(&dmabuf->origbuf, orig, sizeof(dmabuf->origbuf));

		/*
		 * This is an input data buffer, copy original data into new
		 * allocated buffer.
		 */
		if (priv->type & DMAOBJ_INPUT && orig->data)
			memcpy(dmabuf->dmabuf.data, orig->data, orig->length);

		dmabuf->newbuf = true;

		DMAOBJ_TRACE("dmabuf %p - insert new buffer (%p) of %zu bytes",
			     dmabuf, dmabuf->dmabuf.data,
			     dmabuf->dmabuf.length);
		if (SIMPLEQ_EMPTY(&priv->list))
			SIMPLEQ_INSERT_HEAD(&priv->list, dmabuf, next);
		else
			SIMPLEQ_INSERT_TAIL(&priv->list, dmabuf, next);
	}

	return dmabuf;
}

/*
 * Add the @orig buffer at the end of the DMA Buffer list.
 * Return NULL if error, else the new entry in the list
 *
 * @priv    DMA Object private data
 * @orig    Original buffer reference
 */
static struct dmabuf *dmalist_insert_buf(struct priv_dmaobj *priv,
					 struct caambuf *orig)
{
	struct dmabuf *dmabuf = NULL;

	dmabuf = caam_calloc(sizeof(*dmabuf));
	if (dmabuf) {
		/* Save the original buffer reference */
		memcpy(&dmabuf->origbuf, orig, sizeof(dmabuf->origbuf));

		/* Setup the DMA Buffer (same as original) */
		memcpy(&dmabuf->dmabuf, orig, sizeof(dmabuf->dmabuf));
		dmabuf->newbuf = false;

		DMAOBJ_TRACE("dmabuf %p - insert buffer (%p) of %zu bytes",
			     dmabuf, dmabuf->dmabuf.data,
			     dmabuf->dmabuf.length);

		if (SIMPLEQ_EMPTY(&priv->list))
			SIMPLEQ_INSERT_HEAD(&priv->list, dmabuf, next);
		else
			SIMPLEQ_INSERT_TAIL(&priv->list, dmabuf, next);
	}

	return dmabuf;
}

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
		caam_sgt_cache_op(op, &obj->sgtbuf, obj->sgtbuf.length);
	else if (!obj->sgtbuf.buf->nocache)
		cache_operation(op, obj->sgtbuf.buf->data, obj->sgtbuf.length);
}

/*
 * Read the system cache line size.
 * Get the value from the ARM system configuration register
 */
static uint32_t read_cacheline_size(void)
{
	uint32_t value = 0;

#ifdef ARM64
	value = read_ctr_el0();
#else
	value = read_ctr();
#endif /* ARM64 */
	value = CTR_WORD_SIZE
		<< ((value >> CTR_DMINLINE_SHIFT) & CTR_DMINLINE_MASK);
	DMAOBJ_TRACE("System Cache Line size = %" PRIu32 " bytes", value);

	return value;
}

/*
 * Check if the buffer start address is aligned on the cache line.
 * If not allocate insert a new buffer in the DMA list and
 * add the remaining (if any) area in the DMA list.
 * Returns the number of entries added in the DMA List.
 *
 * @priv    DMA Object private data
 * @pabuf   Buffer to add in the list
 */
static int check_add_start_buf_aligned(struct priv_dmaobj *priv,
				       struct caambuf *pabuf)
{
	int ret_pa_area = 0;
	struct caambuf newbuf = {};
	vaddr_t va_align = 0;
	vaddr_t va_start = 0;
	size_t new_len = 0;
	unsigned int cacheline_size = 0;

	cacheline_size = read_cacheline_size();

	va_start = (vaddr_t)pabuf->data;
	va_align = ROUNDUP(va_start, cacheline_size);
	if (va_align != va_start) {
		DMAOBJ_TRACE("Start address not aligned 0x%" PRIxVA, va_start);
		new_len = va_align - va_start;

		if (new_len > pabuf->length ||
		    pabuf->length <= cacheline_size) {
			new_len = pabuf->length;
			DMAOBJ_TRACE("New full buffer length = %zu", new_len);
		} else {
			DMAOBJ_TRACE("New buffer length = %zu upto 0x%" PRIxVA,
				     new_len, va_align);
		}

		memcpy(&newbuf, pabuf, sizeof(newbuf));
		newbuf.length = new_len;

		if (!dmalist_insert_newbuf(priv, &newbuf))
			return -1;

		ret_pa_area = 1;
	}

	/* Adjust the pabuf entry to remove new buffer allocated if any */
	pabuf->length -= new_len;
	if (pabuf->length) {
		pabuf->data += new_len;
		pabuf->paddr += new_len;
	}

	DMAOBJ_TRACE("Start aligned buffer ret %d", ret_pa_area);
	return ret_pa_area;
}

/*
 * Check if the buffer end address is aligned on the cache line.
 * If not allocate insert a new buffer in the DMA list and
 * add the remaining (if any) area in the DMA list.
 * Returns -1 in case of error, else the increment DMA List entries.
 *
 * @priv    DMA Object private data
 * @pabuf   Buffer to add in the list
 * @maxlen  Maximum length to use
 * @counter DMA List entries
 */
static int check_add_end_buf_aligned(struct priv_dmaobj *priv,
				     struct caambuf *pabuf, size_t maxlen,
				     int counter)
{
	int ret_pa_area = counter;
	struct dmabuf *newelem = NULL;
	struct caambuf newbuf = {};
	vaddr_t va_align = 0;
	vaddr_t va_end_real = 0;
	vaddr_t va_end = 0;
	paddr_t last_pa = 0;
	size_t new_len = 0;
	unsigned int cacheline_size = 0;

	if (!pabuf->length)
		goto end;

	cacheline_size = read_cacheline_size();
	va_end_real = (vaddr_t)pabuf->data + pabuf->length;
	va_end = (vaddr_t)pabuf->data + maxlen;
	va_align = ROUNDUP(va_end, cacheline_size);
	if (va_align > va_end_real) {
		DMAOBJ_TRACE("End address not aligned 0x%" PRIxVA, va_end);
		va_align = ROUNDDOWN(va_end, cacheline_size);
		new_len = va_end - va_align;
		DMAOBJ_TRACE("New buffer length = %zu from 0x%" PRIxVA, new_len,
			     va_align);

		if (new_len < pabuf->length) {
			/*
			 * Insert first the last pabufs entry
			 * ending on a cacheline
			 */
			pabuf->length -= new_len;
			if (ADD_OVERFLOW(pabuf->paddr, pabuf->length,
					 &last_pa)) {
				ret_pa_area = -1;
				goto end;
			}

			if (IS_DMA_OVERFLOW(last_pa))
				newelem = dmalist_insert_newbuf(priv, pabuf);
			else
				newelem = dmalist_insert_buf(priv, pabuf);

			if (!newelem) {
				ret_pa_area = -1;
				goto end;
			}

			ret_pa_area++;
		}

		newbuf.data = (uint8_t *)va_align;
		newbuf.length = new_len;
		newbuf.paddr = virt_to_phys(newbuf.data);
		newbuf.nocache = pabuf->nocache;

		newelem = dmalist_insert_newbuf(priv, &newbuf);
		if (!newelem) {
			ret_pa_area = -1;
			goto end;
		}

		ret_pa_area++;
	} else {
		DMAOBJ_TRACE("End address aligned 0x%" PRIxVA, va_end);
		pabuf->length = maxlen;
		if (ADD_OVERFLOW(pabuf->paddr, pabuf->length, &last_pa)) {
			ret_pa_area = -1;
			goto end;
		}

		if (IS_DMA_OVERFLOW(last_pa))
			newelem = dmalist_insert_newbuf(priv, pabuf);
		else
			newelem = dmalist_insert_buf(priv, pabuf);

		if (!newelem) {
			ret_pa_area = -1;
			goto end;
		}

		ret_pa_area++;
	}

end:
	DMAOBJ_TRACE("End aligned buffer ret %d", ret_pa_area);
	return ret_pa_area;
}

/*
 * Go through all the @orig space to extract all physical area used to
 * map the buffer.
 * If one of the physical area is not accessible by the CAAM DMA, reallocates
 * a new DMA accessible buffer.
 * If success, returns the number of Physical Area used to handle the
 * @orig's data space, otherwise returns -1.
 *
 * @obj     CAAM DMA object
 * @orig    Original Data
 * @maxlen  Maximum length to use
 */
static int check_buffer_boundary(struct caamdmaobj *obj, struct caambuf *orig,
				 size_t maxlen)
{
	struct priv_dmaobj *priv = obj->priv;
	struct dmabuf *curelem = NULL;
	struct caambuf *pabufs = NULL;
	int nb_pa_area = -1;
	int ret_pa_area = 0;
	int idx = 0;
	paddr_t last_pa = 0;
	size_t remlen = maxlen;

	/*
	 * Get the number of physical areas used by the
	 * DMA Buffer
	 */
	nb_pa_area = caam_mem_get_pa_area(orig, &pabufs);
	DMAOBJ_TRACE("Number of pa areas = %d (for max length %zu bytes)",
		     nb_pa_area, remlen);
	if (nb_pa_area == -1) {
		ret_pa_area = -1;
		goto end;
	}

	/*
	 * In case of output data, ensure that the first entry in the
	 * DMA list is aligned on a cache line
	 */
	if (priv->type & DMAOBJ_OUTPUT) {
		ret_pa_area = check_add_start_buf_aligned(priv, &pabufs[idx]);
		if (ret_pa_area == -1)
			goto end;

		/*
		 * End of the buffer must be also aligned on the end of
		 * a cache line. So remove the last PA entry from
		 * the next for loop and handle this case after.
		 */
		if (ret_pa_area) {
			curelem = SIMPLEQ_FIRST(&priv->list);
			if (remlen > curelem->dmabuf.length)
				remlen -= curelem->dmabuf.length;
			else
				remlen = 0;
		}
		nb_pa_area--;
	}

	DMAOBJ_TRACE("Idx = %d - add %d PA areas", idx, nb_pa_area);
	for (; idx < nb_pa_area && remlen; idx++, ret_pa_area++) {
		DMAOBJ_TRACE("Remaining length = %zu", remlen);
		if (remlen < pabufs[idx].length)
			break;

		if (ADD_OVERFLOW(pabufs[idx].paddr, pabufs[idx].length,
				 &last_pa)) {
			ret_pa_area = -1;
			goto end;
		}

		DMAOBJ_TRACE("PA 0x%" PRIxPA " = 0x%" PRIxPA " + %zu", last_pa,
			     pabufs[idx].paddr, pabufs[idx].length);
		if (IS_DMA_OVERFLOW(last_pa))
			curelem = dmalist_insert_newbuf(priv, &pabufs[idx]);
		else
			curelem = dmalist_insert_buf(priv, &pabufs[idx]);

		if (!curelem) {
			ret_pa_area = -1;
			goto end;
		}

		if (remlen > curelem->dmabuf.length)
			remlen -= curelem->dmabuf.length;
		else
			remlen = 0;
	}

	DMAOBJ_TRACE("Last idx = %d - add %d PA areas", idx, nb_pa_area);
	DMAOBJ_TRACE("Remaining length = %zu", remlen);
	if (priv->type & DMAOBJ_OUTPUT)
		ret_pa_area = check_add_end_buf_aligned(priv, &pabufs[idx],
							remlen, ret_pa_area);

	orig->length = maxlen;

end:
	caam_free(pabufs);
	return ret_pa_area;
}

/*
 * Allocate and create the CAAM SGT/Buffer object based on the
 * @obj DMA Buffer list.
 *
 * @obj     CAAM DMA object
 */
static TEE_Result build_sgt_data(struct caamdmaobj *obj)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caamsgtbuf *sgtbuf = &obj->sgtbuf;
	struct priv_dmaobj *priv = obj->priv;
	struct dmabuf *dmabuf = NULL;
	unsigned int idx = 0;

	/*
	 * If data is mapped on non-contiguous physical areas,
	 * a SGT object of the number of physical area is built.
	 *
	 * Otherwise create a buffer object.
	 */
	if (sgtbuf->number > 1) {
		sgtbuf->sgt_type = true;
		sgtbuf->length = 0;

		DMAOBJ_TRACE("Allocate %d SGT entries", sgtbuf->number);

		retstatus = caam_sgtbuf_alloc(sgtbuf);
		if (retstatus != CAAM_NO_ERROR)
			return caam_status_to_tee_result(retstatus);

		SIMPLEQ_FOREACH(dmabuf, &priv->list, next)
		{
			memcpy(&sgtbuf->buf[idx], &dmabuf->dmabuf,
			       sizeof(sgtbuf->buf[idx]));
			sgtbuf->length += dmabuf->dmabuf.length;
			idx++;
		}

		/* Build the SGT table based on the physical area list */
		caam_sgt_fill_table(sgtbuf);

		sgtbuf->paddr = virt_to_phys(sgtbuf->sgt);
	} else {
		/*
		 * Only the data buffer is to be used and it's not
		 * split on multiple physical pages
		 */
		sgtbuf->sgt_type = false;

		DMAOBJ_TRACE("SGT is just a buffer");

		retstatus = caam_sgtbuf_alloc(sgtbuf);
		if (retstatus != CAAM_NO_ERROR)
			return caam_status_to_tee_result(retstatus);

		SIMPLEQ_FOREACH(dmabuf, &priv->list, next)
		{
			memcpy(sgtbuf->buf, &dmabuf->dmabuf,
			       sizeof(*sgtbuf->buf));
			sgtbuf->length += dmabuf->dmabuf.length;
		}

		sgtbuf->paddr = sgtbuf->buf->paddr;
	}

	return TEE_SUCCESS;
}

TEE_Result caam_dmaobj_init_input(struct caamdmaobj *obj, const void *data,
				  size_t length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct priv_dmaobj *priv = NULL;
	int nb_pa_area = 0;

	DMAOBJ_TRACE("Input object with data @%p of %zu bytes", data, length);

	if (!data || !length || !obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	obj->orig.paddr = virt_to_phys((void *)data);
	if (!obj->orig.paddr) {
		DMAOBJ_TRACE("Object virtual address error");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	obj->orig.data = (void *)data;
	obj->orig.length = length;
	if (!caam_mem_is_cached_buf((void *)data, length))
		obj->orig.nocache = 1;

	priv = caam_calloc(sizeof(*priv));
	if (!priv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->priv = priv;

	SIMPLEQ_INIT(&priv->list);

	/* Set the object type as input */
	priv->type = DMAOBJ_INPUT;

	nb_pa_area = check_buffer_boundary(obj, &obj->orig, obj->orig.length);
	if (nb_pa_area == -1) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->sgtbuf.number = nb_pa_area;

	ret = build_sgt_data(obj);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_init_output(struct caamdmaobj *obj, void *data,
				   size_t length, size_t min_length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caambuf newbuf = {};
	struct priv_dmaobj *priv = NULL;
	int nb_pa_area = 0;

	DMAOBJ_TRACE("Output object with data @%p of %zu (min %zu) bytes", data,
		     length, min_length);

	if (!obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	if (data) {
		obj->orig.paddr = virt_to_phys((void *)data);
		if (!obj->orig.paddr) {
			DMAOBJ_TRACE("Object virtual address error");
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto end;
		}

		obj->orig.data = (void *)data;
		obj->orig.length = length;
		if (!caam_mem_is_cached_buf((void *)data, length))
			obj->orig.nocache = 1;
	}

	priv = caam_calloc(sizeof(*priv));
	if (!priv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->priv = priv;

	SIMPLEQ_INIT(&priv->list);

	/* Set the object type as output */
	priv->type = DMAOBJ_OUTPUT;

	if (data) {
		nb_pa_area = check_buffer_boundary(obj, &obj->orig,
						   MIN(min_length, length));
		if (nb_pa_area == -1) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end;
		}
	}

	obj->sgtbuf.number = nb_pa_area;

	if (length < min_length || !data) {
		DMAOBJ_TRACE("Output buffer too short need %zu bytes (+%zu)",
			     min_length, min_length - length);
		newbuf.length = min_length - length;
		if (!dmalist_insert_newbuf(priv, &newbuf)) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end;
		}
		obj->sgtbuf.number++;
	}

	ret = build_sgt_data(obj);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

TEE_Result caam_dmaobj_new_output(struct caamdmaobj *obj, size_t length)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct priv_dmaobj *priv = NULL;

	DMAOBJ_TRACE("New Output object of %zu bytes", length);

	if (!obj || !length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	priv = caam_calloc(sizeof(*priv));
	if (!priv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->priv = priv;

	SIMPLEQ_INIT(&priv->list);
	retstatus = caam_alloc_align_buf(&obj->orig, length);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	/* Set the object type as output and allocated origin */
	priv->type |= DMAOBJ_OUTPUT | DMAOBJ_ALLOC_ORIG;

	if (!dmalist_insert_buf(priv, &obj->orig)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->sgtbuf.number = 1;

	ret = build_sgt_data(obj);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}

void caam_dmaobj_cache_push(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	enum utee_cache_operation op = TEE_CACHECLEAN;

	if (obj && obj->priv) {
		priv = obj->priv;

		if (priv->type & DMAOBJ_OUTPUT)
			op = TEE_CACHEFLUSH;

		dmaobj_cache_operation(op, obj);
	}
}

void caam_dmaobj_copy_to_orig(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct dmabuf *dmabuf = NULL;
	size_t dst_rlen = 0;
	size_t copy_size = 0;

	if (!obj)
		return;

	if (!obj->orig.data)
		return;

	dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

	priv = obj->priv;
	dst_rlen = obj->orig.length;
	obj->orig.length = 0;

	DMAOBJ_TRACE("Copy (len=%zu)", dst_rlen);

	SIMPLEQ_FOREACH(dmabuf, &priv->list, next)
	{
		if (!dst_rlen)
			break;

		if (dmabuf->origbuf.data) {
			copy_size = MIN(dst_rlen, dmabuf->origbuf.length);
			if (dmabuf->newbuf)
				memcpy(dmabuf->origbuf.data,
				       dmabuf->dmabuf.data, copy_size);

			obj->orig.length += copy_size;
			dst_rlen -= copy_size;
		}
	}
}

void caam_dmaobj_copy_ltrim_to_orig(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct dmabuf *dmabuf = NULL;
	uint8_t *dst = NULL;
	size_t off = 0;
	size_t offset = 0;
	size_t dst_rlen = 0;
	size_t copy_size = 0;

	if (!obj)
		return;

	if (!obj->orig.data)
		return;

	dmaobj_cache_operation(TEE_CACHEINVALIDATE, obj);

	priv = obj->priv;

	/* Find the first non-zero byte */
	SIMPLEQ_FOREACH(dmabuf, &priv->list, next)
	{
		for (offset = 0; offset < dmabuf->dmabuf.length;
		     off++, offset++) {
			if (dmabuf->dmabuf.data[offset])
				goto do_copy;
		}
	}

do_copy:
	dst = obj->orig.data;
	dst_rlen = obj->orig.length;
	obj->orig.length = 0;

	DMAOBJ_TRACE("Copy/Move Offset=%zu (len=%zu)", off, dst_rlen);

	if (off >= dst_rlen) {
		dst[0] = 0;
		obj->orig.length = 1;
		return;
	}

	/*
	 * Do the copy or move from DMA buffer starting at found
	 * offset @off while there is place in the original buffer.
	 */
	SIMPLEQ_FOREACH(dmabuf, &priv->list, next)
	{
		if (!dst_rlen)
			break;

		if (dmabuf->dmabuf.length < off) {
			off -= dmabuf->dmabuf.length;
			DMAOBJ_TRACE("Do not copy %zu-%zu", off,
				     dmabuf->dmabuf.length);
			continue;
		}

		if (off) {
			copy_size = MIN(dst_rlen, dmabuf->dmabuf.length - off);
			memcpy(dst, &dmabuf->dmabuf.data[off], copy_size);
			off = 0;
		} else {
			copy_size = MIN(dst_rlen, dmabuf->dmabuf.length);
			memcpy(dst, dmabuf->dmabuf.data, copy_size);
		}

		dst += copy_size;
		dst_rlen -= copy_size;
		obj->orig.length += copy_size;
	}
}

void caam_dmaobj_free(struct caamdmaobj *obj)
{
	struct priv_dmaobj *priv = NULL;
	struct dmabuf *dmabuf = NULL;
	struct dmabuf *next = NULL;

	if (obj && obj->priv) {
		priv = obj->priv;

		DMAOBJ_TRACE("Free %s object with data @%p of %zu bytes",
			     priv->type & DMAOBJ_INPUT ? "Input" : "Output",
			     obj->orig.data, obj->orig.length);

		dmabuf = SIMPLEQ_FIRST(&priv->list);
		while (dmabuf) {
			DMAOBJ_TRACE("Is type 0x%" PRIx8 " newbuf %s",
				     priv->type,
				     dmabuf->newbuf ? "true" : "false");
			if (dmabuf->newbuf && !(priv->type & DMAOBJ_DERIVED))
				caam_free_buf(&dmabuf->dmabuf);

			next = SIMPLEQ_NEXT(dmabuf, next);

			DMAOBJ_TRACE("Free dmabuf %p", dmabuf);
			caam_free(dmabuf);

			dmabuf = next;
			DMAOBJ_TRACE("Next to dmabuf %p", dmabuf);
		};

		DMAOBJ_TRACE("Free SGTBUF %p", &obj->sgtbuf);
		caam_sgtbuf_free(&obj->sgtbuf);

		if (priv->type & DMAOBJ_ALLOC_ORIG) {
			DMAOBJ_TRACE("Free Allocated origin");
			caam_free_buf(&obj->orig);
		}

		DMAOBJ_TRACE("Free private object %p", priv);
		caam_free(priv);

		memset(obj, 0, sizeof(*obj));
	}
}

TEE_Result caam_dmaobj_add_first_block(struct caamdmaobj *res,
				       struct caamblock *block,
				       struct caamdmaobj *obj)
{
	struct priv_dmaobj *respriv = NULL;
	struct priv_dmaobj *objpriv = NULL;
	enum caam_status retstatus = CAAM_BAD_PARAM;

	if (!obj || !res || !block)
		goto end;

	respriv = caam_calloc(sizeof(*respriv));
	if (!respriv) {
		retstatus = CAAM_OUT_MEMORY;
		goto end;
	}

	res->priv = respriv;
	SIMPLEQ_INIT(&respriv->list);

	objpriv = obj->priv;

	/* Set the same DMA Object type than input @obj */
	respriv->type = objpriv->type;

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
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct priv_dmaobj *priv = NULL;
	struct priv_dmaobj *frompriv = NULL;
	struct caambuf newbuf = {};
	struct dmabuf *newelem = NULL;
	struct dmabuf *dmabuf = NULL;
	vaddr_t start = 0;
	size_t rlength = length;

	DMAOBJ_TRACE("Derive DMA object %p - offset %zu - length %zu bytes",
		     from, offset, length);

	if (!obj) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	priv = caam_calloc(sizeof(*priv));
	if (!priv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	obj->priv = priv;
	SIMPLEQ_INIT(&priv->list);

	frompriv = from->priv;

	/*
	 * Set the same object type and add derived type
	 * to not free buffer if reallocated.
	 */
	priv->type = frompriv->type | DMAOBJ_DERIVED;

	/* Derive original buffer starting at @offset of @length */
	if (ADD_OVERFLOW((vaddr_t)from->orig.data, offset, &start)) {
		ret = TEE_ERROR_OVERFLOW;
		goto end;
	}

	obj->orig.data = (uint8_t *)start;
	obj->orig.length = length;

	DMAOBJ_TRACE("Object orig start @%p = @%p + %zu", obj->orig.data,
		     from->orig.data, offset);

	/* Derive DMA buffer starting at @offset of @length */
	frompriv = from->priv;
	SIMPLEQ_FOREACH(dmabuf, &frompriv->list, next)
	{
		if (dmabuf->dmabuf.length < offset)
			offset -= dmabuf->dmabuf.length;
		else
			break;
	}

	if (!dmabuf) {
		ret = TEE_ERROR_OVERFLOW;
		goto end;
	}

	if (ADD_OVERFLOW((vaddr_t)dmabuf->dmabuf.data, offset, &start)) {
		ret = TEE_ERROR_OVERFLOW;
		goto end;
	}

	newbuf.data = (uint8_t *)start;
	newbuf.length = dmabuf->dmabuf.length - offset;
	newbuf.length = MIN(rlength, newbuf.length);
	newbuf.nocache = dmabuf->dmabuf.nocache;
	newbuf.paddr = virt_to_phys(newbuf.data);

	DMAOBJ_TRACE("Object DMA start @%p = @%p + %zu (of %zu bytes)",
		     newbuf.data, dmabuf->dmabuf.data, offset, newbuf.length);

	newelem = dmalist_insert_buf(priv, &newbuf);
	if (!newelem) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	rlength -= newbuf.length;
	obj->sgtbuf.number = 1;

	for (dmabuf = SIMPLEQ_NEXT(dmabuf, next); dmabuf && rlength;
	     dmabuf = SIMPLEQ_NEXT(dmabuf, next)) {
		if (rlength >= dmabuf->dmabuf.length) {
			newelem = dmalist_insert_buf(priv, &dmabuf->dmabuf);
			if (!newelem) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto end;
			}
			rlength -= dmabuf->dmabuf.length;
			obj->sgtbuf.number++;
		} else {
			memcpy(&newbuf, &dmabuf->dmabuf, sizeof(newbuf));
			newbuf.length = MIN(rlength, dmabuf->dmabuf.length);
			newelem = dmalist_insert_buf(priv, &dmabuf->dmabuf);
			if (!newelem) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto end;
			}
			obj->sgtbuf.number++;
			break;
		}
	}

	ret = build_sgt_data(obj);

end:
	DMAOBJ_TRACE("Object returns 0x%" PRIx32, ret);
	return ret;
}
