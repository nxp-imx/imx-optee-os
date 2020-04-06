// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Scatter-Gatter Table management utilities.
 */
#include <caam_common.h>
#include <caam_io.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_trace.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <tee/cache.h>
#include <util.h>

#define ENTRY_LEN(len)	((len) & GENMASK_32(29, 0))
#define BS_ENTRY_EXT	BIT32(31)
#define BS_ENTRY_FINAL	BIT32(30)

void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt)
{
	unsigned int idx = 0;

	cache_operation(TEE_CACHECLEAN, (void *)insgt->sgt,
			insgt->number * sizeof(struct caamsgt));

	SGT_TRACE("SGT @%p %d entries", insgt, insgt->number);
	for (idx = 0; idx < insgt->number; idx++) {
		if (insgt->sgt[idx].len_f_e & BS_ENTRY_EXT) {
			SGT_TRACE("SGT EXT @%p", insgt->buf[idx].data);
			caam_sgt_cache_op(op, (void *)insgt->buf[idx].data);

			/*
			 * Extension entry is the last entry of the
			 * current SGT, even if there are entries
			 * after, they are not used.
			 */
			break;
		}

		if (!insgt->buf[idx].nocache)
			cache_operation(op, (void *)insgt->buf[idx].data,
					insgt->buf[idx].length);
	}
}

void caam_sgt_set_entry(struct caamsgt *sgt, paddr_t paddr, size_t len,
			unsigned int offset, bool final_e, bool ext_e)
{
	unsigned int len_f_e = 0;

	caam_write_val32(&sgt->ptr_ls, paddr);
#ifdef CFG_CAAM_64BIT
	caam_write_val32(&sgt->ptr_ms, paddr >> 32);
#else
	caam_write_val32(&sgt->ptr_ms, 0);
#endif

	len_f_e = ENTRY_LEN(len);
	if (final_e)
		len_f_e |= BS_ENTRY_FINAL;
	else if (ext_e)
		len_f_e |= BS_ENTRY_EXT;

	caam_write_val32(&sgt->len_f_e, len_f_e);
	caam_write_val32(&sgt->offset, offset);
}

static void caam_sgt_fill_table(struct caambuf *buf, struct caamsgtbuf *sgt,
				int start_idx, int nb_pa)
{
	int idx = 0;

	SGT_TRACE("Create %d SGT entries", nb_pa);

	for (; idx < nb_pa; idx++) {
		sgt->buf[idx + start_idx].data = buf[idx].data;
		sgt->buf[idx + start_idx].length = buf[idx].length;
		sgt->buf[idx + start_idx].paddr = buf[idx].paddr;
		sgt->buf[idx + start_idx].nocache = buf[idx].nocache;
		sgt->length += buf[idx].length;
		if (idx < nb_pa - 1)
			CAAM_SGT_ENTRY(&sgt->sgt[idx + start_idx],
				       sgt->buf[idx + start_idx].paddr,
				       sgt->buf[idx + start_idx].length);
		else
			CAAM_SGT_ENTRY_FINAL(&sgt->sgt[idx + start_idx],
					     sgt->buf[idx + start_idx].paddr,
					     sgt->buf[idx + start_idx].length);

		SGT_TRACE("SGT[%d]->data   = %p", idx + start_idx,
			  sgt->buf[idx + start_idx].data);
		SGT_TRACE("SGT[%d]->length = %zu", idx + start_idx,
			  sgt->buf[idx + start_idx].length);
		SGT_TRACE("SGT[%d]->paddr  = 0x%" PRIxPA, idx + start_idx,
			  sgt->buf[idx + start_idx].paddr);
		SGT_TRACE("SGT[%d]->ptr_ms   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].ptr_ms);
		SGT_TRACE("SGT[%d]->ptr_ls   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].ptr_ls);
		SGT_TRACE("SGT[%d]->len_f_e  = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].len_f_e);
		SGT_TRACE("SGT[%d]->offset   = %" PRIx32, idx + start_idx,
			  sgt->sgt[idx + start_idx].offset);
	}

}

enum caam_status caam_sgt_build_data(struct caamsgtbuf *sgtbuf,
				     struct caambuf *data,
				     struct caambuf *pabufs)
{
	enum caam_status retstatus = CAAM_FAILURE;

	/*
	 * If data is mapped on non-contiguous physical areas,
	 * a SGT object of the number of physical area is built.
	 *
	 * Otherwise create a buffer object.
	 */
	if (sgtbuf->number > 1) {
		sgtbuf->sgt_type = true;
		sgtbuf->length = 0;

		SGT_TRACE("Allocate %d SGT entries", sgtbuf->number);
		retstatus = caam_sgtbuf_alloc(sgtbuf);

		if (retstatus != CAAM_NO_ERROR)
			return retstatus;

		/* Build the SGT table based on the physical area list */
		caam_sgt_fill_table(pabufs, sgtbuf, 0, sgtbuf->number);

		sgtbuf->paddr = virt_to_phys(sgtbuf->sgt);
	} else {
		/*
		 * Only the data buffer is to be used and it's not
		 * split on mutliple physical pages
		 */
		sgtbuf->sgt_type = false;

		retstatus = caam_sgtbuf_alloc(sgtbuf);
		if (retstatus != CAAM_NO_ERROR)
			return retstatus;

		sgtbuf->buf->data = data->data;
		sgtbuf->buf->length = data->length;
		sgtbuf->buf->paddr = data->paddr;
		sgtbuf->buf->nocache = data->nocache;
		sgtbuf->length = data->length;
		sgtbuf->paddr = sgtbuf->buf->paddr;
	}

	return CAAM_NO_ERROR;
}

void caam_sgtbuf_free(struct caamsgtbuf *data)
{
	if (data->sgt_type)
		caam_free(data->sgt);
	else
		caam_free(data->buf);

	data->sgt = NULL;
	data->buf = NULL;
}

enum caam_status caam_sgtbuf_alloc(struct caamsgtbuf *data)
{
	if (!data)
		return CAAM_BAD_PARAM;

	if (data->sgt_type) {
		data->sgt =
			caam_calloc(data->number * (sizeof(struct caamsgt) +
						    sizeof(struct caambuf)));
		data->buf = (void *)(((uint8_t *)data->sgt) +
				     (data->number * sizeof(struct caamsgt)));
	} else {
		data->buf = caam_calloc(data->number * sizeof(struct caambuf));
		data->sgt = NULL;
	}

	if (!data->buf || (!data->sgt && data->sgt_type)) {
		caam_sgtbuf_free(data);
		return CAAM_OUT_MEMORY;
	}

	return CAAM_NO_ERROR;
}
