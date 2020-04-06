/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Scatter-Gather Table management utilities header.
 */
#ifndef __CAAM_UTILS_SGT_H__
#define __CAAM_UTILS_SGT_H__

#include <caam_types.h>
#include <utee_types.h>

/*
 * Scatter/Gather Table type for input and output data
 */
struct caamsgt {
	uint32_t ptr_ms;  /* W0 - Address pointer (MS 8 LSBs) */
	uint32_t ptr_ls;  /* W1 - Address pointer (LS 32 bits) */
	uint32_t len_f_e; /* W2 - Length 30bits, 1bit Final, 1bit Extension */
	uint32_t offset;  /* W3- Offset in memory buffer (13 LSBs) */
};

/*
 * Data buffer encoded in SGT format
 */
struct caamsgtbuf {
	struct caamsgt *sgt; /* SGT Array */
	struct caambuf *buf; /* Buffer Array */
	unsigned int number; /* Number of SGT/Buf */
	size_t length;	     /* Total length of the data encoded */
	paddr_t paddr;	     /* Physical address to use in CAAM descriptor */
	bool sgt_type;	     /* Define the data format */
};

/*
 * Allocate data of type struct caamsgtbuf
 *
 * @data    [out] Data object allocated
 */
enum caam_status caam_sgtbuf_alloc(struct caamsgtbuf *data);

/*
 * Free data of type struct caamsgtbuf
 *
 * @data    Data object to free
 */
void caam_sgtbuf_free(struct caamsgtbuf *data);

/*
 * Cache operation on SGT table
 *
 * @op     Cache operation
 * @insgt  SGT table
 */
void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt);

/*
 * Set a Scatter Gather Table Entry
 *
 * @sgt      SGT entry
 * @paddr    Data's physical address
 * @len      Data's length
 * @offset   Offset to start in data buffer
 * @final_e  Final entry in the table if true
 * @ext_e    Entry is a SGT table extension
 */
void caam_sgt_set_entry(struct caamsgt *sgt, vaddr_t paddr, size_t len,
			unsigned int offset, bool final_e, bool ext_e);

#define CAAM_SGT_ENTRY(sgt, paddr, len)                                        \
	caam_sgt_set_entry(sgt, paddr, len, 0, false, false)
#define CAAM_SGT_ENTRY_FINAL(sgt, paddr, len)                                  \
	caam_sgt_set_entry(sgt, paddr, len, 0, true, false)
#define CAAM_SGT_ENTRY_EXT(sgt, paddr, len)                                    \
	caam_sgt_set_entry(sgt, paddr, len, 0, false, true)

/*
 * Build a SGT object with @data buffer.
 * If the @data buffer is a buffer mapped on non-contiguous physical areas,
 * convert it in SGT entries.
 *
 * @sgtbuf [out] SGT object built
 * @data   Operation data
 * @pabufs Physical Areas list of the @data buffer
 */
enum caam_status caam_sgt_build_data(struct caamsgtbuf *sgtbuf,
				     struct caambuf *data,
				     struct caambuf *pabufs);

#endif /* __CAAM_UTILS_SGT_H__ */
