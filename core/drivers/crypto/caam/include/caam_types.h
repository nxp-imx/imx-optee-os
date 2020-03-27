/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 *
 * CAAM driver data type definition.
 */

#ifndef __CAAM_TYPES_H__
#define __CAAM_TYPES_H__

#include <types_ext.h>

/*
 * Definition of a CAAM buffer type
 */
struct caambuf {
	uint8_t *data;	 /* Data buffer */
	paddr_t paddr;	 /* Physical address of the buffer */
	size_t length;	 /* Number of bytes in the data buffer */
	uint8_t nocache; /* =1 if buffer is not cacheable, 0 otherwise */
};

/*
 * Definition of a CAAM Block buffer. Buffer used to store
 * user source data to build a full algorithm block buffer
 */
struct caamblock {
	struct caambuf buf; /* Data buffer */
	size_t filled;	    /* Current length filled in the buffer */
	size_t max;	    /* Maximum size of the block */
};

/*
 * Definition of key size
 */
struct caamdefkey {
	uint8_t min; /* Minimum size */
	uint8_t max; /* Maximum size */
	uint8_t mod; /* Key modulus */
};

/*
 * Scatter/Gather Table type for input and output data
 */
struct caamsgt {
	/* Word 0 */
	uint32_t ptr_ms;   /* Address pointer (MS 8 LSBs) */

	/* Word 1 */
	uint32_t ptr_ls;   /* Address pointer (LS 32 bits) */

	/* Word 2 */
	uint32_t len_f_e;  /* Length 30bits + 1bit Final + 1bit Extension) */

	/* Word 3 */
	uint32_t offset;   /* Offset in memory buffer (13 LSBs) */
};

/*
 * Data buffer encoded in SGT format
 */
struct caamsgtbuf {
	struct caamsgt *sgt; /* SGT Array */
	struct caambuf *buf; /* Buffer Array */
	unsigned int number; /* Number of SGT/Buf */
	size_t length;       /* Total length of the data encoded */
	paddr_t paddr;	     /* Physical address to use in CAAM descriptor */
	bool sgt_type;       /* Define the data format */
};

#endif /* __CAAM_TYPES_H__ */
