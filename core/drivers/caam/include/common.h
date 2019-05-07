/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    common.h
 *
 * @brief   CAAM driver common include file.\n
 *          Definition of the internal driver status codes.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* Global Common includes */
#include <trace.h>
#include <types_ext.h>

/* Local Common includes */
#include "desc_helper.h"
#include "caam_status.h"

#if (TRACE_LEVEL >= TRACE_DEBUG)
#define DRV_TRACE(...)		trace_printf(__func__, __LINE__, 0, false, \
							 __VA_ARGS__)
#define DRV_DUMPDESC(desc)	dump_desc(desc)

#define DRV_DUMPBUF(title, buf, len) \
					{DRV_TRACE("%s @ 0x%"PRIxPTR": %d", \
						title, (uintptr_t)buf, len); \
					 dhex_dump(NULL, 0, 0, buf, len); }

#else
#define DRV_TRACE(...)
#define DRV_DUMPDESC(...)
#define DRV_DUMPBUF(...)
#endif

/**
 * @brief   Definition of the number of CAAM Jobs to manage in JR queues
 */
#define NB_JOBS_QUEUE	10

/**
 * @brief   Flag Job Ring Owner is Secure
 */
#define JROWNER_SECURE	0x10

#if !defined(CFG_MX7ULP)
/**
 * @brief   Job Ring Owner. Enumerate Id (expect the Secure Flag) correspond
 *          to the HW ID.
 */
enum jr_owner {
	JROWN_ARM_NS = 0x1,                   ///< Non-Secure ARM
	JROWN_ARM_S  = JROWNER_SECURE | 0x1,  ///< Secure ARM
};
#else
/**
 * @brief   Job Ring Owner. Enumerate Id (expect the Secure Flag) correspond
 *          to the HW ID.
 */
enum jr_owner {
	JROWN_ARM_NS = 0x4,                   ///< Non-Secure ARM
	JROWN_ARM_S  = JROWNER_SECURE | 0x4,  ///< Secure ARM
};
#endif

/**
 * @brief   Definition of a CAAM buffer type
 */
struct caambuf {
	uint8_t *data;    ///< Data buffer
	paddr_t paddr;    ///< Physical address of the buffer
	size_t  length;   ///< Number of bytes in the data buffer
	uint8_t nocache;  ///< =1 if buffer is not cacheable
};

/**
 * @brief   Definition of a CAAM Block buffer. Buffer used to store
 *          user source data to build a full algorithm block buffer
 */
struct caamblock {
	struct caambuf buf;     ///< Data buffer
	size_t         filled;  ///< Current length filled in the buffer
	size_t         max;     ///< Maximum size of the block
};

/**
 * @brief   Definition of key size
 */
struct defkey {
	uint8_t min;  ///< Minimum size
	uint8_t max;  ///< Maximum size
	uint8_t mod;  ///< Key modulus
};

/**
 * @brief Scatter/Gather Table type for inputs and outputs data
 */
#define	SG_ENTRY_LENGTH_MASK	0x3FFFFFFF
#define	SG_ENTRY_EXTENSION_BIT	BIT32(31)
#define	SG_ENTRY_FINAL_BIT	BIT32(30)

#define	SG_ENTRY_OFFSET_MASK	0x00001FFF
#define	SG_ENTRY_OFFSET_SHIFT	0

struct sgt {
	/* Word 0 */
	uint32_t ptr_ms;   ///< Address pointer (MS 8 LSBs)

	/* Word 1 */
	uint32_t ptr_ls;      ///< Address pointer (LS 32 bits)

	/* Word 2 */
	uint32_t len_f_e;  ///< Length 30bits + 1bit Final + 1bit Extension)

	/* Word 3 */
	uint32_t offset;   ///< Offset in memory buffer (13 LSBs)
};

/**
 * @brief   Data buffer encoded in SGT format
 */
struct sgtbuf {
	struct sgt     *sgt;      ///< SGT Array
	struct caambuf *buf;      ///< Buffer Array
	uint8_t        number;    ///< Number of SGT/Buf
	bool           sgt_type;  ///< Define the data format
};

#endif /* __COMMON_H__ */
