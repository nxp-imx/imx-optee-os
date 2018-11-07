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
struct sgt {
	/* Word 0 */
	uint32_t ptr_ms :8;   ///< Address pointer (MS 8 bits)
	uint32_t res_w0 :24;  ///< Not used

	/* Word 1 */
	uint32_t ptr_ls;      ///< Address pointer (LS 32 bits)

	/* Word 2 */
	uint32_t length :30;  ///< Length (30 bits)
	uint32_t final  :1;   ///< Last entry in the table
	uint32_t ext    :1;   ///< Extension bit (if set, point to sgt table)

	/* Word 3 */
	uint32_t offset :13;  ///< Offset in memory buffer
	uint32_t res_w3 :19;  ///< Not used
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
