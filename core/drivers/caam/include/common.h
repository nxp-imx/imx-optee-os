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
#define NB_JOBS_QUEUE	(10)

/**
 * @brief   Flag Job Ring Owner is Secure
 */
#define JROWNER_SECURE	(0x10)

/**
 * @brief   Job Ring Owner. Enumerate Id (expect the Secure Flag) correspond
 *          to the HW ID.
 */
enum jr_owner {
	JROWN_ARM_NS = 0x01,                  ///< Non-Secure ARM
	JROWN_ARM_S  = JROWNER_SECURE | 0x1,  ///< Secure ARM
};

/**
 * @brief   Definition of a CAAM buffer type
 */
struct caambuf {
	uint8_t *data;    ///< Data buffer
	paddr_t paddr;    ///< Physical address of the buffer
	size_t  length;   ///< Number of bytes in the data buffer
};

#endif /* __COMMON_H__ */
