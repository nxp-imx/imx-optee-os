/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM HUK manager header
 */
#ifndef __CAAM_HUK_H__
#define __CAAM_HUK_H__

#include <caam_common.h>
#include <tee_api_types.h>

#ifdef CFG_NXP_CAAM_HUK_DRV
/*
 * Initialize the HUK module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_huk_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_huk_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_HUK_DRV */

#endif /* __CAAM_HUK_H__ */
