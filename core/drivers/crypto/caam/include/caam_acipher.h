/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-209 NXP
 *
 * Brief   CAAM Asymmetric Cipher manager header.
 */
#ifndef __CAAM_ACIPHER_H__
#define __CAAM_ACIPHER_H__

#include <caam_common.h>

#ifdef CFG_NXP_CAAM_ECC_DRV
/*
 * Initialize the Cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_ecc_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_ecc_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_ECC_DRV */
#endif /* __CAAM_ACIPHER_H__ */
