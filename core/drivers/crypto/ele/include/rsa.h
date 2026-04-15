/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __RSA_H__
#define __RSA_H__

#include <tee_api_types.h>

#ifdef CFG_IMX_ELE_RSA_DRV
/*
 * Initialize the RSA module
 */
TEE_Result imx_ele_rsa_init(void);
#else
static inline TEE_Result imx_ele_rsa_init(void)
{
	return TEE_SUCCESS;
}
#endif /* CFG_IMX_ELE_RSA_DRV */

#endif /* __RSA_H__ */
