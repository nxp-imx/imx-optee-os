/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    libnxpcrypt_huk.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Hardware Unique Key interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_HUK_H__
#define __LIBNXPCRYPT_HUK_H__

#include <tee_api_types.h>

/**
 * @brief   NXP Crypto Library HUK driver operations
 *
 */
struct nxpcrypt_huk {
	///< Allocates of the Software context
	TEE_Result (*generate_huk)(struct nxpcrypt_buf *hukkey);
};

#endif /* __LIBNXPCRYPT_HUL_H__ */
