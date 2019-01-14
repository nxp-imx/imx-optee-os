/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    libimxcrypt_huk.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Hardware Unique Key interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_HUK_H__
#define __LIBIMXCRYPT_HUK_H__

#include <tee_api_types.h>

/**
 * @brief   i.MX Crypto Library HUK driver operations
 *
 */
struct imxcrypt_huk {
	///< Allocates of the Software context
	TEE_Result (*generate_huk)(struct imxcrypt_buf *hukkey);
};

#endif /* __LIBIMXCRYPT_HUL_H__ */
