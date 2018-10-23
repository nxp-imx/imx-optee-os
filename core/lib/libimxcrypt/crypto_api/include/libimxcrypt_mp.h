/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_mp.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Manufacturing Protection (MP) interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_MP_H__
#define __LIBIMXCRYPT_MP_H__

#include <tee_api_types.h>
#include <crypto_extension.h>

/**
 * @brief   i.MX Crypto Library MP driver operations
 *
 */
struct imxcrypt_mp {
	///< Export the MP Public key
	TEE_Result (*export_pubkey)(struct imxcrypt_buf *pubkey);
	///< Export the MPMR content
	TEE_Result (*export_mpmr)(struct imxcrypt_buf *mpmr_reg);
	///< Sign a message and returns the signature
	TEE_Result (*sign)(struct imxcrypt_mp_sign *sdata);
};


#endif /* __LIBIMXCRYPT_MP_H__ */
