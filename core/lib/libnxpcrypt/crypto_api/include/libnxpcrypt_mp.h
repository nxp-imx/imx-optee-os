/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt_mp.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Manufacturing Protection (MP) interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_MP_H__
#define __LIBNXPCRYPT_MP_H__

#include <tee_api_types.h>
#include <crypto_extension.h>

/**
 * @brief   NXP Crypto Library MP driver operations
 *
 */
struct nxpcrypt_mp {
	///< Export the MP Public key
	TEE_Result (*export_pubkey)(struct nxpcrypt_buf *pubkey);
	///< Export the MPMR content
	TEE_Result (*export_mpmr)(struct nxpcrypt_buf *mpmr_reg);
	///< Sign a message and returns the signature
	TEE_Result (*sign)(struct nxpcrypt_mp_sign *sdata);
};


#endif /* __LIBNXPCRYPT_MP_H__ */
