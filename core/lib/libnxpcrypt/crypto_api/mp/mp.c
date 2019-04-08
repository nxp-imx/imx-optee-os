// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    mp.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Manufacturing Protection (MP) crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>

/* Library NXP includes */
#include <libnxpcrypt_mp.h>
#include <crypto_extension.h>

#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Export the MP Public Key
 *
 * @param[out] pubkey    MP Public key structure
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_mp_export_pubkey(struct nxpcrypt_buf *pubkey)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct nxpcrypt_mp  *mp;

	/* Check the pubkey buffer */
	if (!pubkey) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the parameters */
	if (!pubkey->data || (pubkey->length == 0)) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mp = nxpcrypt_getmod(CRYPTO_MP);
	if (mp) {
		if (mp->export_pubkey)
			ret = mp->export_pubkey(pubkey);
	}

	LIB_TRACE("MP Sign ret = 0x%"PRIx32"", ret);
	return ret;
}

/**
 * @brief   Export the MPMR content
 *
 * @param[out] mpmr_reg                MPMR register
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_mp_export_mpmr(struct nxpcrypt_buf *mpmr_reg)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct nxpcrypt_mp  *mp;

	/* Check the pointer mpmr_reg*/
	if (!mpmr_reg) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the parameters */
	if (!mpmr_reg->data || (mpmr_reg->length == 0)) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mp = nxpcrypt_getmod(CRYPTO_MP);
	if (mp) {
		if (mp->export_mpmr)
			ret = mp->export_mpmr(mpmr_reg);
	}

	LIB_TRACE("MP Sign ret = 0x%"PRIx32"", ret);
	return ret;
}

/**
 * @brief   Sign a message with the MP Private key\n
 *          and returns the signature.
 *
 * @param[in/out] sdata      MP Signature structure
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_mp_sign(struct nxpcrypt_mp_sign *sdata)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct nxpcrypt_mp *mp;

	/* Check the pointer sdata */
	if (!sdata) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* We assume that the message and signature could not be null */
	if ((!sdata->message.data) || (!sdata->signature.data) ||
		(sdata->message.length == 0) ||
		(sdata->signature.length == 0)) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* check the curve identifier */
	mp = nxpcrypt_getmod(CRYPTO_MP);
	if (mp) {
		if (mp->sign)
			ret = mp->sign(sdata);
	}

	LIB_TRACE("MP Sign ret = 0x%"PRIx32"", ret);
	return ret;
}
