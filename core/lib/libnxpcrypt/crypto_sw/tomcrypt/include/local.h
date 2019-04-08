/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    local.h
 *
 * @brief   Software implementation of the NXP cryptographic library.
 *          Software connection with LibTomCrypt. Local include file.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

/* Global includes */
#include <tee_api_types.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_hash.h>
#include <libnxpcrypt_cipher.h>

/* Library TomCrypt includes */
#include <tomcrypt.h>

/**
 * @brief   Define the maximum size in bits of a LibTomCrypt bignumber
 */
#define LTC_MAX_BITS_PER_VARIABLE   4096

struct ltc_prng {
	int        index;
	prng_state state;
};

/**
 * @brief   Initialize the RSA module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_rsa_init(void);

/**
 * @brief   Initialize the DSA module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_dsa_init(void);

/**
 * @brief   Initialize the ECC module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_ecc_init(void);

/**
 * @brief   Initialize the DH module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_dh_init(void);

/**
 * @brief   Initialize the RNG module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_rng_init(void);

/**
 * @brief   Initialize the HASH module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_hash_init(void);

/**
 * @brief   Initialize the HASH SW module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_hash_sw_init(void);

/**
 * @brief   Initialize the HMAC SW module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_hmac_sw_init(void);

/**
 * @brief   Allocation and setup the scratch memory pool used by LibTomCrypt
 *
 * @retval  0   if success
 * @retval (-1) otherwise
 */
int libsoft_mpa_init(void);

/**
 * @brief   Initialize the Cipher module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_cipher_init(void);

/**
 * @brief   Initialize the Authentication module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_authenc_init(void);

/**
 * @brief   Find Hash index into the LibTomCrypt hash registered
 *
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval  >=0 if found
 * @retval  (-1) if not found
 */
int get_ltc_hashindex(enum nxpcrypt_hash_id algo);

/**
 * @brief   Find Cipher index into the LibTomCrypt hash registered
 *
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval  >=0 if found
 * @retval  (-1) if not found
 */
int get_ltc_cipherindex(enum nxpcrypt_cipher_id algo);

/**
 * @brief   Return the reference to the PRNG
 *
 * @retval  reference to PRNG
 */
struct ltc_prng *get_ltc_prng(void);

/**
 * @brief   Convert a TEE_Result code to a LibTomCrypt error code
 *
 * @param[in] code  TEE_Result code
 *
 * @retval  CRYPT_xxx code
 */
int conv_TEE_Result_to_CRYPT(TEE_Result code);

/**
 * @brief   Convert a LibTomCrypt error code to TEE_Result
 *
 * @param[in] code  CRYPT_xxx code
 *
 * @retval  TEE_Result code
 */
TEE_Result conv_CRYPT_to_TEE_Result(int code);

#endif // __LOCAL_H__
