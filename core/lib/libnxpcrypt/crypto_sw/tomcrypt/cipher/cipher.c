// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    cipher.c
 *
 * @brief   Implementation of the cipher pseudo-driver compatible with the
 *          NXP cryptographic library. LibTomCrypt's descriptor wrapper
 *          to use the HW module.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>

/* Local includes */
#include "local.h"

#ifdef CFG_CRYPTO_CIPHER_HW
/*
 * Definition of a CIPHER wrapper used into the LibTomCrypt
 * to access the HW CIPHER module.
 */
/**
 * @brief   Initialization of the CIPHER State.
 *
 * @param[in]     algo        TEE Aglorithm id
 * @param[in]     key         Cipher key
 * @param[in]     keylen      Length of the key
 * @param[in]     num_rounds  Number of rounds
 * @param[in/out] skey        Cipher context to initialize
 *
 * @retval CRYPT_OK            Success
 * @retval CRYPT_MEM           Out of memory
 * @retval CRYPT_INVALID_ARG   Invalid argument
 */
static int do_init(uint32_t algo, const unsigned char *key, int keylen,
		int num_rounds __unused, symmetric_key *skey)
{
	TEE_Result res;

	/* First Allocate the context */
	skey->data = NULL;
	res = crypto_cipher_alloc_ctx(&skey->data, algo);
	if (res == TEE_SUCCESS) {
		/*
		 * Initialize the CIPHER Direction mode is not kept
		 * so there is not importance to give ENCRYPT or DECYPT
		 */
		res = crypto_cipher_init(skey->data, algo, TEE_MODE_ENCRYPT,
				key, keylen, NULL, 0, NULL, 0);
	}

	if (res != TEE_SUCCESS) {
		/* Free the context in case of error */
		crypto_cipher_free_ctx(skey->data, algo);
	}

	return conv_TEE_Result_to_CRYPT(res);
}

/**
 * @brief   Update the cipher block
 *
 * @param[in]  algo  TEE Aglorithm id
 * @param[in]  mode  Operation mode
 * @param[in]  data  Data to encrypt/decrypt
 * @param[in]  len   Length of the input data and output result
 * @param[out] dst   Result block of the operation
 * @param[in]  skey  Cipher context
 *
 * @retval CRYPT_OK  Success
 */
static int do_update(uint32_t algo, TEE_OperationMode mode,
				const unsigned char *data, size_t len,
				unsigned char *dst,
				symmetric_key *skey)
{
	TEE_Result res;

	/* Update Cipher - not last block */
	res = crypto_cipher_update(skey->data, algo, mode, false,
			data, len, dst);

	if (res != TEE_SUCCESS) {
		/* Free the context in case of error */
		crypto_cipher_free_ctx(skey->data, algo);
	}

	return conv_TEE_Result_to_CRYPT(res);
}

/**
 * @brief   Finalize the cipher
 *
 * @param[in]  algo    TEE Aglorithm id
 * @param[in]  skey    Cipher context
 */
static void do_final(uint32_t algo, symmetric_key *skey)
{
	/* Finalize cipher */
	crypto_cipher_final(skey->data, algo);

	/* Free the context in case of error */
	crypto_cipher_free_ctx(skey->data, algo);
}

/**
 * @brief   Self-test. Do Nothing
 *
 * @retval  CRYPT_NOP  Self-test disabled
 */
static int do_test(void)
{
	return CRYPT_NOP;
}

/**
 * @brief   Create local static function do_init associated to the
 *          algorithm \a algo
 */
#define WRAP_CIPHER_INIT(name, algo)                            \
static int do_init_##name(const unsigned char *key, int keylen, \
		int num_rounds, symmetric_key *skey)                    \
{                                                               \
	return do_init(algo, key, keylen, num_rounds, skey);        \
}

/**
 * @brief   Create local static function do_update encryption
 *          associated to the algorithm \a algo
 */
#define WRAP_CIPHER_UPDATE_ENC(name, algo, len)                     \
static int do_update_enc_##name(const unsigned char *data,          \
		unsigned char *dst, symmetric_key *skey)                    \
{                                                                   \
	return do_update(algo, TEE_MODE_ENCRYPT, data, len, dst, skey); \
}

/**
 * @brief   Create local static function do_update decryption
 *          associated to the algorithm \a algo
 */
#define WRAP_CIPHER_UPDATE_DEC(name, algo, len)                     \
static int do_update_dec_##name(const unsigned char *data,          \
		unsigned char *dst, symmetric_key *skey)                    \
{                                                                   \
	return do_update(algo, TEE_MODE_DECRYPT, data, len, dst, skey); \
}

/**
 * @brief   Create local static function do_final associated to the
 *          algorithm \a algo
 */
#define WRAP_CIPHER_FINAL(name, algo)            \
static void do_final_##name(symmetric_key *skey) \
{                                                \
	do_final(algo, skey);                        \
}

#define WRAP_CIPHER_INIT_GEN(name)	\
			WRAP_CIPHER_INIT(name, TEE_ALG_##name)
#define WRAP_CIPHER_UPDATE_ENC_GEN(name, len) \
			WRAP_CIPHER_UPDATE_ENC(name, TEE_ALG_##name, len)
#define WRAP_CIPHER_UPDATE_DEC_GEN(name, len) \
			WRAP_CIPHER_UPDATE_DEC(name, TEE_ALG_##name, len)
#define WRAP_CIPHER_FINAL_GEN(name)	\
			WRAP_CIPHER_FINAL(name, TEE_ALG_##name)

/*
 * Registration of the AES Wrapper to use the HW CIPHER module
 */
/**
 * @brief   AES ECB NOPAD algorithm
 */
WRAP_CIPHER_INIT_GEN(AES_ECB_NOPAD)
WRAP_CIPHER_UPDATE_ENC_GEN(AES_ECB_NOPAD, TEE_AES_BLOCK_SIZE)
WRAP_CIPHER_UPDATE_DEC_GEN(AES_ECB_NOPAD, TEE_AES_BLOCK_SIZE)
WRAP_CIPHER_FINAL_GEN(AES_ECB_NOPAD)

static const struct ltc_cipher_descriptor aes_wrap_desc = {
	.name              = "aes_wrap",
	.ID                = 6,
	.min_key_length    = 16,
	.max_key_length    = 32,
	.block_length      = TEE_AES_BLOCK_SIZE,
	.default_rounds    = 10,
	.setup             = &do_init_AES_ECB_NOPAD,
	.ecb_encrypt       = &do_update_enc_AES_ECB_NOPAD,
	.ecb_decrypt       = &do_update_dec_AES_ECB_NOPAD,
	.done              = &do_final_AES_ECB_NOPAD,
	.test              = &do_test,
	.keysize           = NULL,
	.accel_ecb_encrypt = NULL,
	.accel_ecb_decrypt = NULL,
	.accel_cbc_encrypt = NULL,
	.accel_cbc_decrypt = NULL,
	.accel_ctr_encrypt = NULL,
	.accel_xts_encrypt = NULL,
	.accel_xts_decrypt = NULL,
};
#endif // CFG_CRYPTO_CIPHER_HW

/**
 * @brief   Find Cipher index into the LibTomCrypt Cipher registered
 *
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval  >=0 if found
 * @retval  (-1) if not found
 */
int get_ltc_cipherindex(enum nxpcrypt_cipher_id algo)
{
	int index = (-1);

	switch (algo) {
	case AES_ECB_NOPAD:
		index = find_cipher("aes_wrap");
		break;

	default:
		break;
	}

	return index;
}

/**
 * @brief   Initialize the CIPHER module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_cipher_init(void)
{
	int ret = 0;

#ifdef CFG_CRYPTO_CIPHER_HW
	/* Register the Cipher descriptor into libTomCrypt Software */
	ret = register_cipher(&aes_wrap_desc);
#endif

	return (ret == (-1)) ? ret : 0;
}

