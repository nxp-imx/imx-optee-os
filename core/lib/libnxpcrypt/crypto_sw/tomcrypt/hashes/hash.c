// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hash.c
 *
 * @brief   Implementation of the hash pseudo-driver compatible with the
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

#ifdef CFG_CRYPTO_HASH_HW
/*
 * Definition of a HASH wrapper used into the LibTomCrypt
 * to access the HW HASH module.
 */
/**
 * @brief   Initialization of the HASH State.
 *
 * @param[in]     algo  TEE Aglorithm id
 * @param[in/out] hash  Hash context to initialize
 *
 * @retval CRYPT_OK            Success
 * @retval CRYPT_INVALID_ARG   Invalid argument
 */
static int do_init(uint32_t algo, hash_state *hash)
{
	TEE_Result res;

	/* First Allocate the context */
	hash->data = NULL;
	res = crypto_hash_alloc_ctx(&hash->data, algo);
	if (res == TEE_SUCCESS) {
		/* Initialize the HASH */
		res = crypto_hash_init(hash->data, algo);
	}

	if (res != TEE_SUCCESS) {
		/* Free the context in case of error */
		crypto_hash_free_ctx(hash->data, algo);
	}

	return conv_TEE_Result_to_CRYPT(res);
}

/**
 * @brief   Hashes to input block of data
 *
 * @param[in] algo  TEE Aglorithm id
 * @param[in] hash  Hash context
 * @param[in] buf   Input data buffer
 * @param[in] len   Input buffer length in bytes
 *
 * @retval CRYPT_OK  Success
 */
static int do_update(uint32_t algo, hash_state *hash,
				const unsigned char *buf, unsigned long len)
{
	TEE_Result res;

	/* Update Hash */
	res = crypto_hash_update(hash->data, algo, buf, len);

	if (res != TEE_SUCCESS) {
		/* Free the context in case of error */
		crypto_hash_free_ctx(hash->data, algo);
	}

	return conv_TEE_Result_to_CRYPT(res);
}

/**
 * @brief   Finalize the hashing by creating the digest
 *
 * @param[in]  algo    TEE Aglorithm id
 * @param[in]  hash    Hash context
 * @param[out] digest  Digest buffer (size function of the hash algorithm)
 * @param[in]  len     Digest buffer length in bytes
 *
 * @retval CRYPT_OK  Success
 */
static int do_final(uint32_t algo, hash_state *hash,
					unsigned char *digest, size_t len)
{
	TEE_Result res;

	/* Finalize to get the digest */
	res = crypto_hash_final(hash->data, algo, digest, len);

	/* Free the context in case of error */
	crypto_hash_free_ctx(hash->data, algo);

	return conv_TEE_Result_to_CRYPT(res);
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
#define WRAP_HASH_INIT(name, algo)          \
static int do_init_##name(hash_state *hash) \
{                                           \
	return do_init(algo, hash);         \
}

/**
 * @brief   Create local static function do_update associated to the
 *          algorithm \a algo
 */
#define WRAP_HASH_UPDATE(name, algo)                         \
static int do_update_##name(hash_state *hash,                \
		const unsigned char *buf, unsigned long len) \
{                                                            \
	return do_update(algo, hash, buf, len);              \
}

/**
 * @brief   Create local static function do_final associated to the
 *          algorithm \a algo
 */
#define WRAP_HASH_FINAL(name, algo, len)                         \
static int do_final_##name(hash_state *hash, unsigned char *buf) \
{                                                                \
	return do_final(algo, hash, buf, len);                   \
}

#define WRAP_HASH_INIT_GEN(name)	\
				WRAP_HASH_INIT(name, TEE_ALG_##name)
#define WRAP_HASH_UPDATE_GEN(name)	\
				WRAP_HASH_UPDATE(name, TEE_ALG_##name)
#define WRAP_HASH_FINAL_GEN(name)	\
				WRAP_HASH_FINAL(name, TEE_ALG_##name, \
					TEE_##name##_HASH_SIZE)

/*
 * Registration of the HASH Wrapper to use the HW HASH module
 */
#ifdef CFG_CRYPTO_HASH_HW_MD5
/**
 * @brief   MD5 algorithm
 */
WRAP_HASH_INIT_GEN(MD5)   // Function declaration
WRAP_HASH_UPDATE_GEN(MD5) // Function declaration
WRAP_HASH_FINAL_GEN(MD5)  // Function declaration

static const struct ltc_hash_descriptor md5_desc = {
	"md5",
	3,
	TEE_MD5_HASH_SIZE,
	TEE_MD5_HASH_SIZE * 4,

	/* OID */
	{1, 2, 840, 113549, 2, 5,  },
	6,

	&do_init_MD5,
	&do_update_MD5,
	&do_final_MD5,
	&do_test,
	NULL
};
#endif

#ifdef CFG_CRYPTO_HASH_HW_SHA1
/**
 * @brief   SHA1 algorithm
 */
WRAP_HASH_INIT_GEN(SHA1)   // Function declaration
WRAP_HASH_UPDATE_GEN(SHA1) // Function declaration
WRAP_HASH_FINAL_GEN(SHA1)  // Function declaration

static const struct ltc_hash_descriptor sha1_desc = {
	"sha1",
	2,
	TEE_SHA1_HASH_SIZE,
	TEE_MAX_HASH_SIZE,

	/* OID */
	{1, 3, 14, 3, 2, 26,  },
	6,

	&do_init_SHA1,
	&do_update_SHA1,
	&do_final_SHA1,
	&do_test,
	NULL
};
#endif

#ifdef CFG_CRYPTO_HASH_HW_SHA224
/**
 * @brief   SHA224 algorithm
 */
WRAP_HASH_INIT_GEN(SHA224)   // Function declaration
WRAP_HASH_UPDATE_GEN(SHA224) // Function declaration
WRAP_HASH_FINAL_GEN(SHA224)  // Function declaration

static const struct ltc_hash_descriptor sha224_desc = {
	"sha224",
	10,
	TEE_SHA224_HASH_SIZE,
	TEE_MAX_HASH_SIZE,

	/* OID */
	{2, 16, 840, 1, 101, 3, 4, 2, 4, },
	9,

	&do_init_SHA224,
	&do_update_SHA224,
	&do_final_SHA224,
	&do_test,
	NULL
};
#endif

#ifdef CFG_CRYPTO_HASH_HW_SHA256
/**
 * @brief   SHA256 algorithm
 */
WRAP_HASH_INIT_GEN(SHA256)   // Function declaration
WRAP_HASH_UPDATE_GEN(SHA256) // Function declaration
WRAP_HASH_FINAL_GEN(SHA256)  // Function declaration

static const struct ltc_hash_descriptor sha256_desc = {
	"sha256",
	0,
	TEE_SHA256_HASH_SIZE,
	TEE_MAX_HASH_SIZE,

	/* OID */
	{2, 16, 840, 1, 101, 3, 4, 2, 1, },
	9,

	&do_init_SHA256,
	&do_update_SHA256,
	&do_final_SHA256,
	&do_test,
	NULL
};
#endif

#ifdef CFG_CRYPTO_HASH_HW_SHA384
/**
 * @brief   SHA384 algorithm
 */
WRAP_HASH_INIT_GEN(SHA384)   // Function declaration
WRAP_HASH_UPDATE_GEN(SHA384) // Function declaration
WRAP_HASH_FINAL_GEN(SHA384)  // Function declaration

static const struct ltc_hash_descriptor sha384_desc = {
	"sha384",
	4,
	TEE_SHA384_HASH_SIZE,
	TEE_MAX_HASH_SIZE * 2,

	/* OID */
	{2, 16, 840, 1, 101, 3, 4, 2, 2, },
	9,

	&do_init_SHA384,
	&do_update_SHA384,
	&do_final_SHA384,
	&do_test,
	NULL
};
#endif

#ifdef CFG_CRYPTO_HASH_HW_SHA512
/**
 * @brief   SHA512 algorithm
 */
WRAP_HASH_INIT_GEN(SHA512)   // Function declaration
WRAP_HASH_UPDATE_GEN(SHA512) // Function declaration
WRAP_HASH_FINAL_GEN(SHA512)  // Function declaration

static const struct ltc_hash_descriptor sha512_desc = {
	"sha512",
	5,
	TEE_SHA512_HASH_SIZE,
	TEE_MAX_HASH_SIZE * 2,

	/* OID */
	{2, 16, 840, 1, 101, 3, 4, 2, 3, },
	9,

	&do_init_SHA512,
	&do_update_SHA512,
	&do_final_SHA512,
	&do_test,
	NULL
};
#endif
#endif // CFG_CRYPTO_HASH_HW

/**
 * @brief   Find Hash index into the LibTomCrypt hash registered
 *
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval  >=0 if found
 * @retval  (-1) if not found
 */
int get_ltc_hashindex(enum nxpcrypt_hash_id algo)
{
	int index = (-1);

	switch (algo) {
	case HASH_MD5:
		index = find_hash("md5");
		break;

	case HASH_SHA1:
		index = find_hash("sha1");
		break;

	case HASH_SHA224:
		index = find_hash("sha224");
		break;

	case HASH_SHA256:
		index = find_hash("sha256");
		break;

	case HASH_SHA384:
		index = find_hash("sha384");
		break;

	case HASH_SHA512:
		index = find_hash("sha512");
		break;

	default:
		break;
	}

	return index;
}

/**
 * @brief   Initialize the HASH module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_hash_init(void)
{
	int ret = 0;

	/* Register the Hash descriptor into libTomCrypt Software */
	ret |= register_hash(&md5_desc);
	ret |= register_hash(&sha1_desc);
	ret |= register_hash(&sha224_desc);
	ret |= register_hash(&sha256_desc);
	ret |= register_hash(&sha384_desc);
	ret |= register_hash(&sha512_desc);

	return (ret == (-1)) ? ret : 0;
}

