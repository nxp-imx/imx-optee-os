// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <assert.h>
#include <crypto/crypto_accel.h>
#include <drivers/ele_extension.h>
#include <kernel/huk_subkey.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_mode_ctx.h>
#if defined(CFG_WITH_VFP)
#include <kernel/vfp.h>
#endif
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/vm.h>
#include <pta_imx_trusted_arm_ce.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>

#ifndef CFG_CORE_RESERVED_SHM
#error "CFG_CORE_RESERVED_SHM is required"
#endif
#ifndef CFG_CORE_DYN_SHM
#error "CFG_CORE_DYN_SHM is required"
#endif

#define TRUSTED_ARM_CE_PTA_NAME "trusted_arm_ce.pta"

#define AES_KEYSIZE_128 16U
#define AES_KEYSIZE_256 32U

/*
 * Maximum expanded key size in words is equal to 15 * 16 bytes
 * (maximum number of rounds * size of an aes block)
 * Please refer to crypto_accel_aes_expand_keys.
 */
#define EXPANDED_KEY_SIZE 60

#define SHM_CACHE_ATTRS                                                    \
	((uint32_t)(core_mmu_is_shm_cached() ? TEE_MATTR_MEM_TYPE_CACHED : \
					       TEE_MATTR_MEM_TYPE_DEV))

#if defined(CFG_MX93)
#define OCRAM_START 0x20498000
#define OCRAM_END 0x2049A000
#else
#error "Platform not supported"
#endif

static_assert(OCRAM_END > OCRAM_START);

#define OCRAM_SIZE (OCRAM_END - OCRAM_START)

/* Maximum number of keys in memory */
#define MAX_NUMBER_KEYS (OCRAM_SIZE / sizeof(struct symmetric_key))

/*
 * This structure size must be aligned on 64 bytes,
 * cause imx_ele_derive_key need cache aligned key buffer.
 */
struct symmetric_key {
	uint8_t key_buffer[TEE_AES_BLOCK_SIZE];
	uint32_t enc_key[EXPANDED_KEY_SIZE];
	uint32_t dec_key[EXPANDED_KEY_SIZE];
	size_t key_size;
	uint32_t key_id;
	uint32_t round_count;
	bool allocated;
} __aligned(64);

/* Physical Secure OCRAM pool */
static tee_mm_pool_t tee_mm_sec_ocram;
static tee_mm_pool_t tee_mm_nsec_shm;
static void *sec_ocram_base;

static struct symmetric_key *key_storage;
static struct mutex key_storage_mutex = MUTEX_INITIALIZER;

/*
 * Get symmetric key with given key identifier
 *
 * [in]	key_id	Symmetric key identifier
 *
 * return a symmetric_key structure pointer matching key_id
 * or NULL if not found
 */
static struct symmetric_key *get_client_key(uint32_t key_id)
{
	if (key_storage) {
		unsigned int key_idx = 0;

		for (key_idx = 0; key_idx < MAX_NUMBER_KEYS; key_idx++) {
			struct symmetric_key *entry = &key_storage[key_idx];

			if (entry->key_id == key_id)
				return entry;
		}
	}

	return NULL;
}

/*
 * Get symmetric key with given key identifier or add it if not found
 *
 * [in]	key_id	Symmetric key identifier
 *
 * return a symmetric_key structure pointer
 */
static struct symmetric_key *add_client_key(uint32_t key_id)
{
	struct symmetric_key *entry = NULL;

	mutex_lock(&key_storage_mutex);

	entry = get_client_key(key_id);
	if (!entry && key_storage) {
		unsigned int key_idx = 0;

		for (key_idx = 0; key_idx < MAX_NUMBER_KEYS; key_idx++) {
			if (!key_storage[key_idx].allocated) {
				entry = &key_storage[key_idx];
				entry->allocated = true;
				entry->key_id = key_id;
				break;
			}
		}
	}
	mutex_unlock(&key_storage_mutex);

	return entry;
}

/*
 * Remove a secret key according to key id
 *
 * [in]	key_id	Symmetric key identifier
 */
static TEE_Result remove_client_key(uint32_t key_id)
{
	struct symmetric_key *entry = NULL;

	mutex_lock(&key_storage_mutex);

	entry = get_client_key(key_id);
	if (entry)
		memzero_explicit(entry, sizeof(struct symmetric_key));

	mutex_unlock(&key_storage_mutex);

	return TEE_SUCCESS;
}

/*
 * Get static shared memory buffer virtual address from physical address
 *
 * [in] pa	buffer physical address
 * [in] size	buffer size
 *
 * return buffer virtual address or NULL if no match found
 */
static inline void *nsec_shm_phys_to_virt(paddr_t pa, size_t size)
{
	return phys_to_virt(pa, MEM_AREA_NSEC_SHM, size);
}

/*
 * Deserialize physical memory address and size
 *
 * [in]     buffer	serialized data buffer
 * [in/out] size	serialized data size
 * [out]    pa		physical address
 * [out]    sz		size
 *
 * return updated serialized data buffer address
 */
static uint8_t *deserialize_memref(uint8_t *buffer, size_t *size, paddr_t *pa,
				   size_t *sz)
{
	if (!buffer)
		goto out;

	if (*size < sizeof(paddr_t))
		goto out;
	memcpy(pa, buffer, sizeof(paddr_t));
	buffer += sizeof(paddr_t);
	size -= sizeof(paddr_t);

	if (*size < sizeof(size_t))
		goto out;
	memcpy(sz, buffer, sizeof(size_t));
	buffer += sizeof(size_t);
	size -= sizeof(size_t);
out:
	return buffer;
}

/*
 * Parse TEE parameters
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 * [out]   key_id_1	AES key id 1
 * [out]   key_id_2	AES key id 2 [optional]
 * [out]   iv		iv physical address
 * [out]   ivlen	iv size
 * [out]   srcdata	source physical address
 * [out]   srclen	source size
 * [out]   dstdata	destination physical address
 * [out]   dstlen	destination size
 */
static TEE_Result parse_params(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS],
			       uint32_t *key_id_1, uint32_t *key_id_2,
			       paddr_t *iv, size_t *ivlen, paddr_t *srcdata,
			       size_t *srclen, paddr_t *dstdata, size_t *dstlen)
{
	uint8_t *buffer = NULL;
	size_t buffer_size = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	buffer = params[0].memref.buffer;
	buffer_size = params[0].memref.size;

	buffer = deserialize_memref(buffer, &buffer_size, srcdata, srclen);
	buffer = deserialize_memref(buffer, &buffer_size, dstdata, dstlen);
	buffer = deserialize_memref(buffer, &buffer_size, iv, ivlen);

	*key_id_1 = params[1].value.a;
	if (key_id_2)
		*key_id_2 = params[1].value.b;

	return TEE_SUCCESS;
}

TEE_Result cipher_cbc(uint32_t key_id, paddr_t iv, paddr_t srcdata,
		      size_t srclen, paddr_t dstdata, size_t dstlen,
		      bool encrypt)
{
	struct symmetric_key *key = NULL;
	uint8_t *nonce = NULL;
	uint8_t *src = NULL;
	uint8_t *dst = NULL;

	if (srclen % TEE_AES_BLOCK_SIZE || dstlen % TEE_AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	nonce = nsec_shm_phys_to_virt(iv, TEE_AES_BLOCK_SIZE);
	src = nsec_shm_phys_to_virt(srcdata, srclen);
	dst = nsec_shm_phys_to_virt(dstdata, dstlen);
	if (!nonce || !src || !dst)
		return TEE_ERROR_BAD_PARAMETERS;

	key = get_client_key(key_id);
	if (!key)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (encrypt) {
		/* encrypt srcdata in destdata */
		if (vfp_is_enabled())
			ce_aes_cbc_encrypt(dst, src, (uint8_t *)key->enc_key,
					   key->round_count,
					   srclen / TEE_AES_BLOCK_SIZE, nonce);
		else
			crypto_accel_aes_cbc_enc(dst, src,
						 (uint8_t *)key->enc_key,
						 key->round_count,
						 srclen / TEE_AES_BLOCK_SIZE,
						 nonce);
	} else {
		/* decrypt srcdata in destdata */
		if (vfp_is_enabled())
			ce_aes_cbc_decrypt(dst, src, (uint8_t *)key->dec_key,
					   key->round_count,
					   srclen / TEE_AES_BLOCK_SIZE, nonce);
		else
			crypto_accel_aes_cbc_dec(dst, src,
						 (uint8_t *)key->dec_key,
						 key->round_count,
						 srclen / TEE_AES_BLOCK_SIZE,
						 nonce);
	}

	return TEE_SUCCESS;
}

/*
 * Do AES CBC Cipher operation
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 * [in]    encrypt	True for encryption, false otherwise
 */
static TEE_Result pta_cipher_cbc(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS], bool encrypt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t iv = 0;
	size_t ivlen = 0;
	paddr_t srcdata = 0;
	paddr_t destdata = 0;
	size_t srclen = 0;
	size_t destlen = 0;
	uint32_t key_id = 0;

	res = parse_params(param_types, params, &key_id, NULL, &iv, &ivlen,
			   &srcdata, &srclen, &destdata, &destlen);
	if (res)
		return res;

	return cipher_cbc(key_id, iv, srcdata, srclen, destdata, destlen,
			  encrypt);
}

TEE_Result cipher_xts(uint32_t key_id_1, uint32_t key_id_2, paddr_t iv,
		      paddr_t srcdata, size_t srclen, paddr_t dstdata,
		      size_t dstlen, bool encrypt)
{
	struct symmetric_key *key1 = NULL;
	struct symmetric_key *key2 = NULL;
	uint8_t *nonce = NULL;
	uint8_t *src = NULL;
	uint8_t *dst = NULL;

	if (srclen % TEE_AES_BLOCK_SIZE || dstlen % TEE_AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	nonce = nsec_shm_phys_to_virt(iv, TEE_AES_BLOCK_SIZE);
	src = nsec_shm_phys_to_virt(srcdata, srclen);
	dst = nsec_shm_phys_to_virt(dstdata, dstlen);

	if (!nonce || !src || !dst)
		return TEE_ERROR_BAD_PARAMETERS;

	key1 = get_client_key(key_id_1);
	if (!key1)
		return TEE_ERROR_ITEM_NOT_FOUND;

	key2 = get_client_key(key_id_2);
	if (!key2)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (encrypt) {
		/* encrypt srcdata in destdata */
		if (vfp_is_enabled())
			ce_aes_xts_encrypt(dst, src, (uint8_t *)key1->enc_key,
					   key1->round_count,
					   srclen / TEE_AES_BLOCK_SIZE,
					   (uint8_t *)key2->enc_key, nonce);
		else
			crypto_accel_aes_xts_enc(dst, src,
						 (uint8_t *)key1->enc_key,
						 key1->round_count,
						 srclen / TEE_AES_BLOCK_SIZE,
						 (uint8_t *)key2->enc_key,
						 nonce);
	} else {
		/* decrypt srcdata in destdata */
		if (vfp_is_enabled())
			ce_aes_xts_decrypt(dst, src, (uint8_t *)key1->dec_key,
					   key1->round_count,
					   srclen / TEE_AES_BLOCK_SIZE,
					   (uint8_t *)key2->enc_key, nonce);
		else
			crypto_accel_aes_xts_dec(dst, src,
						 (uint8_t *)key1->dec_key,
						 key1->round_count,
						 srclen / TEE_AES_BLOCK_SIZE,
						 (uint8_t *)key2->enc_key,
						 nonce);
	}

	return TEE_SUCCESS;
}

/*
 * Do AES XTS Cipher operation
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 * [in]    encrypt	True for encryption, false otherwise
 */
static TEE_Result pta_cipher_xts(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS], bool encrypt)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t iv = 0;
	size_t ivlen = 0;
	paddr_t srcdata = 0;
	paddr_t destdata = 0;
	size_t srclen = 0;
	size_t destlen = 0;
	uint32_t key_id_1 = 0;
	uint32_t key_id_2 = 0;

	res = parse_params(param_types, params, &key_id_1, &key_id_2, &iv,
			   &ivlen, &srcdata, &srclen, &destdata, &destlen);
	if (res)
		return res;

	return cipher_xts(key_id_1, key_id_2, iv, srcdata, srclen, destdata,
			  destlen, encrypt);
}

/*
 * Return true if key size is supported
 *
 * [in]    key_size	key size in bytes
 */
static TEE_Result is_key_size_supported(size_t key_size)
{
	switch (key_size) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_256:
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/*
 * Add or update a secret key
 *
 * [in]    key_id	AES key id
 * [in]    salt		salt used for key generation
 * [in]    length	size of the input salt
 */
static TEE_Result set_key(uint32_t key_id, uint8_t *salt, size_t length)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct symmetric_key *key = NULL;
	void *keybuffer = NULL;
	void *enc_key = NULL;
	void *dec_key = NULL;
	uint32_t *round_count = NULL;

	if (!key_id)
		return TEE_ERROR_BAD_PARAMETERS;

	key = add_client_key(key_id);
	if (!key)
		return TEE_ERROR_OUT_OF_MEMORY;

	keybuffer = key->key_buffer;
	enc_key = key->enc_key;
	dec_key = key->dec_key;
	round_count = &key->round_count;

	res = imx_ele_derive_key(salt, length, keybuffer, length);
	if (res)
		goto out;

	res = crypto_accel_aes_expand_keys(keybuffer, length, enc_key, dec_key,
					   sizeof(key->enc_key), round_count);
	if (res)
		goto out;

	key->key_size = length;

	return TEE_SUCCESS;
out:
	memzero_explicit(key, sizeof(struct symmetric_key));

	return res;
}

/*
 * Add or update a secret key
 *
 * [in]    nCommandID	PTA_SET_XTS_KEY or PTA_SET_CBC_KEY
 * [in]    param_types	command param type
 * [in]    params	command parameters
 */
static TEE_Result pta_set_key(uint32_t nCommandID, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *salt = NULL;
	size_t salt_length = 0;
	uint32_t key_id_1 = 0;
	uint32_t key_id_2 = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	salt = params[0].memref.buffer;
	salt_length = params[0].memref.size;
	key_id_1 = params[1].value.a;
	key_id_2 = params[1].value.b;

	if (!salt || !salt_length)
		return TEE_ERROR_BAD_PARAMETERS;

	if (nCommandID == PTA_SET_XTS_KEY) {
		/* we get two keys salt */
		if (salt_length % 2)
			return TEE_ERROR_BAD_PARAMETERS;

		salt_length = salt_length / 2;
	}

	/* key salt length is key length */
	res = is_key_size_supported(salt_length);
	if (res)
		return res;

	res = set_key(key_id_1, salt, salt_length);
	if (res)
		return res;

	if (nCommandID == PTA_SET_XTS_KEY)
		res = set_key(key_id_2, salt + salt_length, salt_length);

	return res;
}

/*
 * Remove secrets keys according to key id
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 */
static TEE_Result pta_remove_key(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t key_id_1 = 0;
	uint32_t key_id_2 = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_id_1 = params[0].value.a;
	key_id_2 = params[0].value.b;

	res = remove_client_key(key_id_1);
	if (res)
		return res;

	if (key_id_2)
		res = remove_client_key(key_id_2);

	return res;
}

/*
 * Allocate a buffer in ocram heap
 *
 * [out]   va		allocated buffer address
 * [in]    alloc_size	allocation size
 */
static TEE_Result ocram_allocate(vaddr_t *va, size_t alloc_size)
{
	tee_mm_entry_t *mm = NULL;
	size_t size = OCRAM_SIZE;

	if (!alloc_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (alloc_size > size)
		return TEE_ERROR_OUT_OF_MEMORY;

	mm = tee_mm_alloc(&tee_mm_sec_ocram, alloc_size);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	*va = (vaddr_t)phys_to_virt(tee_mm_get_smem(mm), MEM_AREA_RAM_SEC,
				    alloc_size);

	return TEE_SUCCESS;
}

/*
 * Free a buffer in ocram heap
 *
 * [in] va		allocated buffer address
 */
static TEE_Result ocram_free(vaddr_t va)
{
	tee_mm_entry_t *mm = NULL;
	paddr_t pa = 0;

	if (!va)
		return TEE_ERROR_BAD_PARAMETERS;

	pa = virt_to_phys((void *)va);

	mm = tee_mm_find(&tee_mm_sec_ocram, pa);
	if (!mm)
		return TEE_ERROR_ITEM_NOT_FOUND;

	tee_mm_free(mm);

	return TEE_SUCCESS;
}

/*
 * Allocate a static shared memory
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 */
static TEE_Result pta_shm_allocate(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	tee_mm_entry_t *mm = NULL;
	size_t alloc_size = 0;
	paddr_t pa = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	alloc_size = reg_pair_to_64(params[0].value.a, params[0].value.b);
	if (!alloc_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mm = tee_mm_alloc(&tee_mm_nsec_shm, alloc_size);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	pa = tee_mm_get_smem(mm);

	reg_pair_from_64(pa, &params[1].value.a, &params[1].value.b);

	return TEE_SUCCESS;
}

/*
 * Free a static shared memory
 *
 * [in]    param_types	command param type
 * [in]    params	command parameters
 */
static TEE_Result pta_shm_free(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	tee_mm_entry_t *mm = NULL;
	paddr_t pa = 0;

	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	pa = reg_pair_to_64(params[0].value.a, params[0].value.b);
	if (!pa)
		return TEE_ERROR_BAD_PARAMETERS;

	mm = tee_mm_find(&tee_mm_nsec_shm, pa);
	if (!mm)
		return TEE_ERROR_ITEM_NOT_FOUND;

	tee_mm_free(mm);

	return TEE_SUCCESS;
}

/*
 * Called when a pseudo TA instance is created.
 */
static TEE_Result trusted_arm_ce_create(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t ps = OCRAM_START;
	size_t size = OCRAM_SIZE;
	vaddr_t va = 0;

	sec_ocram_base = core_mmu_add_mapping(MEM_AREA_RAM_SEC, ps, size);
	if (!sec_ocram_base)
		return TEE_ERROR_OUT_OF_MEMORY;

	memzero_explicit(sec_ocram_base, size);

	if (!tee_mm_init(&tee_mm_sec_ocram, ps, size, CORE_MMU_USER_CODE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS)) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = ocram_allocate(&va, ROUNDUP(MAX_NUMBER_KEYS *
			     sizeof(struct symmetric_key), SIZE_4K));
	if (res)
		goto out;

	key_storage = (struct symmetric_key *)va;

	/*
	 * Add tee_mm_nsec_shm memory pool on the static shm area.
	 * Doing that we reserve it for the PTA shm allocation,
	 * as the area will not be used by Linux when Dynamic shm is enabled.
	 */
	if (!tee_mm_init(&tee_mm_nsec_shm, default_nsec_shm_paddr,
			 default_nsec_shm_size, CORE_MMU_USER_CODE_SHIFT,
			 TEE_MM_POOL_NO_FLAGS)) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	return TEE_SUCCESS;
out:
	if (key_storage)
		ocram_free((vaddr_t)key_storage);
	tee_mm_final(&tee_mm_sec_ocram);
	core_mmu_remove_mapping(MEM_AREA_RAM_SEC, sec_ocram_base, size);
	return res;
}

/*
 * Called when a pseudo TA instance is destroyed.
 */
static void trusted_arm_ce_destroy(void)
{
	size_t size = ROUNDUP(MAX_NUMBER_KEYS * sizeof(struct symmetric_key),
			      SIZE_4K);

	if (key_storage) {
		memzero_explicit(key_storage, size);

		ocram_free((vaddr_t)key_storage);
	}

	tee_mm_final(&tee_mm_sec_ocram);
	tee_mm_final(&tee_mm_nsec_shm);

	size = OCRAM_SIZE;
	memzero_explicit(sec_ocram_base, size);

	core_mmu_remove_mapping(MEM_AREA_RAM_SEC, sec_ocram_base, size);
}

/*
 * Called when this pseudo TA is invoked.
 *
 * sess_ctx    Session Identifier
 * cmd_id      Command ID
 * param_types Parameter types
 * prms        Buffer or value parameters
 */
static TEE_Result trusted_arm_ce_invoke_command(void *sess_ctx __unused,
						uint32_t cmd_id,
						uint32_t param_types,
						TEE_Param prms[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_SHM_ALLOCATE:
		return pta_shm_allocate(param_types, prms);
	case PTA_SHM_FREE:
		return pta_shm_free(param_types, prms);
	case PTA_SET_XTS_KEY:
	case PTA_SET_CBC_KEY:
		return pta_set_key(cmd_id, param_types, prms);
	case PTA_REMOVE_KEY:
		return pta_remove_key(param_types, prms);
	case PTA_ENCRYPT_CBC:
		return pta_cipher_cbc(param_types, prms, true);
	case PTA_DECRYPT_CBC:
		return pta_cipher_cbc(param_types, prms, false);
	case PTA_ENCRYPT_XTS:
		return pta_cipher_xts(param_types, prms, true);
	case PTA_DECRYPT_XTS:
		return pta_cipher_xts(param_types, prms, false);
	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_TRUSTED_ARM_CE_UUID,
		   .name = TRUSTED_ARM_CE_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .create_entry_point = trusted_arm_ce_create,
		   .destroy_entry_point = trusted_arm_ce_destroy,
		   .invoke_command_entry_point = trusted_arm_ce_invoke_command);
