/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __PTA_IMX_TRUSTED_ARM_CE_H__
#define __PTA_IMX_TRUSTED_ARM_CE_H__

#include <tee_api_types.h>

#define PTA_TRUSTED_ARM_CE_UUID                                        \
	{                                                              \
		0x560c5231, 0x71bc, 0x476d,                            \
		{                                                      \
			0x8c, 0x2e, 0x4b, 0xa1, 0x07, 0x99, 0x1e, 0x72 \
		}                                                      \
	}

/*
 * Set AES CBC symmetric key
 *
 * [in]     param[0].memref        Salt used to derive a key
 */
#define PTA_SET_CBC_KEY 0

/*
 * Set AES XTS symmetric keys
 *
 * [in]     param[0].memref        Salt used to derive keys
 */
#define PTA_SET_XTS_KEY 1

/*
 * Remove secrets keys according to key id
 *
 * [in]     param[0].value.a       Key id 1
 * [in]     param[0].value.b       Key id 2
 */
#define PTA_REMOVE_KEY  2

/*
 * Do AES CBC Encryption
 *
 * [in]     param[0].memref        Parameters buffer
 * [in]     param[1].value.a       Key id
 */
#define PTA_ENCRYPT_CBC 3

/*
 * Do AES CBC Decryption
 *
 * [in]     param[0].memref        Parameters buffer
 * [in]     param[1].value.a       Key id
 */
#define PTA_DECRYPT_CBC 4

/*
 * Do AES XTS Encryption
 *
 * [in]     param[0].memref        Parameters buffer
 * [in]     param[1].value.a       Key id 1
 * [in]     param[1].value.b       Key id 2
 */
#define PTA_ENCRYPT_XTS 5

/*
 * Do AES XTS Decryption
 *
 * [in]     param[0].memref        Parameters buffer
 * [in]     param[1].value.a       Key id 1
 * [in]     param[1].value.b       Key id 2
 */
#define PTA_DECRYPT_XTS 6

/*
 * Allocate a static shared memory buffer
 *
 * [in]     param[0].value.a       Buffer size
 * [out]    param[1].value.a       MSB Buffer physical address
 * [out]    param[1].value.b       LSB Buffer physical address
 */
#define PTA_SHM_ALLOCATE 7

/*
 * Free a static shared memory buffer
 *
 * [in]    param[0].value.a       MSB Buffer physical address
 * [in]    param[0].value.b       LSB Buffer physical address
 */
#define PTA_SHM_FREE	 8

/*
 * Do AES CBC Cipher operation
 *
 * [in]     key_id   Key id
 * [in]     iv       Initial vector physical address
 * [in]     srcdata  Input buffer physical address
 * [in]     srclen   Input buffer size
 * [out]    dstdata  Output buffer physical address
 * [out]    dstlen   Output buffer size
 * [in]     encrypt  True for encryption, false otherwise
 */
TEE_Result cipher_cbc(uint32_t key_id, paddr_t iv, paddr_t srcdata,
		      size_t srclen, paddr_t dstdata, size_t dstlen,
		      bool encrypt);

/*
 * Do AES XTS Cipher operation
 *
 * [in]     key_id_1 First key id
 * [in]     key_id_2 Second key id
 * [in]     iv       Initial vector physical address
 * [in]     srcdata  Input buffer physical address
 * [in]     srclen   Input buffer size
 * [out]    dstdata  Output buffer physical address
 * [out]    dstlen   Output buffer size
 * [in]     encrypt  True for encryption, false otherwise
 */
TEE_Result cipher_xts(uint32_t key_id_1, uint32_t key_id_2, paddr_t iv,
		      paddr_t srcdata, size_t srclen, paddr_t dstdata,
		      size_t dstlen, bool encrypt);

void ce_aes_cbc_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, uint8_t iv[]);
void ce_aes_cbc_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk[],
			int rounds, int blocks, uint8_t iv[]);
void ce_aes_xts_encrypt(uint8_t out[], uint8_t const in[], uint8_t const rk1[],
			int rounds, int blocks, uint8_t const rk2[],
			uint8_t iv[]);
void ce_aes_xts_decrypt(uint8_t out[], uint8_t const in[], uint8_t const rk1[],
			int rounds, int blocks, uint8_t const rk2[],
			uint8_t iv[]);

#endif /* __PTA_IMX_TRUSTED_ARM_CE_H__ */
