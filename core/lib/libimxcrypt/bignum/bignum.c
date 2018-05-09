// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    bignum.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Big number crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <utee_defines.h>
#include <kernel/panic.h>
#include <trace.h>

#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif


struct bignum *crypto_bignum_allocate(size_t size_bits __unused)
{
	LIB_TRACE("bad");
	return NULL;
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from __unused,
				size_t fromsize __unused,
				struct bignum *to __unused)
{
	//return TEE_ERROR_NOT_IMPLEMENTED;
	LIB_TRACE("Bypass crypto_bignum_bin2bn");
	return TEE_SUCCESS;
}

size_t crypto_bignum_num_bytes(struct bignum *a __unused)
{
	LIB_TRACE("bad");
	return 0;
}

size_t crypto_bignum_num_bits(struct bignum *a __unused)
{
	LIB_TRACE("bad");
	return 0;
}

/*
 * crypto_bignum_allocate() and crypto_bignum_bin2bn() failing should be
 * enough to guarantee that the functions calling this function aren't
 * called, but just in case add a panic() here to avoid unexpected
 * behavoir.
 */
static void bignum_cant_happen(void)
{
	LIB_TRACE("bad");
	/* Avoid warning about function does not return */
	panic();
}

void crypto_bignum_bn2bin(const struct bignum *from __unused,
			  uint8_t *to __unused)
{
	LIB_TRACE("bad");
	bignum_cant_happen();
}

void crypto_bignum_copy(struct bignum *to __unused,
			const struct bignum *from __unused)
{
	LIB_TRACE("bad");
	bignum_cant_happen();
}

void crypto_bignum_free(struct bignum *a)
{
	LIB_TRACE("bad");
	if (a)
		panic();
}

void crypto_bignum_clear(struct bignum *a __unused)
{
	LIB_TRACE("bad");
	bignum_cant_happen();
}

/* return -1 if a<b, 0 if a==b, +1 if a>b */
int32_t crypto_bignum_compare(struct bignum *a __unused,
			      struct bignum *b __unused)
{
	LIB_TRACE("bad");
	bignum_cant_happen();
	return -1;
}
