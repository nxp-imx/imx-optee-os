// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rng.c
 *
 * @brief   Implementation of the PRNG pseudo-driver compatible with the
 *          NXP cryptographic library and using the TomCrypt software
 *          driver
 */
/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>

/* Library NXP includes */
#include <libnxpcrypt.h>

/* Local includes */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/*
 * Definition of a PRNG wrapper used into the LibTomCrypt
 * to access the HW RNG module.
 */
/**
 * @brief   Start the RNG module. Not used
 *
 * @param[out] prng  PRNG state to initialized
 *
 * @retval CRYPT_OK  Success
 */
static int do_start(prng_state *prng __unused)
{
	return CRYPT_OK;
}

/**
 * @brief   Add entropy to RNG module. Nothing done.
 *
 * @param[in]  inbuf  Entropy to add
 * @param[in]  len    Size of the entropy buffer
 * @param[out] prng   PRNG state
 *
 * @retval CRYPT_OK     Success
 * @retval CRYPT_ERROR  Generic Error
 */
static int do_add_entropy(const unsigned char *inbuf __unused, unsigned long len __unused,
						prng_state *prng __unused)
{
	/* No entropy is required */
	return CRYPT_OK;
}

/**
 * @brief   Ensure RNG module is ready to read. Nothing done.
 *
 * @param[out] prng  PRNG state to initialized
 *
 * @retval CRYPT_OK  Success
 */
static int do_ready(prng_state *prng __unused)
{
	return CRYPT_OK;
}

/**
 * @brief   Read random data of \a len bytes.
 *
 * @param[out] out   Output buffer
 * @param[in]  len   Length in bytes to read
 * @param[in]  prng  PRNG state
 *
 * @retval CRYPT_OK  Success
 */
static unsigned long do_read(unsigned char *out, unsigned long len,
					prng_state *prng __unused)
{
	if (crypto_rng_read(out, len) == TEE_SUCCESS)
		return len;
	else
		return 0;
}

/**
 * @brief   Terminate the RNG module. Nothing done.
 *
 * @param[out]  prng  PRNG state to terminate
 *
 * @retval CRYPT_OK  Success
 */
static int do_done(prng_state *prng __unused)
{
	return CRYPT_OK;
}

/**
 * @brief   Export the PRNG state of \a len bytes.
 *
 * @param[out]    out   Destination of the state
 * @param[in/out] len   Maximum size of \a out and return size of the state
 * @param[in]     prng  PRNG state to export
 *
 * @retval CRYPT_OK  Success
 */
static int do_export(unsigned char *out __unused,
					unsigned long *len __unused,
					prng_state *prng __unused)
{
	return CRYPT_OK;
}

/**
 * @brief   Import the PRNG state of \a len bytes.
 *
 * @param[in] in    State to import
 * @param[in] len   Length of the input data
 * @param[in] prng  PRNG state to import
 *
 * @retval CRYPT_OK  Success
 */
static int do_import(const unsigned char *in  __unused,
					unsigned long len __unused,
					prng_state *prng __unused)
{
	return CRYPT_OK;
}

/**
 * @brief   PRNG self-test.
 *
 * @retval CRYPT_NOP  Self-testing disabled
 */
static int do_test(void)
{
	return CRYPT_NOP;
}

/**
 * @brief   Registration of the PRNG Wrapper to use the HW RNG module
 */
static const struct ltc_prng_descriptor prng_hw_wrapper_desc = {
#ifdef CFG_CRYPTO_RNG_HW
	.name        = "hw_rng",
#else
	.name        = "sw_rng",
#endif
	.export_size = 0,
	.start       = &do_start,
	.add_entropy = &do_add_entropy,
	.ready       = &do_ready,
	.read        = &do_read,
	.done        = &do_done,
	.pexport     = &do_export,
	.pimport     = &do_import,
	.test        = &do_test,
};

/**
 * @brief   Local PRNG driver variable
 */
static struct ltc_prng prng;

/**
 * @brief   Return the reference to the PRNG
 *
 * @retval  reference to PRNG
 */
struct ltc_prng *get_ltc_prng(void)
{
	return &prng;
}

/**
 * @brief   Initialize the RNG module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_rng_init(void)
{
	int ret = (-1);

	register_prng(&prng_hw_wrapper_desc);
	/* Get the PRNG index */
	prng.index = find_prng(prng_hw_wrapper_desc.name);

	LIB_TRACE("LTC Prng index = %d", prng.index);

	if (prng.index != (-1))
		ret = 0;

	return ret;
}

