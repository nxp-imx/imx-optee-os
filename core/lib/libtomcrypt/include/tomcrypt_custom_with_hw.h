/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libtomcrypt_custom_with_hw.h
 *
 * @brief   Define the LibTomCrypt library algorithm to support
 *          in case of use with a library mixing Hardware accelerator
 *          and software algorithm.
 */
#ifndef TOMCRYPT_CUSTOM_WITH_HW
#define TOMCRYPT_CUSTOM_WITH_HW

/*
 * RNG
 */
#ifdef CFG_CRYPTO_RNG_HW
	#define LTC_NO_PRNGS	// Don't enable all SW RNG by default
#endif

/*
 * Ciphers
 */
#define LTC_NO_CIPHERS	// Don't enable AES/DES by default
#define LTC_NO_MODES	// Don't enable Cipher Modes by default

#ifndef CFG_CRYPTO_CIPHER_HW
	/* Don't use the CIPHER by HW hence configure enable SW ciphers */
	#ifdef CFG_CRYPTO_AES
		#define LTC_RIJNDAEL
	#endif
	#ifdef CFG_CRYPTO_DES
		#define LTC_DES
	#endif

	#ifdef CFG_CRYPTO_ECB
		#define LTC_ECB_MODE
	#endif
	#ifdef CFG_CRYPTO_CBC
		#define LTC_CBC_MODE
	#endif
	#if defined(CFG_CRYPTO_CBC) || defined(CFG_CRYPTO_CBC_MAC)
		#define LTC_CTR_MODE
	#endif
	#ifdef CFG_CRYPTO_XTS
		#define LTC_XTS_MODE
	#endif
#else
	#ifdef CFG_CRYPTO_WITH_CE
	/* Define the following constant used in the files
	 * implemented in ARM Crypto Acceleration
	 */
	#define CTR_COUNTER_LITTLE_ENDIAN    0x0000
	#endif
#endif

/*
 * Hash
 */
#define LTC_NO_HASHES	// Don't enable all Hashes by default

#if defined(CFG_CRYPTO_MD5) && !defined(CFG_CRYPTO_HASH_HW_MD5)
	#define LTC_MD5
#endif
#if defined(CFG_CRYPTO_SHA1) && !defined(CFG_CRYPTO_HASH_HW_SHA1)
	#define LTC_SHA1
#endif
#if defined(CFG_CRYPTO_SHA1_ARM32_CE) && !defined(CFG_CRYPTO_HASH_HW_SHA1)
	#define LTC_SHA1_ARM32_CE
#endif
#if defined(CFG_CRYPTO_SHA1_ARM64_CE) && !defined(CFG_CRYPTO_HASH_HW_SHA1)
	#define LTC_SHA1_ARM64_CE
#endif
#if defined(CFG_CRYPTO_SHA224) && !defined(CFG_CRYPTO_HASH_HW_SHA224)
	#define LTC_SHA224
#endif
#if defined(CFG_CRYPTO_SHA256) && !defined(CFG_CRYPTO_HASH_HW_SHA256)
	#define LTC_SHA256
#endif
#if defined(CFG_CRYPTO_SHA256_ARM32_CE) && !defined(CFG_CRYPTO_HASH_HW_SHA256)
	#define LTC_SHA256_ARM32_CE
#endif
#if defined(CFG_CRYPTO_SHA256_ARM64_CE) && !defined(CFG_CRYPTO_HASH_HW_SHA256)
	#define LTC_SHA256_ARM64_CE
#endif
#if defined(CFG_CRYPTO_SHA384) && !defined(CFG_CRYPTO_HASH_HW_SHA384)
	#define LTC_SHA384
#endif
#if defined(CFG_CRYPTO_SHA512) && !defined(CFG_CRYPTO_HASH_HW_SHA512)
	#define LTC_SHA512
#endif

/*
 * MACS
 */
#define LTC_NO_MACS	// Don't enable all Macs by default

#if !defined(CFG_CRYPTO_HMAC_FULL_HW) && defined(CFG_CRYPTO_HMAC)
   #define LTC_HMAC
#endif

#if !defined(CFG_CRYPTO_CMAC_HW) && defined(CFG_CRYPTO_CMAC)
   #define LTC_OMAC
#endif

#if !defined(CFG_CRYPTO_CCM_HW) && defined(CFG_CRYPTO_CCM)
   #define LTC_CCM_MODE
#endif

#if !defined(CFG_CRYPTO_GCM_HW) && defined(CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB)
	#define LTC_GCM_MODE
#endif

/*
 * PKCS
 */
#define LTC_NO_PKCS	// Don't enable all PKCS #1 by default
#define LTC_NO_PK	// Don't enable all Public Keys by default

#ifndef CFG_CRYPTO_PKCS_HW
	#if defined(CFG_CRYPTO_RSA) || defined(CFG_CRYPTO_DSA) || \
		defined(CFG_CRYPTO_ECC)
	   #define LTC_DER
	#endif
#endif

#if !defined(CFG_CRYPTO_RSA_HW) && defined(CFG_CRYPTO_RSA)
   #define LTC_MRSA
#endif
#if !defined(CFG_CRYPTO_DSA_HW) && defined(CFG_CRYPTO_DSA)
   #define LTC_MDSA
#endif
#if !defined(CFG_CRYPTO_DH_HW) && defined(CFG_CRYPTO_DH)
   #define LTC_MDH
#endif

#if !defined(CFG_CRYPTO_ECC_HW) && defined(CFG_CRYPTO_ECC)
   #define LTC_MECC

   /* use Shamir's trick for point mul (speeds up signature verification) */
   #define LTC_ECC_SHAMIR

   #if defined(TFM_LTC_DESC) && defined(LTC_MECC)
   #define LTC_MECC_ACCEL
   #endif

   /* do we want fixed point ECC */
   /* #define LTC_MECC_FP */

   /* Timing Resistant */
   #define LTC_ECC_TIMING_RESISTANT

   #define LTC_ECC192
   #define LTC_ECC224
   #define LTC_ECC256
   #define LTC_ECC384
   #define LTC_ECC521

   /* ECC 521 bits is the max supported key size */
   #define LTC_MAX_ECC 521
#endif

#define LTC_RIJNDAEL

#endif // TOMCRYPT_CUSTOM_WITH_HW
