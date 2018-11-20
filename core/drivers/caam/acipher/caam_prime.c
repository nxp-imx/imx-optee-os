// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    caam_prime.c
 *
 * @brief   CAAM Prime Number manager.\n
 *          Implementation of Prime Number functions
 */
/* Global includes */
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <tee/cache.h>

/* Local includes */
#include "local.h"
#include "caam_jr.h"
#include "ccb_regs.h"

/* Utils includes */
#include "utils_mem.h"

/*
 * Debug Macros
 */
//#define PRIME_DEBUG
#ifdef PRIME_DEBUG
//#define DUMP_DESC
//#define DUMP_BUF
#define PRIME_TRACE		DRV_TRACE
#else
#define PRIME_TRACE(...)
#endif

#ifdef DUMP_DESC
#define PRIME_DUMPDESC(desc)	\
			{PRIME_TRACE("PRIME Descriptor @0x%08"PRIxPTR"", \
					(uintptr_t)desc); \
			DRV_DUMPDESC(desc); }
#else
#define PRIME_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define PRIME_DUMPBUF	DRV_DUMPBUF
#else
#define PRIME_DUMPBUF(...)
#endif


#define PRIME_TRY_FAIL	0x42
#define RETRY_TOO_SMALL	0x2A

#define STATUS_GOOD_Q   0xCA

#define SETUP_PRIME_DESC_ENTRIES	17
#define GEN_PRIME_DESC_ENTRIES		58
#define CHECK_P_Q_DESC_ENTRIES		29

/**
 * @brief   Predefined const value corresponding to the
 *          operation sqrt(2) * (2 ^ ((nlen / 2) - 1))
 *          Used at step 4.4
 */
static const char sqrt_value[] =
	"b504f333f9de6484597d89b3754abe9f1d6f60ba893ba84ced17ac8583339915"
	"4afc83043ab8a2c3a8b1fe6fdc83db390f74a85e439c7b4a780487363dfa2768"
	"d2202e8742af1f4e53059c6011bc337bcab1bc911688458a460abc722f7c4e33"
	"c6d5a8a38bb7e9dccb2a634331f3c84df52f120f836e582eeaa4a0899040ca4a"
	"81394ab6d8fd0efdf4d3a02cebc93e0c4264dabcd528b651b8cf341b6f8236c7"
	"0104dc01fe32352f332a5e9f7bda1ebff6a1be3fca221307dea06241f7aa81c2"
	"c1fcbddea2f7dc3318838a2eaff5f3b2d24f4a763facb882fdfe170fd3b1f780"
	"f9acce41797f2805c246785e929570235fcf8f7bca3ea33b4d7c60a5e633e3e1";

/**
 * @brief   Speedups for prime searching
 *
 * These values are products of small primes.  Information about the product
 * preceeds it.
 *
 * Per Handbook of Applied Cryptography, Menezes et al, 4.4.1, one can compute
 * the percentage of non-primes weeded out by checking for small prime factors
 * in the candidates.  In the table below, "highest prime" is used for B, and
 * "%weeded" is the number of candidates which get through this
 * sieve.  As you can see, even with relatively few primes, there are
 * diminishing returns to using larger numbers of primes.
 *
 * Percentage weeded:  1 - 1.12/ln B
 *
 * These can be used to compute GCD(prime, smallprime) before the Miller
 * Rabin; this will weed out those candidates with 'small' primes before doing
 * the costly modular exponentation inside of Miller-Rabin.  (If the result is
 * not one, then the candidate has as a factor at least one of the small primes
 * in the product).
 *
 * So, where is the sweet spot for the size of the product versus the size of
 * the candidate?  Does it depend upon the size of the PKHA multiplier?  Hunt
 * time for primes takes a long time to actually compute, and what are the
 * stats for percentage of candidates that might be weeded out?  If not many,
 * then there is an extra computation.
 */
static const char * const smallprimes[] = {
	/*     sizes     | #primes | highest prime | %weeded */
	/*  bits / bytes |         |                         */
	/*    64 / 8     |   15    |          53   |    72   */
	"e221f97c30e94e1d",
	/*   128 / 16    |   25    |          101  |    76   */
	"5797d47c51681549d734e4fc4c3eaf7f",
	/*   256 / 32    |   43    |          193  |    79   */
	"dbf05b6f5654b3c0f5243551439586889f155887819aed2ac05b93352be98677",
	/*   384 / 48    |   59    |          281  |    80   */
	"501201cc51a492a544d3900ad4f8b32a203c858406a4457cab0b4f805ab18ac6"
	"eb9572ac6e9394fa522bffb6f44af2f3",
	/*   512 / 64    |   74    |          379  |    81   */
	"106aa9fb7646fa6eb0813c28c5d5f09f077ec3ba238bfb99c1b631a203e81187"
	"233db117cbc384056ef04659a4a11de49f7ecb29bada8f980decece92e30c48f",
	/*   576 / 72    |   81    |          421  |    82   */
	"0185dbeb2b8b11d37633e9dc1eec541565c6ce8431d227ee28f0328a60c90118"
	"ae031cc5a781c824d1f16d25f4f0cccff35e974579072ec8caf1ac8eefd5566f"
	"a15fb94fe34f5d37",
	/*   768 / 96    |  103    |          569  |    82   */
	"25eac89f8d4da338337b49850d2d14892663177b4010af3dd23eeb0b228f3832"
	"ffcee2e5cbd1acc98f47f251873380ae10f0ffdd8e602ffa210f41f669a1570a"
	"93c158c1a9a8227ff81a90c5630e9c44845c755c7df35a7d430c679a11575655",
	/*  1024 / 128   |  130    |          739  |    83   */
	"02c85ff870f24be80f62b1ba6c20bd72b837efdf121206d87db56b7d69fa4c02"
	"1c107c3ca206fe8fa7080ef576effc82f9b10f5750656b7794b16afd70996e91"
	"aef6e0ad15e91b071ac9b24d98b233ad86ee055518e58e56638ef18bac5c74cb"
	"35bbb6e5dae2783dd1c0ce7dec4fc70e5186d411df36368f061aa36011f30179",
	/*  1088 / 184   |  136    |          787  |    83   */
	"16af5c18a2bef8eff2278332182d0fbf0038cc205148b83d06e3d7d932828b18"
	"e11e094028c7eaeda3395017e07d8ae9b594060451d05f93084cb481663c94c6"
	"ff980ddeccdb42ad37097f41a7837fc95afe3f18ad76f23483ae942e0f0c0bc6"
	"e40016123189872be58f6dfc239ca28fb0cfbf964c8f27ce05d6c77a01f9d332"
	"36c9d442ad69ed33",
	/*  1536 / 192   |  182    |         1093  |    84   */
	"021bf9497091b8c368cc7c8e00c1990c6027481b79215ac8a7517749a2151377"
	"9a993d2958fcb49a7368029268527994c6cc1928add4129596765f4cc3141a04"
	"4eb1d6157888166757d8618781813062032267987df0d4719cd38f1b7085fca5"
	"334be3a6003a3ce7e19aba553e80cc5ae4060eff6e1806661da5eeb7d142d3b2"
	"e40739f1443dee3a198637f03c062845eaff3ff27ea38d9344d8a90222472df0"
	"7dfb5c9c8ada77cd0d5b94eff021e02e307d08010312d57cb5d975764697842d",
	/*  2048 / 256   |  232    |         1471  |    85   */
	"2465a7bd85011e1c9e0527929fff268c82ef7efa416863baa5acdb0971dba0cc"
	"ac3ee4999345029f2cf810b99e406aac5fce5dd69d1c717daea5d18ab913f456"
	"505679bc91c57d46d9888857862b36e2ede2e473c1f0ab359da25271affe15ff"
	"240e299d0b04f4cd0e4d7c0e47b1a7ba007de89aae848fd5bdcd7f9815564eb0"
	"60ae14f19cb50c291f0bbd8ed1c4c7f8fc5fba51662001939b532d92dac844a8"
	"431d400c832d039f5f900b278a75219c2986140c79045d7759540854c31504dc"
	"56f1df5eebe7bee447658b917bf696d6927f2e2428fbeb340e515cb9835d6387"
	"1be8bbe09cf13445799f2e67788151571a93b4c1eee55d1b9072e0b2f5c4607f",
	/*  3072 / 384   | 326     |          2179  |    85   */
	"004dc20e27315123fdabcd18ca812ee0ee44492387389ed6c91697958965edc5"
	"3d8913a8e6ec7f836a8bd6037e57ed0c6930ef26490dc35d05d098a466adf817"
	"9f829969d139558f16e98b3f76fc9062c15725ce0988faedca966a6b925f9b9c"
	"670343ea7e842065bd26f2bf29904fa7f49f334928963373ba089596513daca7"
	"3928cf305adf8c246e1d99a242d9235623c49af2914506c911215e1e49af8480"
	"3ed9a2ca0551721fe6319bf238c08aae6fd5015403d9e55509ee31c96012f908"
	"35185f31cbd2e489833c1d5462fa80535904867b2c945e9a0c2f7aa36e0ac0eb"
	"9bb4c11bf580cf0d6d2a49ed1a2d74cae0f4c3adff61d648ca6a120858f4abb3"
	"b31207cf9b7c2fda74f7722b149917875aac9d6153c97113fcd374af93dd3fa2"
	"1a7de51f1a70c631ba6c92261e89541aa47141f44e075a1c522ae58160dac870"
	"dfbd8606e4eca0892ae51c8734f5b7712bcd3de3325ec25f07d4ef943394d5e7"
	"b3841005a3bd1a3e4d27061d54d2445824f85117d0f6971284a8c97a4250b99b",
	/*  4096 / 512   | 417     |          2887  |    86   */
	"096207fccb19d6758e374bee6c3709af0a54a982bf9014e450b7481813b7305b"
	"4c25f0e2ea6e2b56f91e5992142d216eaeb2ece005fa0d18efeb78efc341f31f"
	"783ee44ac5ef5dfe355791282106156c64d167a5421cfec33cbbd388380be854"
	"149fb65c08e79cd04ec48b45628ee67f5c6fb01818fa1ff732240c0bb1c7fec1"
	"4c48234c6fc3e075764f63c0268361831d8960f24b237e96c2caba4c1a2123ff"
	"33a49bca3949e8abadde06dac5703d16db7677df2b0ce2c78485ebd5e69bd80a"
	"1848a9fe289ca2ba664a687b3f0540156e67ae6769c09e11ce567357f5a576a4"
	"8eedd96335e62877c73a65408b71484ed0f11d20d51e8e5467a1e4c09bf729ba"
	"169fcfdba8b55c4c5b682faa28719b9f49bf362d9f03ee6bde7901e940e249b4"
	"1c93b9ab054abcab109af12aa6535ed8f623abfd312aaa084a748f865383bce3"
	"15dc0d45cb89508deca93bda22f0e77a4feaa2a790e00e5ada9bbb9ae7d5fb63"
	"54a252da7dc26e6ac2d7a642eabf4812e64ae195bf29cc9ee02584b774dcb112"
	"9157bf52438fb7b7cd6a7824a7418bcc6583058ec2f06928e442623798b503f6"
	"751dcee2c01f39acb0fb478f6e8b16a30fe8219b8e6704c726b603e10009f677"
	"76465141570d4b4c2a30db84026f934b81f0d5e985c975d6a9075a41d417c6d9"
	"93cb4973cbe512a67db31f6aec8cc3e9e5ebdc1eb7b474545152a156d5ac587d"
};

/**
 * @brief   Search the small prime closed to the given input bytes
 *          size \a size
 *
 * @param[in]  size   Size in bytes
 * @param[out] prime  Output predefined small prime
 */
static void search_smallprime(size_t size, struct caambuf *prime)
{
	size_t nbElem = ARRAY_SIZE(smallprimes);
	size_t idx;
	size_t psize;

	for (idx = 0; idx < nbElem; idx++) {
		psize = strlen(smallprimes[idx]);

		if (psize == size) {
			/* Found a predefined prime */
			PRIME_TRACE("Found prime idx %d", idx);
			prime->data   = (uint8_t *)&smallprimes[idx];
			prime->length = psize;
			prime->paddr  = virt_to_phys(prime->data);
			break;
		}
	}
}

/**
 * @brief   Build the descriptor used to prepare the CAAM HW
 *          to generate a prime of length \a p_length
 *
 * @param[out] desc        Reference to the descriptor buffer to build
 * @param[in]  data        Prime generation data
 * @param[in]  small_prime Pre-generated small prime value
 * @param[in]  desc_prime  Physical address of the prime generator descriptor
 *
 * @retval  CAAM_NO_ERROR   No Error
 * @retval  CAAM_FAILURE    General failure
 */
static enum CAAM_Status do_desc_setup(descPointer_t desc,
		struct caam_prime_data *data,
		const struct caambuf *small_prime, const paddr_t desc_prime)
{
	uint8_t desclen = 1;

	/*
	 * Build the descriptor setuping the generate prime parameters
	 */
	/*
	 * Referring to FIPS.186-4, B.3.3 (step 4.7)
	 * Maximum tries = 5 * (nlen / 2)
	 * Where nlen is the RSA security length in bit
	 */
	desc[desclen++] = MATH(ADD, IMM_DATA, ZERO, SOL, 4);
	desc[desclen++] = 5 * (data->key_size / 2);

	/*
	 * Referring to FIPS.186-4, Table C.2
	 * Get the number Miller-Rabin test interation function
	 * of the prime number size
	 */
	desc[desclen++] = MATH(ADD, IMM_DATA, ZERO, SIL, 4);
	if (data->p->length > (1536 / 8))
		desc[desclen++] = 4;
	else
		desc[desclen++] = 5;

	/*
	 * Preload PKHA A2 with the sqrt_value array (step 4.4)
	 * Do it once, not at each loop
	 */
	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_A2, NOACTION, data->p->length);
	desc[desclen++] = virt_to_phys((void *)sqrt_value);

	if ((data->era >= 8)  && (small_prime->paddr)) {
		/*
		 * Preload PKHA B2 with small prime predefined
		 * (preload only prime size requested)
		 *
		 * Before Era 8, the PRIME TEST function overwrites PKHA B2
		 * hence PKHA B2 must be reloaded if new prime tentative after
		 * PRIME TEST on Era < 8
		 */
		desc[desclen++] = FIFO_LD(CLASS_1, PKHA_B2, NOACTION,
				small_prime->length);
		desc[desclen++] = small_prime->paddr;
	}

	/* Set the High order bit used to turn on MSB in prime candidate */
	desc[desclen++] = MATHI_OP1(SHIFT_L, ONE, 0x3F, REG2, 8);

	/* Load PKHA N Size with the prime size */
	desc[desclen++] = LD_IMM(CLASS_1, REG_PKHA_N_SIZE, 4);
	desc[desclen++] = data->p->length;

	/*
	 * Set the number of maximum tries because of generated value
	 * is too small. This value is used to not lock the system
	 * in prime number generation
	 */
	desc[desclen++] = MATH(ADD, ZERO, IMM_DATA, DPOVRD, 4);
	desc[desclen++] = 500000;

	/* Jump to the next descriptor desc */
	desc[desclen++] = JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
						JMP_COND(NONE));
	desc[desclen++] = desc_prime;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	PRIME_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, (void *)sqrt_value, data->p->length);

	return CAAM_NO_ERROR;
}

/**
 * @brief   Build the descriptor to generate a prime \a p
 *
 * @param[out] desc        Reference to the descriptor buffer to build
 * @param[in]  data        Prime generation data
 * @param[in]  small_prime Pre-generated small prime value
 * @param[in]  do_prime_q  Generate Prime Q
 * @param[in]  desc_next   Physical address of the next descriptor (can be NULL)
 */
static void do_desc_prime(descPointer_t desc,
		struct caam_prime_data *data,
		const struct caambuf *small_prime, bool do_prime_q,
		const paddr_t desc_next)
{
	uint8_t desclen = 1;

	uint8_t retry_too_small;
	uint8_t retry_new_number;
	uint8_t retry_new_mr_failed;
	uint8_t retry_mr_test;

	/* Setup the number of try counter = MAX (counting down) */
	desc[desclen++] = MATH(ADD, SOL, ZERO, VSOL, 4);

	retry_new_mr_failed = desclen;
	if ((data->era < 8)  && (small_prime->paddr)) {
		/*
		 * Preload PKHA B2 with small prime predefined
		 * (preload only prime size requested)
		 */
		desc[desclen++] = FIFO_LD(CLASS_1, PKHA_B2, NOACTION,
							small_prime->length);
		desc[desclen++] = small_prime->paddr;
	}

	retry_new_number = desclen;
	/* Decrement the number of try */
	desc[desclen++] = MATH(SUB, VSOL, ONE, VSOL, 4);
	/* Exceed retry count - exit with PRIME_TRY_FAIL error */
	desc[desclen++] = HALT_USER(ALL_COND_TRUE, MATH_N, PRIME_TRY_FAIL);

	retry_too_small = desclen;
	/* Check internal limit on random value generation  */
	desc[desclen++] = MATH(SUB, DPOVRD, ONE, DPOVRD, 4);
	desc[desclen++] = HALT_USER(ALL_COND_TRUE, MATH_Z, RETRY_TOO_SMALL);

	/*
	 * Step 4.2 - Obtain a string p of (nlen/2) bits
	 * Step 4.3 - if (p is not odd) then p = p + 1
	 */
	/* Generate 16 random bytes load into DECO fifo */
	desc[desclen++] = LD_IMM(CLASS_NO, REG_NFIFO, 4);
	desc[desclen++] = NFIFO_PAD(DECO, NFIFO_LC1, MSG, RND, 16);
	/* Get the DECO Input fifo 8 MSB and force on high bit */
	desc[desclen++] = MATH(OR, REG2, IFIFO, REG0, 8);
	/* Get the DECO Input fifo 8 LSB and force it be be odd */
	desc[desclen++] = MATH(OR, ONE, IFIFO, REG1, 8);
	/* Move the MSB and LSB into IFIFO */
	desc[desclen++] = MOVE(MATH_REG0, IFIFO, 0, 16);
	/* Send the 8 MSB into PKHA N */
	desc[desclen++] = LD_IMM(CLASS_NO, REG_NFIFO, 4);
	desc[desclen++] = NFIFO_NOPAD(C1, 0, IFIFO, PKHA_N, 8);

	/*
	 * Generate the "middle" random bytes and start them
	 * on their way into PKHA N
	 */
	desc[desclen++] = LD_IMM(CLASS_NO, REG_NFIFO, 8);
	desc[desclen++] = NFIFO_PAD(C1, 0, PKHA_N, RND, 0);
	desc[desclen++] = data->p->length - 16;

	/* And send the 8 LSB into PKHA N */
	desc[desclen++] = LD_IMM(CLASS_NO, REG_NFIFO, 4);
	desc[desclen++] = NFIFO_NOPAD(C1, NFIFO_FC1, IFIFO, PKHA_N, 8);

	/*
	 * Step 4.4 - if ((prime < (sqrt 2)(2^((nlen / 2) - 1))
	 *    ==> retry_too_small
	 */
	desc[desclen++] = PKHA_CPY_SSIZE(A2, B0);
	desc[desclen++] = PKHA_CPY_SSIZE(B0, A0);
	desc[desclen++] = PKHA_OP(MOD_AMODN, A);
	desc[desclen++] = PKHA_CPY_SSIZE(A2, B0);
	desc[desclen++] = PKHA_F2M_OP(MOD_ADD_A_B, B);
	desc[desclen]   = JUMP_CNO_LOCAL(ANY_COND_FALSE,
					JMP_COND(PKHA_IS_ZERO),
					(retry_too_small - desclen));
	desclen++;

	/*
	 * Step 4.5 - Compute GCD(prime-1, e) and test if = 1 else try
	 * another candidate
	 */
	desc[desclen++] = PKHA_CPY_SSIZE(N0, A0);
	desc[desclen++] = FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1);
	desc[desclen++] = 0x01;
	desc[desclen++] = PKHA_F2M_OP(MOD_ADD_A_B, B);
	desc[desclen++] = PKHA_CPY_SSIZE(B0, N0);

	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_A, NOACTION, data->e->length);
	desc[desclen++] = data->e->paddr;
	desc[desclen++] = PKHA_OP(GCD_A_N, B);
	desc[desclen] = JUMP_CNO_LOCAL(ANY_COND_FALSE, JMP_COND(PKHA_GCD_1),
					(retry_new_number - desclen));
	desclen++;

	/* Restore "prime candidate" */
	desc[desclen++] = PKHA_CPY_SSIZE(N0, A0);
	desc[desclen++] = FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1);
	desc[desclen++] = 0x01;
	desc[desclen++] = PKHA_F2M_OP(MOD_ADD_A_B, B);
	desc[desclen++] = PKHA_CPY_SSIZE(B0, N0);

	/*
	 * Step 4.5.1 - test primality
	 */
	if (small_prime->paddr) {
		/* Test if it has small prime factors */
		desc[desclen++] = PKHA_CPY_SSIZE(B2, A0);
		desc[desclen++] = PKHA_OP(GCD_A_N, B);
		desc[desclen] = JUMP_CNO_LOCAL(ANY_COND_FALSE,
						JMP_COND(PKHA_GCD_1),
						(retry_new_number - desclen));
		desclen++;
	}

	/* Generate 8 random bytes 'miller-rabin seed' */
	/* Load the number of Miller-Rabin test iteration */
	desc[desclen++] = MATH(ADD, SIL, ZERO, VSIL, 4);
	retry_mr_test = desclen;
	desc[desclen++] = LD_IMM(CLASS_NO, REG_NFIFO, 8);
	desc[desclen++] = NFIFO_PAD(C1, NFIFO_FC1, PKHA_A, RND, 0);
	desc[desclen++] = data->p->length;
	desc[desclen++] = FIFO_LD_IMM(CLASS_1, PKHA_B, NOACTION, 1);
	desc[desclen++] = 0x01;
	desc[desclen++] = PKHA_OP(MR_PRIMER_TEST, B);
	desc[desclen] = JUMP_CNO_LOCAL(ANY_COND_FALSE,
					JMP_COND(PKHA_IS_PRIME),
					(retry_new_mr_failed - desclen));
	desclen++;
	desc[desclen++] = MATH(SUB, VSIL, ONE, VSIL, 4);
	desc[desclen] = JUMP_CNO_LOCAL(ALL_COND_FALSE,
					(JMP_COND(MATH_N) | JMP_COND(MATH_Z)),
					(retry_mr_test - desclen));
	desclen++;

	/* Save prime generated */
	desc[desclen++] = FIFO_ST(PKHA_N, data->p->length);

	if (do_prime_q)
		desc[desclen++] = data->q->paddr;
	else
		desc[desclen++] = data->p->paddr;

	if (desc_next) {
		/* Jump to the next descriptor desc */
		desc[desclen++] = JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
						JMP_COND(NONE));
		desc[desclen++] = desc_next;
	}

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	if (desclen > GEN_PRIME_DESC_ENTRIES)	{
		PRIME_TRACE("Descriptor Size too short (%d vs %d)",
					desclen, GEN_PRIME_DESC_ENTRIES);
		panic();
	}

	PRIME_DUMPDESC(desc);

}

/**
 * @brief   Build the descriptor to check p and q not too closed.\n
 *          Check the upper 100 bits by doing
 *          \f$ |p - q| <= 2^(nlen/2-100) \f$
 *
 * @param[out] desc        Reference to the descriptor buffer to build
 * @param[in]  p           Prime P
 * @param[in]  max_n       Max N built with 0xFFFF...
 * @param[in]  desc_new_q  Physical address to generate a new Q value
 */
static void do_checks_primes(descPointer_t desc,
		const struct caambuf *p,
		const struct caambuf *max_n,
		const paddr_t desc_new_q)
{
	const uint8_t check_len = 16; /* Check 128 bits */
	uint8_t desclen = 1;

	/* Load prime p */
	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_B, NOACTION, p->length);
	desc[desclen++] = p->paddr;

	/* Retrieve Q from PKHA N, previously computed */
	desc[desclen++] = PKHA_CPY_SSIZE(N0, A0);

	/* Calculate p - q, need a modulus of size prime p filled with 0xFF */
	desc[desclen++] = FIFO_LD(CLASS_1, PKHA_N, NOACTION, max_n->length);
	desc[desclen++] = max_n->paddr;

	/* PKHA_B = p - q */
	desc[desclen++] = PKHA_OP(MOD_SUB_A_B, B);

	/* Unload PKHA register B to output Data FIFO */
	desc[desclen++] = LD_NOCLASS_IMM(REG_CHA_CTRL, 4);
	desc[desclen++] = CCTRL_ULOAD_PKHA_B;

	/* Get the first 128 bits in MATH 0 */
	desc[desclen++] = MOVE_WAIT(OFIFO, MATH_REG0, 0, check_len);

	/*
	 * We now need to trash the rest of the result.
	 * We started with 128, 192, or 256 bytes in the OFIFO before we moved
	 * check_len bytes into MATH registers.
	 */
	if (p->length > (128 + check_len)) {
		desc[desclen++] = MOVE(OFIFO, C1_CTX_REG, 0, check_len);
		desc[desclen++] = MOVE(OFIFO, C1_CTX_REG, 0,
						(p->length - 128 - check_len));
	} else if (p->length > check_len) {
		desc[desclen++] = MOVE(OFIFO, C1_CTX_REG, 0,
						(p->length - check_len));
	}

	/*
	 * In MATH registers we have the p - q value modulo 0xFFFFF...
	 * Check the upper 100 bits are either zero or one meaning
	 * q is too close to p
	 */
	/* Check first 64 bits if not 0's check if 1's */
	desc[desclen++] = MATH(ADD, ZERO, REG0, REG0, 8);
	desc[desclen++] = JUMP_CNO_LOCAL(ANY_COND_FALSE, JMP_COND(MATH_Z), 6);
	/* First 64 bits are 0's, check next 36 bits */
	desc[desclen++] = MATH(AND, REG1, IMM_DATA, REG1, 8);
	desc[desclen++] = 0xFFFFFFFF;
	desc[desclen++] = 0xF0000000;

	/* Next 36 bits are 0 */
	desc[desclen++] = JUMP_CNO_LOCAL(ALL_COND_TRUE, JMP_COND(MATH_Z), 10);
	/* Exit status GOOD Q */
	desc[desclen++] = HALT_USER(ALL_COND_TRUE, NONE, STATUS_GOOD_Q);

	/* Check if 100 bits are 1's */
	desc[desclen++] = MATH(ADD, ONE, REG0, REG0, 8);
	/* Not all 1's exit status GOOD Q */
	desc[desclen++] = HALT_USER(ANY_COND_FALSE, MATH_Z,
					STATUS_GOOD_Q);
	/* First 64 bits are 1's, check next 36 bits */
	desc[desclen++] = MATH(AND, REG1, IMM_DATA, REG1, 8);
	desc[desclen++] = 0xFFFFFFFF;
	desc[desclen++] = 0xF0000000;
	/* Use only 4 bytes of immediate data even is operation is 8 bytes */
	desc[desclen++] = MATH(ADD, REG1, IMM_DATA, REG1, 8) | MATH_IFB;
	desc[desclen++] = 0x10000000;
	/* Not all 1's exit status GOOD Q */
	desc[desclen++] = HALT_USER(ANY_COND_FALSE, MATH_Z,
					STATUS_GOOD_Q);

	if (desc_new_q) {
		desc[desclen++] = JUMP_NOTLOCAL(CLASS_NO, ALL_COND_TRUE,
						JMP_COND(NONE));
		desc[desclen++] = desc_new_q;
	}

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	if (desclen > CHECK_P_Q_DESC_ENTRIES)	{
		PRIME_TRACE("Descriptor Size too short (%d vs %d)",
					desclen, CHECK_P_Q_DESC_ENTRIES);
		panic();
	}

	PRIME_DUMPDESC(desc);
}

/**
 * @brief   Generate a Prime Number
 *          Algorithm based on the Chapter B.3.3 of the FIPS.184-6
 *          specification
 *
 * @param[in/out] data  Prime generation data
 *
 * @retval  CAAM_NO_ERROR   No Error
 * @retval  CAAM_FAILURE    General failure
 * @retval  CAAM_OUT_MEMORY Out of memory error
 */
enum CAAM_Status caam_prime_gen(struct caam_prime_data *data)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	struct caambuf small_prime = {0};
	struct caambuf max_n       = {0};

	struct jr_jobctx jobctx  = {0};
	descPointer_t all_descs  = NULL;
	descPointer_t desc_p;
	descPointer_t desc_q;
	descPointer_t desc_check_p_q;
	paddr_t       paddr_desc_p;
	paddr_t       paddr_desc_q;
	paddr_t       paddr_desc_check_p_q;

	size_t size_all_descs;

	/* Allocate the job used to prepare the operation */
	if (data->q) {
		size_all_descs = SETUP_PRIME_DESC_ENTRIES +
						(GEN_PRIME_DESC_ENTRIES * 2) +
						CHECK_P_Q_DESC_ENTRIES;

		retstatus = caam_alloc_buf(&max_n, data->p->length + 1);
		if (retstatus != CAAM_NO_ERROR)
			goto end_gen_prime;

		/* Set the max_n with 0xFFF... to operate the check P and Q */
		memset(max_n.data, 0xFF, max_n.length);
		cache_operation(TEE_CACHECLEAN, max_n.data, max_n.length);
	} else {
		size_all_descs = SETUP_PRIME_DESC_ENTRIES +
		    GEN_PRIME_DESC_ENTRIES;
	}

	all_descs = caam_alloc_desc(size_all_descs);
	if (!all_descs) {
		retstatus = CAAM_OUT_MEMORY;
		goto end_gen_prime;
	}

	/* Descriptor Prime P */
	desc_p       = all_descs + SETUP_PRIME_DESC_ENTRIES;
	paddr_desc_p = virt_to_phys(desc_p);
	if (!paddr_desc_p) {
		retstatus = CAAM_FAILURE;
		goto end_gen_prime;
	}

	/*
	 * Search predefined prime in the small_prime list, if the
	 * small prime is not found in the list, continue anyway
	 * but prime will be probably not so strong
	 */
	search_smallprime(data->p->length, &small_prime);

	PRIME_TRACE("Do prime of %d bytes for security length=%d bits (ERA=%d)",
			data->p->length, data->key_size, data->era);

	retstatus = do_desc_setup(all_descs, data, &small_prime, paddr_desc_p);

	if (data->q) {
		/* Descriptor Prime Q */
		desc_q       = desc_p + GEN_PRIME_DESC_ENTRIES;
		paddr_desc_q = paddr_desc_p +
					DESC_SZBYTES(GEN_PRIME_DESC_ENTRIES);

		/* Descriptor Check Primes P & Q */
		desc_check_p_q       = desc_q + GEN_PRIME_DESC_ENTRIES;
		paddr_desc_check_p_q = paddr_desc_q +
					DESC_SZBYTES(GEN_PRIME_DESC_ENTRIES);

		/* Generate Prime P and Q then check Q not too close than P */
		do_desc_prime(desc_p, data, &small_prime, false, paddr_desc_q);

		do_desc_prime(desc_q, data, &small_prime, true,
				paddr_desc_check_p_q);

		do_checks_primes(desc_check_p_q, data->p, &max_n, paddr_desc_q);
	} else {
		do_desc_prime(desc_p, data, &small_prime, false, 0);
	}

	cache_operation(TEE_CACHECLEAN, small_prime.data, data->p->length);
	cache_operation(TEE_CACHECLEAN, data->e->data, data->e->length);
	cache_operation(TEE_CACHEFLUSH, data->p->data, data->p->length);

	if (data->q)
		cache_operation(TEE_CACHEFLUSH, data->q->data, data->q->length);

	jobctx.desc = all_descs;

	cache_operation(TEE_CACHECLEAN, (void *)all_descs,
			DESC_SZBYTES(size_all_descs));

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if ((data->q) && (retstatus == CAAM_JOB_STATUS)) {
		/*
		 * Expect to have a retstatus == CAAM_JOB_STATUS, where
		 * job status == STATUS_GOOD_Q
		 */
		PRIME_TRACE("Check Prime Q Status 0x%08"PRIx32"",
				jobctx.status);

		if (JRSTA_GET_HALT_USER(jobctx.status) == STATUS_GOOD_Q) {
			cache_operation(TEE_CACHEINVALIDATE, data->p->data,
					data->p->length);
			cache_operation(TEE_CACHEINVALIDATE, data->q->data,
					data->q->length);

			PRIME_DUMPBUF("Prime P", data->p->data,
					data->p->length);
			PRIME_DUMPBUF("Prime Q", data->q->data,
					data->q->length);
			retstatus = CAAM_NO_ERROR;
			goto end_gen_prime;
		}
	} else if ((retstatus == CAAM_NO_ERROR) && (!data->q)) {
		/* Ensure Prime value is correct */
		cache_operation(TEE_CACHEINVALIDATE, data->p->data,
				data->p->length);

		PRIME_DUMPBUF("Prime", data->p->data, data->p->length);

		retstatus = CAAM_NO_ERROR;
		goto end_gen_prime;
	}

	PRIME_TRACE("Prime Status 0x%08"PRIx32"", jobctx.status);
	retstatus = CAAM_FAILURE;

end_gen_prime:
	caam_free_desc(&all_descs);
	caam_free_buf(&max_n);

	return retstatus;

}

