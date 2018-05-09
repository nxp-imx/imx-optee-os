/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    desc_interface.h
 *
 * @brief   CAAM Descriptor interface.
 */
#ifndef __DESC_HELPER_H__
#define __DESC_HELPER_H__

/* Local includes */
#include "desc_defines.h"

/**
 * @brief   Descriptor Entry type
 */
typedef uint32_t descEntry_t;

/**
 * @brief   Descriptor pointer type
 */
typedef uint32_t *descPointer_t;

/**
 * @brief   Descriptor status type
 */
typedef uint32_t descStatus_t;

/**
 * @brief  Returns the number of entries of the descriptor \a desc
 */
#define DESC_NBENTRIES(desc)	GET_JD_DESCLEN(*(descEntry_t *)desc)

/* Debug print function to dump a Descriptor in hex */
static inline void dump_desc(void *desc)
{
	size_t idx;
	size_t len;
	descPointer_t buf = desc;

	len = DESC_NBENTRIES(desc);

	for (idx = 0; idx < len; idx++)
		trace_printf(NULL, 0, 0, false, "[%02d] %08X",
				(int)idx, buf[idx]);
}

/**
 * @brief  Returns the descriptor size in bytes of \a nbEntries
 */
#define DESC_SZBYTES(nbEntries)	(nbEntries * sizeof(descEntry_t))

/**
 * @brief  Descriptor Header starting at index \a idx w/o descriptor length
 */
#define DESC_HDR(idx) \
			(CMD_HDR_JD_TYPE | HDR_JD_ONE | HDR_JD_START_IDX(idx))

/**
 * @brief  Descriptor Header starting at index 0 with descriptor length \a len
 */
#define DESC_HEADER(len) \
			(DESC_HDR(0) | HDR_JD_DESCLEN(len))

/**
 * @brief  Jump Local of class \a cla to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_LOCAL(cla, test, cond, offset) \
		(CMD_JUMP_TYPE | CMD_CLASS(cla) | JUMP_TYPE(LOCAL) |	\
		JUMP_TST_TYPE(test) | cond | JMP_LOCAL_OFFSET(offset))
/**
 * @brief  Jump Local of class 1 to descriptor offset \a offset
 *          if test \a test meet the condition \a cond
 */
#define JUMP_C1_LOCAL(test, cond, offset) \
			JUMP_LOCAL(CLASS_1, test, cond, offset)

/**
 * @brief  Load Immediate value of length \a len to register \a dst of
 *         class \a cla
 */
#define LD_IMM(cla, dst, len) \
			(CMD_LOAD_TYPE | CMD_CLASS(cla) | CMD_IMM |	\
			LOAD_DST(dst) | LOAD_LENGTH(len))

/**
 * @brief  Load Immediate value of length \a len to register \a dst w/o class
 */
#define LD_NOCLASS_IMM(dst, len) \
			LD_IMM(CLASS_NO, dst, len)

/**
 * @brief  FIFO Store from register \a src of length \a len
 */
#define FIFO_ST(src, len) \
			(CMD_FIFO_STORE_TYPE | FIFO_STORE_OUTPUT(src) | \
			FIFO_STORE_LENGTH(len))

/**
 * @brief  RNG State Handle instantation operation for \a sh id
 */
#define RNG_SH_INST(sh) \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			ALGO_RNG_SH(sh) | ALGO_AS(RNG_INSTANTIATE))

/**
 * @brief  RNG Generates Secure Keys
 */
#define RNG_GEN_SECKEYS \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			ALGO_RNG_SK | ALGO_AS(RNG_GENERATE))

/**
 * @brief  RNG Generates Data
 */
#define RNG_GEN_DATA \
			(CMD_OP_TYPE | OP_TYPE(CLASS1) | OP_ALGO(RNG) | \
			 ALGO_AS(RNG_GENERATE))

#endif /* __DESC_HELPER_H__ */

