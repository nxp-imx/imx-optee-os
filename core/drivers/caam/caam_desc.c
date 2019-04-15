// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    caam_desc.c
 *
 * @brief   Descriptor construction functions..\n
 */
#include <types_ext.h>
#include <trace.h>

#include "desc_helper.h"
#include "desc_defines.h"
#include "caam_io.h"

/* Macros for manipulating JR registers */
typedef union {
	uint64_t m_whole;
	struct {
#ifdef CFG_NXP_SEC_BE
		uint32_t high;
		uint32_t low;
#else
		uint32_t low;
		uint32_t high;
#endif
	} m_halves;
} ptr_addr_t;

// Return higher 32 bits of physical address
#define PHYS_ADDR_HI(phys_addr) \
	(uint32_t)(((uint64_t)phys_addr) >> 32)

// Return lower 32 bits of physical address
#define PHYS_ADDR_LO(phys_addr) \
	(uint32_t)(((uint64_t)phys_addr) & 0xFFFFFFFF)


uint32_t desc_get_len(uint32_t * desc)
{
	return GET_JD_DESCLEN(get32((void *)desc));
}

/* Initialize the descriptor */
void desc_init(uint32_t *desc)
{
	*desc = 0;
}

void desc_update_hdr(uint32_t *desc, uint32_t word)
{
	/* Update first word of desc */
	put32((void *)desc, word);

}

void desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t len = GET_JD_DESCLEN(get32((void *)desc));

	uint32_t *last = desc + len;

	/* Add Word at Last */
	put32((void *)last, word);

	/* Increase the length */
	put32((void *)(desc), (get32((void *)desc) + 1));
}

/* Add Pointer to the descriptor */
void desc_add_ptr(uint32_t *desc, paddr_t ptr)
{
	uint32_t len = GET_JD_DESCLEN(get32((void *)desc));

	/* Add Word at Last */
	uint32_t *last = desc + len;
	uint32_t inc = 1;

#ifdef CFG_PHYS_64BIT
	ptr_addr_t *ptr_addr = (ptr_addr_t *)(uintptr_t)last;

	put32((void *)(&ptr_addr->m_halves.high), PHYS_ADDR_HI(ptr));
	put32((void *)(&ptr_addr->m_halves.low), PHYS_ADDR_LO(ptr));
	inc++;
#else
	put32((void *)last, ptr);
#endif

	/* Increase the length */
	put32((void *)(desc), (get32((void *)desc) + inc));
}
