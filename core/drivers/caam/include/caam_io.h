/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    caam_io.h
 *
 * @brief   CAAM driver caam_io.h include file.\n
 *          Macros for reading/writing CAAM registers
 *          taking care of endianness.
 */

#ifndef __CAAM_IO_H__
#define __CAAM_IO_H__

#include <io.h>

#define put_le64(a, v)		(*(volatile uint64_t *)(a) = (v))

#define setbits_le32(a, v)      write32((vaddr_t)(a), read32((vaddr_t)(a)) | (v))
#define clrbits_le32(a, c)      write32((vaddr_t)(a), read32((vaddr_t)(a)) & ~(c))
#define clrsetbits_le32(a, c, s)        write32((vaddr_t)(a), (read32((vaddr_t)(a)) & ~(c)) | (s))

#define setbits_be32(a, v)      put_be32((void *)(a), get_be32((void *)(a)) | (v))
#define clrbits_be32(a, c)      put_be32((void *)(a), get_be32((void *)(a)) & ~(c))
#define clrsetbits_be32(a, c, s)        put_be32((void *)(a), (get_be32((void *)(a)) & ~(c)) | (s))

#ifdef CFG_NXP_SEC_BE
#define get32(a)		get_be32((void *)(a))
#define put32(a, v)		put_be32((void *)(a), v)
#define get64(a)	(                                       \
		((uint64_t)get32(a) << 32) |        \
		(get32((uintptr_t)(a) + 4)))
#define put64(a, v)	put_be64((void *)(a), v)
#define mask32(a, v, mask) (		\
	put32(a, (get32(a) & ~mask) | (v & mask)))
#else
#define get32(a)		read32((vaddr_t)(a))
#define put32(a, v)		write32(v, (vaddr_t)(a))
#define get64(a)	(                                       \
		((uint64_t)get32((uintptr_t)(a) + 4) << 32) |    \
		(get32(a)))
#define put64(a, v)	put_le64(a, v)
#define mask32(a, v, mask) (		\
	put32(a, (get32(a) & ~mask) | (v & mask)))
#endif

#ifdef	CFG_PHYS_64BIT
#define sec_read_addr(a)	get64(a)
#define sec_write_addr(a, v)    put64(a, v)
#else
#define sec_read_addr(a)	get32(a)
#define sec_write_addr(a, v)    put32(a, v)
#endif

#endif /* __CAAM_IO_H__ */
