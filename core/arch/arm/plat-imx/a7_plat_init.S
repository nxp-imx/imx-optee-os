/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 */

/*
 * Entry points for the A7 init.
 * It is assume no stack is available when these routines are called.
 * It is assume each routine is called with return address in LR
 * and with ARM registers R0, R1, R2, R3 being scratchable.
 */

#include <arm32_macros.S>
#include <asm.S>
#include <arm.h>
#include <kernel/unwind.h>
#include <platform_config.h>

/*
 * Local variable to store the DTB physical address
 * This variable is needed if DTB must be read
 * before the virtual DTB address is setup during
 * the C generic boot
 * Better will be to have a init platform function
 * called by the C generic boot
 */
.section .data
.align 2
phys_dt_addr:
.word 0

.section .text
.balign 4
.code 32

/*
 * Cortex A7 configuration early configuration
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC plat_cpu_reset_early , :
UNWIND(	.fnstart)

	mov_imm r0, 0x00000040
	write_actlr r0

	mov_imm r0, 0x00040C00
	write_nsacr r0

	read_sctlr r0
	bic	r0, r0, #SCTLR_WXN
	bic	r0, r0, #SCTLR_UWXN
	write_sctlr r0
	isb

	/* based on kernel/generic_entry_a32.S
	 * r6 contains the DT physicall address
	 * Store it in the global variable phys_fdt_addr
	 * instantiated in data area above
	 */
	ldr	r0, =phys_dt_addr
	str	r6, [r0]

	bx	lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early

FUNC plat_get_dt_phys , :
UNWIND( .fnstart)
	/* Return the physical DT address */
	ldr	r0, =phys_dt_addr
	ldr r0, [r0]
	bx  lr
UNWIND( .fnend)
END_FUNC plat_get_dt_phys
