/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <registers/imx-regs.h>

#define STACK_ALIGNMENT			64


#ifndef CFG_DDR_SIZE
#error "CFG_DDR_SIZE not defined"
#endif

/* For i.MX8M platforms */
#if defined(CFG_MX8M)
#include <config/imx8m.h>
/* For i.MX8MM platforms */
#elif defined(CFG_MX8MM)
#include <config/imx8mm.h>
#elif defined(CFG_MX8QM)
#include <config/imx8qm.h>
#elif defined(CFG_MX8QX)
#include <config/imx8qx.h>
/* For i.MX7D/S platforms */
#elif defined(CFG_MX7)
#include <config/imx7.h>
/* For i.MX7ULP platforms */
#elif defined(CFG_MX7ULP)
#include <config/imx7ulp.h>
#elif defined(CFG_MX6QP) || defined(CFG_MX6Q) || defined(CFG_MX6D) || \
	defined(CFG_MX6DL) || defined(CFG_MX6S)
/* For i.MX6 Quad SABRE Lite and Smart Device board */
#include <config/imx6qdlsolo.h>
/* For i.MX 6SL */
#elif defined(CFG_MX6SL)
#include <config/imx6sl.h>
/* For i.MX 6SLL */
#elif defined(CFG_MX6SLL)
#include <config/imx6sll.h>
#elif defined(CFG_MX6SX)
#include <config/imx6sx.h>
#elif defined(CFG_MX6UL) || defined(CFG_MX6ULL)
/* For i.MX 6UltraLite and 6ULL EVK board */
#include <config/imx6ul.h>
#else
#error "Unknown platform flavor"
#endif

#ifdef CFG_UART_BASE
#define CONSOLE_UART_BASE	CFG_UART_BASE
#endif

#ifndef CFG_TEE_RESERVED_SIZE
#define CFG_TEE_RESERVED_SIZE 0x02000000
#endif

#ifndef CFG_TZDRAM_START
#if defined CFG_ARM64_core 
/* put optee end of ddr for AARCH64 */
#define  CFG_TZDRAM_START (DRAM0_BASE + CFG_DDR_SIZE - CFG_TEE_RESERVED_SIZE)
#else
/* put optee at DDR base address + 64MB for AARCH32 */
#define  CFG_TZDRAM_START (DRAM0_BASE + 0x04000000) 
#endif
#endif

#ifndef CFG_SHMEM_SIZE
#define  CFG_SHMEM_SIZE 0x100000
#endif

#ifndef CFG_TZDRAM_SIZE
#define  CFG_TZDRAM_SIZE  (CFG_TEE_RESERVED_SIZE - CFG_SHMEM_SIZE)
#endif

#ifndef CFG_SHMEM_START
#define  CFG_SHMEM_START (CFG_TZDRAM_START + CFG_TZDRAM_SIZE)
#endif

#include <mm/generic_ram_layout.h>

#endif /*PLATFORM_CONFIG_H*/
