/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * Copyright 2017-2018 NXP
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
#ifndef __IMX6_REGS_H__
#define __IMX6_REGS_H__
#include <registers/imx6-crm_regs.h>
#include <registers/imx6-src_regs.h>
#include <registers/imx6-iomux_regs.h>
#include <registers/imx6-mmdc_regs.h>

#define UART1_BASE		0x02020000
#define IOMUXC_BASE		0x020E0000
#define IOMUXC_GPR_BASE		0x020E4000
#define SRC_BASE		0x020D8000
#define CCM_BASE		0x020C4000
#define ANATOP_BASE		0x020C8000
#define SNVS_BASE		0x020CC000
#define UART2_BASE		0x021E8000
#define UART3_BASE		0x021EC000
#define UART4_BASE		0x021F0000
#define UART5_BASE		0x021F4000
#define MMDC_P0_BASE		0x021B0000
#define TZASC_BASE		0x21D0000
#define TZASC2_BASE		0x21D4000
#define SCU_BASE		0x00A00000
#define PL310_BASE		0x00A02000
#define GIC_BASE		0x00A00000
#define GICD_OFFSET		0x1000

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL)
#define GICC_OFFSET		0x2000
#else
#define GICC_OFFSET		0x100
#endif

#if defined(CFG_MX6UL) || defined(CFG_MX6ULL)
/* 128K OCRAM */
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6DL)
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6QP)
#define TRUSTZONE_OCRAM_START		0x938000
#elif defined(CFG_MX6SX)
#define TRUSTZONE_OCRAM_START		0x8f8000
#elif defined(CFG_MX6SL)
#define TRUSTZONE_OCRAM_START		0x918000
#elif defined(CFG_MX6SLL)
#define TRUSTZONE_OCRAM_START		0x918000
#else
/* 256K OCRAM */
#define TRUSTZONE_OCRAM_START		0x938000
#endif

/* Central Security Unit register values */
#define CSU_BASE		0x021C0000
#define CSU_CSL_START		0x0
#define CSU_CSL_END		0xA0
#define CSU_ACCESS_ALL		0x00FF00FF
#define CSU_SETTING_LOCK	0x01000100

#endif /* __IMX6_REGS_H__ */
