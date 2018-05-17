/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018 NXP
 *
 */

#ifndef CONFIG_IMX8MM_H
#define CONFIG_IMX8MM_H

#ifndef CFG_UART_BASE
#define CFG_UART_BASE	(UART2_BASE)
#endif

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		CFG_DDR_SIZE

#define CONSOLE_UART_BASE	(CFG_UART_BASE)
#endif
