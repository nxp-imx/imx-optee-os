/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __DRIVERS_IMX_OCOTP_H
#define __DRIVERS_IMX_OCOTP_H

#include <tee_api_types.h>

/* The i.MX UID is 64 bits long */
#define IMX_UID_SIZE sizeof(uint64_t)

/*
 * Read OCOTP fuse register
 * For Non-ELE platforms, first argument is:-
 * @bank     Fuse bank number for i.MX6/i.MX7/i.MX8 platform.
 *
 * For ELE based platform, first argument is:-
 * @read_common_fuse We have replaced bank parameter with read_common_fuse
 *		     variable, whether user wants to read fuse using
 *		     READ FUSE (0x97) or READ SHADOW FUSE (0xF3) API.
 * @word     Fuse word number
 * @[out]val Shadow register value
 */
TEE_Result imx_ocotp_read(unsigned int bank, unsigned int word, uint32_t *val);

/*
 * Write OCOTP fuses
 *
 * @bank     Fuse bank number
 * @word     Fuse word number
 * @[in]val  Value to burn
 */
TEE_Result imx_ocotp_write(unsigned int bank, unsigned int word, uint32_t val);
#endif /* __DRIVERS_IMX_OCOTP_H */
