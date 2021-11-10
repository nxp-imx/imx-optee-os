/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019, 2021 NXP
 *
 * Brief   CAAM Manufacturing Protection header.
 */
#ifndef __CAAM_MP_H__
#define __CAAM_MP_H__

#ifdef CFG_NXP_CAAM_MP_DRV
/*
 * Initialize the MP module and generate the private key
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_mp_init(vaddr_t ctrl_addr);

/*
 * Power Management for MP
 *
 * @pm_hint   Power mode type
 */
void caam_mp_resume(uint32_t pm_hint);
#else
static inline enum caam_status caam_mp_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}

static inline void caam_mp_resume(uint32_t pm_hint __unused)
{
}
#endif /* CFG_NXP_CAAM_MP_DRV */

#endif /* __CAAM_MP_H__ */
