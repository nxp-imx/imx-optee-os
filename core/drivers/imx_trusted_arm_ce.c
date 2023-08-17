// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */

#include <drivers/imx_trusted_arm_ce.h>
#ifdef CFG_WITH_VFP
#include <kernel/vfp.h>
#endif
#include <pta_imx_trusted_arm_ce.h>

TEE_Result imx_smc_cipher_cbc(struct thread_smc_args *args, bool encrypt)
{
	uint32_t key_id = (uint32_t)args->a1;

	vfp_enable();

	args->a0 = cipher_cbc(key_id, args->a2, args->a3, args->a4, args->a5,
			      args->a6, encrypt);
	vfp_disable();

	return TEE_SUCCESS;
}

TEE_Result imx_smc_cipher_xts(struct thread_smc_args *args, bool encrypt)
{
	uint32_t key_id_1 = (uint32_t)(args->a1 & 0xFFFFFFFF);
	uint32_t key_id_2 = (uint32_t)(args->a1 >> 32);

	vfp_enable();

	args->a0 = cipher_xts(key_id_1, key_id_2, args->a2, args->a3, args->a4,
			      args->a5, args->a6, encrypt);
	vfp_disable();

	return TEE_SUCCESS;
}
