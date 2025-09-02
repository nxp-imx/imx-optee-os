// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023, 2025 NXP
 */

#include <drivers/imx_trusted_arm_ce.h>
#ifdef CFG_WITH_VFP
#include <kernel/vfp.h>
#endif
#include <pta_imx_trusted_arm_ce.h>

#ifdef CFG_WITH_VFP
struct smc_vfp_state {
	bool v_state_saved;
	struct vfp_state v_state;
};

static struct smc_vfp_state smc_v_state = {};
#endif

static void fast_smc_enable_vfp(void)
{
#ifdef CFG_WITH_VFP
	assert(!vfp_is_enabled());

	smc_v_state.v_state_saved = false;
	vfp_lazy_save_state_init(&smc_v_state.v_state);

	vfp_lazy_save_state_final(&smc_v_state.v_state, true /*force_save*/);
	smc_v_state.v_state_saved = true;

	vfp_enable();
#endif
}

static void fast_smc_disable_vfp(void)
{
#ifdef CFG_WITH_VFP
	assert(vfp_is_enabled());

	vfp_disable();
	vfp_lazy_restore_state(&smc_v_state.v_state, smc_v_state.v_state_saved);
	smc_v_state.v_state_saved = false;
#endif
}

TEE_Result imx_smc_cipher_cbc(struct thread_smc_args *args, bool encrypt)
{
	uint32_t key_id = (uint32_t)args->a1;

	fast_smc_enable_vfp();

	args->a0 = cipher_cbc(key_id, args->a2, args->a3, args->a4, args->a5,
			      args->a6, encrypt);

	fast_smc_disable_vfp();

	return TEE_SUCCESS;
}

TEE_Result imx_smc_cipher_xts(struct thread_smc_args *args, bool encrypt)
{
	uint32_t key_id_1 = (uint32_t)(args->a1 & 0xFFFFFFFF);
	uint32_t key_id_2 = (uint32_t)(args->a1 >> 32);

	fast_smc_enable_vfp();

	args->a0 = cipher_xts(key_id_1, key_id_2, args->a2, args->a3, args->a4,
			      args->a5, args->a6, encrypt);

	fast_smc_disable_vfp();

	return TEE_SUCCESS;
}
