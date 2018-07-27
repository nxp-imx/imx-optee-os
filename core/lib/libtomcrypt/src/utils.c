// SPDX-License-Identifier: BSD-2-Clause
/*
 * copyright 2018 NXP
 */

#if defined(CFG_WITH_VFP)
#include <tomcrypt_arm_neon.h>
#include <kernel/thread.h>

void tomcrypt_arm_neon_enable(struct tomcrypt_arm_neon_state *state)
{
	state->state = thread_kernel_enable_vfp();
}

void tomcrypt_arm_neon_disable(struct tomcrypt_arm_neon_state *state)
{
	thread_kernel_disable_vfp(state->state);
}
#endif
