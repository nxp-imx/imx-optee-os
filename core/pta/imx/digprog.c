// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 */
#include <stdlib.h>
#include <string.h>
#include <imx.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common_otp.h>
#include <pta_digprog.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <kernel/user_ta.h>

#define DIGPROG_PTA_NAME "digprog.pta"

/*
 * Called when a pseudo TA is invoked.
 *
 * sess_ctx    Session Identifier
 * cmd_id      Command ID
 * param_types TEE parameters
 * params      Buffer parameters
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id __unused,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = imx_get_digprog();
	params[0].value.b = 0;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_DIGPROG_UUID, .name = DIGPROG_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
