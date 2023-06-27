// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <drivers/ele_extension.h>
#include <ele.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <utils_mem.h>

#ifdef CFG_IMX_OCOTP
#error "CFG_IMX_OCOTP and CFG_IMX_ELE are exclusive"
#endif

#define ELE_CMD_READ_COMMON 0x97
#define ELE_CMD_READ_SHADOW 0xF3

struct ele_instance {
	unsigned int nb_banks;
	unsigned int nb_words;
	bool (*fuse_map)(unsigned int fuse_index);
};

static const struct ele_instance *g_ele;

/*
 * Read fuse value.
 *
 * @fuse_index: fuse id
 * @fuse_value: fuse value
 * @command:	ELE read fuse command
 */
static TEE_Result imx_ele_read_fuse(unsigned int fuse_index,
				    uint32_t *fuse_value, uint8_t command)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct read_fuse_msg_cmd {
		uint32_t fuse_index;
	} cmd = {
		.fuse_index = fuse_index,
	};
	struct read_fuse_rsp {
		uint32_t rsp_code;
		uint32_t fuse_value;
	} rsp = {};
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = command,
	};

	assert(fuse_value);

	/* Fuse index is only 16bits wide for Read Common fuse */
	if (command == ELE_CMD_READ_COMMON && cmd.fuse_index > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to read fuse res = %" PRIx32, res);
		return res;
	}

	*fuse_value = rsp.fuse_value;

	return TEE_SUCCESS;
}

/*
 * ELE fuse map for imx8ulp
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read Common fuse command,
 * this command is used to read non-security related fuses.
 */
static bool imx8ulp_ele_common_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 8 ... 23:
	case 192 ... 224:
	case 256 ... 295:
	case 392 ... 415:
		return true;
	default:
		return false;
	}
}

/*
 * ELE fuse map for imx93
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read Common fuse command,
 * this command is used to read non-security related fuses.
 */
static bool imx93_ele_common_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 24 ... 34:
	case 63:
	case 128 ... 144:
	case 182:
	case 188:
		return true;
	default:
		return false;
	}
}

TEE_Result imx_ocotp_read(unsigned int bank, unsigned int word,
			  uint32_t *fuse_value)
{
	unsigned int fuse_index = 0;

	if (!g_ele || !g_ele->fuse_map)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!fuse_value)
		return TEE_ERROR_BAD_PARAMETERS;

	if (bank > g_ele->nb_banks || word > g_ele->nb_words)
		return TEE_ERROR_BAD_PARAMETERS;

	fuse_index = bank * g_ele->nb_words + word;

	if (g_ele->fuse_map(fuse_index))
		return imx_ele_read_fuse(fuse_index, fuse_value,
					 ELE_CMD_READ_COMMON);
	else
		return imx_ele_read_fuse(fuse_index, fuse_value,
					 ELE_CMD_READ_SHADOW);
}

static const struct ele_instance ele_imx93 = {
	.nb_banks = 64,
	.nb_words = 8,
	.fuse_map = imx93_ele_common_fuse_map,
};

static const struct ele_instance ele_imx8ulp = {
	.nb_banks = 64,
	.nb_words = 8,
	.fuse_map = imx8ulp_ele_common_fuse_map,
};

static TEE_Result imx_ele_fuse_init(void)
{
	switch (imx_soc_type()) {
	case SOC_MX8ULP:
		g_ele = &ele_imx8ulp;
		break;
	case SOC_MX93:
		g_ele = &ele_imx93;
		break;
	default:
		g_ele = NULL;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}
driver_init(imx_ele_fuse_init);
