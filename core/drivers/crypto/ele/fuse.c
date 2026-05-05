// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023, 2025-2026 NXP
 */
#include <drivers/ele_extension.h>
#include <drivers/ele/ele.h>
#include <drivers/ele/memutils.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>

#ifdef CFG_IMX_OCOTP
#error "CFG_IMX_OCOTP and CFG_IMX_ELE are exclusive"
#endif

#define ELE_CMD_READ_COMMON 0x97
#define ELE_CMD_READ_SHADOW 0xF3

struct ele_instance {
	unsigned int nb_banks;
	unsigned int nb_words;
	bool (*fuse_map)(unsigned int fuse_index);
	uint16_t lifecycle;
};

static struct ele_instance *g_ele;

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
	uint32_t current_crc = 0;

	struct read_fuse_msg_cmd {
		uint32_t fuse_index;
	} cmd = {
		.fuse_index = fuse_index,
	};
	struct read_fuse_rsp {
		uint32_t rsp_code;
		uint32_t fuse_value;
		uint32_t crc;
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

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	if (command == ELE_CMD_READ_COMMON &&
	    msg.header.size > CRC_WORD_LIMIT) {
		current_crc = compute_crc(&msg);
		if (current_crc != rsp.crc)
			EMSG("CRC differs current_crc = %x rsp.crc = %x",
			     current_crc, rsp.crc);
	}

	*fuse_value = rsp.fuse_value;

	return TEE_SUCCESS;
}

/*
 * ELE fuse map for imx8ulp
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx8ulp_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 1:
	case 2:
	case 8 ... 23:
	case 66:
	case 97:
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
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx93_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 0 ... 51: /* FSB index */
	case 55 ... 60:
	case 62 ... 63:
	case 97:
	case 128 ... 143:
	case 182:
	case 188:
	case 312 ... 511: /* FSB index */
		return true;
	default:
		return false;
	}
}

/*
 * ELE fuse map for imx91
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx91_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 0 ... 51: /* FSB index */
	case 55 ... 60:
	case 62 ... 63:
	case 97:
	case 128 ... 143:
	case 182:
	case 188:
	case 312 ... 511: /* FSB index */
		return true;
	default:
		return false;
	}
}
/*
 * ELE fuse map for imx95
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx95_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 0:
	case 7:
	case 9 ... 51:
	case 317 ... 318:
	case 320 ... 326:
	case 328 ... 391:
	case 448 ... 607:
		return true;
	default:
		return false;
	}
}

/*
 * ELE fuse map for imx943
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx943_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 0:
	case 7:
	case 9 ... 51:
	case 52 ... 167:
	case 525 ... 526:
	case 528 ... 534:
	case 536 ... 815:
		return true;
	default:
		return false;
	}
}

/*
 * ELE fuse map for imx952
 *
 * @fuse_index: fuse id
 *
 * Return true if fuse id is supported by the ELE Read fuse command
 * or ELE Read Shadow fuse command.
 */
static bool imx952_ele_fuse_map(unsigned int fuse_index)
{
	switch (fuse_index) {
	case 0:
	case 7:
	case 9 ... 51:
	case 317 ... 318:
	case 320 ... 326:
	case 328 ... 391:
	case 448 ... 607:
		return true;
	default:
		return false;
	}
}

TEE_Result imx_ocotp_read(unsigned int read_common_fuse, unsigned int word,
			  uint32_t *fuse_value)
{
	unsigned int fuse_index = 0;

	if (!g_ele || !g_ele->fuse_map)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!fuse_value)
		return TEE_ERROR_BAD_PARAMETERS;

	if (word >= (g_ele->nb_banks * g_ele->nb_words))
		return TEE_ERROR_BAD_PARAMETERS;

	fuse_index = word;

	if (!g_ele->fuse_map(fuse_index))
		return TEE_ERROR_BAD_PARAMETERS;

	if (read_common_fuse) {
		return imx_ele_read_fuse(fuse_index, fuse_value,
					 ELE_CMD_READ_COMMON);
	} else {
		if (g_ele->lifecycle == SOC_LIFECYCLE_OPEN)
			return imx_ele_read_fuse(fuse_index, fuse_value,
						 ELE_CMD_READ_SHADOW);
		/*
		 * In closed lifecycle, it is restricted to read the fuse via
		 * Read Shadow Fuse command.
		 */
		else
			return TEE_ERROR_ACCESS_DENIED;
	}
}

static struct ele_instance ele_imx95 = {
	.nb_banks = 77,
	.nb_words = 8,
	.fuse_map = imx95_ele_fuse_map,
};

static struct ele_instance ele_imx93 = {
	.nb_banks = 64,
	.nb_words = 8,
	.fuse_map = imx93_ele_fuse_map,
};

static struct ele_instance ele_imx91 = {
	.nb_banks = 64,
	.nb_words = 8,
	.fuse_map = imx91_ele_fuse_map,
};

static struct ele_instance ele_imx8ulp = {
	.nb_banks = 64,
	.nb_words = 8,
	.fuse_map = imx8ulp_ele_fuse_map,
};

static struct ele_instance ele_imx943 = {
	.nb_banks = 103,
	.nb_words = 8,
	.fuse_map = imx943_ele_fuse_map,
};

static struct ele_instance ele_imx952 = {
	.nb_banks = 77,
	.nb_words = 8,
	.fuse_map = imx952_ele_fuse_map,
};

static TEE_Result imx_ele_fuse_init(void)
{
	uint16_t lifecycle = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	switch (imx_soc_type()) {
	case SOC_MX8ULP:
		g_ele = &ele_imx8ulp;
		break;
	case SOC_MX93:
		g_ele = &ele_imx93;
		break;
	case SOC_MX91:
		g_ele = &ele_imx91;
		break;
	case SOC_MX95:
		g_ele = &ele_imx95;
		break;
	case SOC_MX943:
		g_ele = &ele_imx943;
		break;
	case SOC_MX952:
		g_ele = &ele_imx952;
		break;
	default:
		g_ele = NULL;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = imx_ele_get_device_lifecycle(&lifecycle);
	if (res)
		return res;

	g_ele->lifecycle = lifecycle;

	return TEE_SUCCESS;
}
driver_init(imx_ele_fuse_init);
