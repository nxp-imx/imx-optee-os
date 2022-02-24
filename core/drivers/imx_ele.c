// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>

#define ELE_VER			    0x06
#define ELE_TAG			    0x17
#define ELE_CMD_READ_FUSE	    0x97
#define ELE_CMD_READ_FUSE_DEVICE_ID 0x01
#define ELE_CMD_SUCCESS		    0xD6

#define UID_SIZE (4 * sizeof(uint32_t))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, MU_BASE, MU_SIZE);

static TEE_Result imx_ele_get_device_id(uint32_t uid[])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t va = 0;
	struct imx_mu_msg msg = {
		.header.version = 0x06,
		.header.size = 2,
		.header.tag = ELE_TAG,
		.header.command = ELE_CMD_READ_FUSE,
		.data.u32[0] = ELE_CMD_READ_FUSE_DEVICE_ID,
	};

	va = core_mmu_get_va(MU_BASE, MEM_AREA_IO_SEC, MU_SIZE);
	if (!va)
		return TEE_ERROR_GENERIC;

	imx_mu_init(va);

	res = imx_mu_call(va, &msg, true);
	if (res)
		return res;

	if (msg.header.command == ELE_CMD_READ_FUSE && msg.header.size == 0x7 &&
	    msg.data.u32[0] == ELE_CMD_SUCCESS) {
		uid[0] = msg.data.u32[1];
		uid[1] = msg.data.u32[2];
		uid[2] = msg.data.u32[3];
		uid[3] = msg.data.u32[4];

		return TEE_SUCCESS;
	}

	return TEE_ERROR_COMMUNICATION;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t uid[UID_SIZE / sizeof(uint32_t)] = {};

	res = imx_ele_get_device_id(uid);
	if (res) {
		EMSG("Error while getting die ID");
		return -1;
	}

	memcpy(buffer, uid, MIN(UID_SIZE, len));

	return 0;
}
