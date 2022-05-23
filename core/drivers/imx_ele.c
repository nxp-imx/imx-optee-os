// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>

/* Definitions for communication protocol */
#define ELE_VERSION	    0x07
#define ELE_COMMAND_SUCCEED 0x00
#define ELE_COMMAND_FAILED  0x29
#define ELE_REQUEST_TAG	    0x17
#define ELE_RESPONSE_TAG    0xe1

#define UID_SIZE (4 * sizeof(uint32_t))

/* Definitions for ELE API */
#define ELE_CMD_SESSION_OPEN  0x10
#define ELE_CMD_SESSION_CLOSE 0x11
#define ELE_CMD_SESSION_DEVICE_INFO 0x16
#define ELE_CMD_RNG_OPEN  0x20
#define ELE_CMD_RNG_CLOSE 0x21
#define ELE_CMD_RNG_GET	  0x22

#define ELE_MU_ID  0x2
#define ELE_MU_IRQ 0x0
#define ELE_MU_DID 0x7

#define CRC_TO_COMPUTE 0xdeadbeef

#define SIZE_CRC_REQUIRED 4

#define SIZE_MSG(_msg) size_msg(sizeof(_msg))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, MU_BASE, MU_SIZE);

struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __packed;

static vaddr_t imx_ele_va;

static void print_rsp_code(const struct response_code rsp __maybe_unused)
{
	IMSG("Response status 0x%" PRIx8 ", rating 0x%" PRIx8 " (ext 0x%" PRIx16
	     ")",
	     rsp.status, rsp.rating, rsp.rating_extension);
}

static void print_msg_header(const struct imx_mu_msg_header hdr __maybe_unused)
{
	IMSG("Header vers 0x%" PRIx8 ", size %" PRId8 ", tag 0x%" PRIx8
	     ", cmd 0x%" PRIx8,
	     hdr.version, hdr.size, hdr.tag, hdr.command);
}

static void dump_message(const struct imx_mu_msg *msg __maybe_unused)
{
	size_t i = 0;
	size_t size = msg->header.size;
	uint32_t *data __maybe_unused = (uint32_t *)msg;

	DMSG("Dump of message %p(%" PRIu64 ")", data, size);
	for (i = 0; i < size; i++)
		DMSG("word %" PRIu64 ": %" PRIx32, i, data[i]);
}

static size_t size_msg(size_t cmd)
{
	size_t words = ROUNDUP(cmd, sizeof(uint32_t)) / sizeof(uint32_t);

	/* Add the header size */
	words = words + 1;

	/* If the message if bigger than 4 word, a CRC is needed */
	if (words > SIZE_CRC_REQUIRED)
		words = words + 1;

	return words;
}

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the crc
 *
 * msg: MU message to hash
 */
static uint32_t compute_crc(const struct imx_mu_msg *msg)
{
	uint32_t crc = 0;
	size_t i = 0;
	/* The CRC is included in the size */
	size_t size = msg->header.size - 1;
	uint32_t *payload = (uint32_t *)msg;

	for (i = 0; i < size; i++)
		crc ^= payload[i];

	return crc;
}

/*
 * The CRC is the last word of the message
 *
 * msg: MU message to hash
 */
static void update_crc(struct imx_mu_msg *msg)
{
	msg->data.u32[msg->header.size - 2] = compute_crc(msg);
}

/*
 * EdgeLock Enclave and MU driver initialization.
 */
static TEE_Result imx_ele_init(void)
{
	vaddr_t va = 0;

	va = core_mmu_get_va(MU_BASE, MEM_AREA_IO_SEC, MU_SIZE);
	if (!va) {
		EMSG("Failed to map ele mu address");
		return TEE_ERROR_GENERIC;
	}

	imx_mu_init(va);

	imx_ele_va = va;

	return TEE_SUCCESS;
}
service_init(imx_ele_init);

static struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {};

	rsp.rating_extension = (word & GENMASK_32(31, 16)) >> 16;
	rsp.rating = (word & GENMASK_32(15, 8)) >> 8;
	rsp.status = (word & GENMASK_32(7, 0)) >> 0;

	return rsp;
}

/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg: MU message
 */
static TEE_Result imx_ele_call(struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct response_code rsp = {};

	if (msg->header.tag != ELE_REQUEST_TAG) {
		EMSG("Request has invalid tag: %" PRIx8 " instead of %" PRIx8,
		     msg->header.tag, ELE_REQUEST_TAG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = imx_mu_call(imx_ele_va, msg, true);
	if (res) {
		EMSG("Failed to transmit message: %" PRIx32, res);
		print_msg_header(msg->header);
		dump_message(msg);
		return res;
	}

	rsp = get_response_code(msg->data.u32[0]);

	if (msg->header.tag != ELE_RESPONSE_TAG) {
		EMSG("Response has invalid tag: %" PRIx8 " instead of %" PRIx8,
		     msg->header.tag, ELE_RESPONSE_TAG);
		print_msg_header(msg->header);
		return TEE_ERROR_GENERIC;
	}

	if (rsp.status == ELE_COMMAND_FAILED) {
		EMSG("Command has failed");
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	/* The rating can be different in success and failing case */
	if (rsp.rating != 0) {
		EMSG("Command has invalid rating: %" PRIx8, rsp.rating);
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Get device information from EdgeLock Enclave
 *
 * @session_handle: EdgeLock Enclave session handler
 * @user_sab_id: user SAB
 * @uid_w0: Chip UUID word 0
 * @uid_w1: Chip UUID word 1
 * @uid_w2: Chip UUID word 2
 * @uid_w3: Chip UUID word 3
 * @life_cycle: Chip current lifecycle state
 * @monotonic_counter: Chip monotonic counter
 * @ele_version: EdgeLock enclave version
 * @ele_version_ext: EdgeLock enclave version ext
 * @fips_mode: EdgeLock enclave FIPS mode
 */
static TEE_Result imx_ele_session_get_device_info(
	uint32_t session_handle, uint32_t *user_sab_id, uint32_t *uid_w0,
	uint32_t *uid_w1, uint32_t *uid_w2, uint32_t *uid_w3,
	uint16_t *life_cycle, uint16_t *monotonic_counter,
	uint32_t *ele_version, uint32_t *ele_version_ext, uint8_t *fips_mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct session_get_device_info_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};

	struct session_get_device_info_rsp {
		uint32_t rsp_code;
		uint32_t user_sab_id;
		uint32_t chip_uid_w0;
		uint32_t chip_uid_w1;
		uint32_t chip_uid_w2;
		uint32_t chip_uid_w3;
		uint16_t chip_life_cycle;
		uint16_t chip_monotonic_counter;
		uint32_t ele_version;
		uint32_t ele_version_ext;
		uint8_t fips_mode;
		uint8_t reserved[3];
		uint32_t crc;
	} __packed *rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_DEVICE_INFO,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	rsp = (void *)msg.data.u32;

	if (compute_crc(&msg) != rsp->crc)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (user_sab_id)
		*user_sab_id = rsp->user_sab_id;
	if (uid_w0)
		*uid_w0 = rsp->chip_uid_w0;
	if (uid_w1)
		*uid_w1 = rsp->chip_uid_w1;
	if (uid_w2)
		*uid_w2 = rsp->chip_uid_w2;
	if (uid_w3)
		*uid_w3 = rsp->chip_uid_w3;
	if (life_cycle)
		*life_cycle = rsp->chip_life_cycle;
	if (monotonic_counter)
		*monotonic_counter = rsp->chip_monotonic_counter;
	if (ele_version)
		*ele_version = rsp->ele_version;
	if (ele_version_ext)
		*ele_version_ext = rsp->ele_version_ext;
	if (fips_mode)
		*fips_mode = rsp->fips_mode;

	return TEE_SUCCESS;
}

/*
 * Open a session with EdgeLock Enclave. It return a session handler.
 *
 * @session_handle: EdgeLock Enclave session handler
 */
static TEE_Result imx_ele_session_open(uint32_t *session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct open_session_cmd {
		uint8_t mu_id;
		uint8_t interrupt_num;
		uint8_t tz;
		uint8_t did;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t reserved;
	} __packed cmd = {
		.mu_id = ELE_MU_ID,
		.interrupt_num = ELE_MU_IRQ,
		.tz = 0,
		.did = ELE_MU_DID,
		.priority = 0,
		.op_mode = 0,
		.reserved = 0,
	};

	struct open_session_rsp {
		uint32_t rsp_code;
		uint32_t session_handle;
	} *rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_OPEN,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	rsp = (void *)msg.data.u32;

	if (session_handle)
		*session_handle = rsp->session_handle;

	return TEE_SUCCESS;
}

/*
 * Close a session with EdgeLock Enclave.
 *
 * @session_handle: EdgeLock Enclave session handler
 */
static TEE_Result imx_ele_session_close(uint32_t session_handle)
{
	struct close_session_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

/*
 * Open a RNG session with EdgeLock Enclave.
 *
 * @session_handle: EdgeLock Enclave session handler
 * @buffer: Output memory for the RNG session transactions
 * @rng_handle: EdgeLock Enclave RNG handler
 */
static TEE_Result imx_ele_rng_open(uint32_t session_handle, paddr_t buffer,
				   uint32_t *rng_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_open_cmd {
		uint32_t session_handle;
		uint32_t msbi;
		uint32_t msbo;
		uint8_t flags;
		uint8_t reserved[3];
		uint32_t crc;
	} __packed cmd = {
		.session_handle = session_handle,
		.msbi = 0,
		.msbo = (uint64_t)buffer >> 32,
		.flags = 0,
		.reserved = {},
		.crc = CRC_TO_COMPUTE,
	};

	struct rng_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t rng_handle;
	} *rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_OPEN,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get open rng session");
		return res;
	}

	rsp = (void *)msg.data.u32;

	if (rng_handle)
		*rng_handle = rsp->rng_handle;

	return TEE_SUCCESS;
}

/*
 * Close RNG session with EdgeLock Enclave.
 *
 * @rng_handle: EdgeLock Enclave RNG handler
 */
static TEE_Result imx_ele_rng_close(uint32_t rng_handle)
{
	struct rng_close_cmd {
		uint32_t rng_handle;
	} cmd = {
		.rng_handle = rng_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

/*
 * Get random data from the EdgeLock Enclave
 *
 * @rng_handle: EdgeLock Enclave RNG handler
 * @buffer: RNG data output
 * @size: RNG data size
 */
static TEE_Result imx_ele_rng_get_random(uint32_t rng_handle, paddr_t buffer,
					 size_t size)
{
	struct rng_get_random_cmd {
		uint32_t rng_handle;
		uint32_t out_addr;
		uint32_t out_size;
		uint32_t crc;
	} cmd = {
		.rng_handle = rng_handle,
		.out_addr = (uint64_t)buffer & GENMASK_32(31, 0),
		.out_size = (uint32_t)size,
		.crc = CRC_TO_COMPUTE,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = SIZE_MSG(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	return imx_ele_call(&msg);
}

unsigned long plat_get_aslr_seed(void)
{
	uint32_t session_handle = 0;
	uint32_t rng_handle = 0;
	unsigned long aslr = 0;

	/*
	 * In this function, we assume that virtual address is also a physical
	 * address. Make sure the MMU is disabled before going further.
	 */
	assert(!cpu_mmu_enabled());

	if (imx_ele_init())
		goto err;

	if (imx_ele_session_open(&session_handle))
		goto err;

	if (imx_ele_rng_open(session_handle, (paddr_t)aslr, &rng_handle))
		goto err;

	if (imx_ele_rng_get_random(rng_handle, (paddr_t)&aslr, sizeof(aslr)))
		goto err;

	if (imx_ele_rng_close(rng_handle))
		goto err;

	if (imx_ele_session_close(session_handle))
		goto err;

	return aslr;
err:
	panic("Fail to the seed the ASLR");
	return 0;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t session_handle = 0;
	uint32_t uid[UID_SIZE] = {};

	res = imx_ele_session_open(&session_handle);
	if (res)
		goto err;

	res = imx_ele_session_get_device_info(session_handle, NULL, &uid[0],
					      &uid[1], &uid[2], &uid[3], NULL,
					      NULL, NULL, NULL, NULL);
	if (res)
		goto err;

	res = imx_ele_session_close(session_handle);
	if (res)
		goto err;

	/*
	 * In the device info array return by the ELE, the words 2, 3, 4 and 5
	 * are the device UID.
	 */
	memcpy(buffer, uid, MIN(UID_SIZE, len));
	DHEXDUMP(uid, UID_SIZE);

	return 0;
err:
	panic("Fail to get the device UID");
	return -1;
}
