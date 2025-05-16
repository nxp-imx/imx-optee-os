// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023, 2025 NXP
 */
#include <drivers/ele_extension.h>
#include <drivers/ele/ele.h>
#include <drivers/ele/key_store.h>
#include <drivers/ele/memutils.h>
#include <drivers/ele/sign_verify.h>
#include <drivers/imx_mu.h>
#include <ecc.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <rng_support.h>
#include <stdint.h>
#include <string_ext.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_types.h>
#include <util.h>
#include <utils_trace.h>

#define ELE_BASE_ADDR MU_BASE
#define ELE_BASE_SIZE MU_SIZE

#define ELE_COMMAND_SUCCEED 0xd6

#define ELE_CMD_SESSION_OPEN	    0x10
#define ELE_CMD_SESSION_CLOSE	    0x11
#define ELE_CMD_RNG_GET		    0xCD
#define ELE_CMD_START_RNG 0xA3
#define ELE_CMD_TRNG_STATE	    0xA4
#define ELE_CMD_GET_INFO	    0xDA
#define ELE_CMD_DERIVE_KEY	    0xA9
#define ELE_CMD_SAB_INIT	    0x17

#define IMX_ELE_TRNG_STATUS_READY 0x3
#define IMX_ELE_RNG_CTX_STATUS_READY 0x2

#define ELE_MU_IRQ 0x0

#define CACHELINE_SIZE 64

#define ELE_RNG_FLAGS_NO_RESEED 0x0000
#define ELE_RNG_FLAGS_NON_BLOCK_RESEED 0x0001
#define ELE_RNG_FLAGS_BLOCK_RESEED 0x0002

register_phys_mem_pgdir(MEM_AREA_IO_SEC, MU_BASE, MU_SIZE);

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the CRC.
 *
 * @msg MU message to hash
 */
uint32_t compute_crc(struct imx_mu_msg *msg)
{
	uint32_t crc = 0;
	uint8_t i = 0;
	uint32_t *payload = (uint32_t *)msg;

	assert(msg);

	for (i = 0; i < msg->header.size - 1; i++)
		crc ^= payload[i];

	return crc;
}

void update_crc(struct imx_mu_msg *msg)
{
	assert(msg);
	/*
	 * The CRC field is the last element of array. The size of the header
	 * is also subtracted from CRC computation.
	 */
	msg->data.u32[msg->header.size - 2] = compute_crc(msg);
}

/*
 * Return the given MU base address, depending on the MMU state.
 *
 * @pa MU physical base address
 * @sz MU size
 */
static vaddr_t imx_ele_init(paddr_t pa, size_t sz)
{
	static bool is_initialized;
	vaddr_t va = 0;

	assert(pa && sz);

	if (cpu_mmu_enabled())
		va = core_mmu_get_va(pa, MEM_AREA_IO_SEC, sz);
	else
		va = (vaddr_t)pa;

	if (!is_initialized) {
		imx_mu_init(va);
		is_initialized = true;
	}

	return va;
}

struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {
		.abort_code = (word & GENMASK_32(31, 16)) >> 16,
		.indication = (word & GENMASK_32(15, 8)) >> 8,
		.status = (word & GENMASK_32(7, 0)) >> 0,
	};

	return rsp;
}

enum ele_status {
	ELE_INVALID_ADDRESS = 0x02,
	ELE_INVALID_ID,
	ELE_INVALID_FLAG,
	ELE_ERROR_NVM_EXPORT,
	ELE_OUT_OF_MEMORY,
	ELE_UNKNOWN_HANDLE,
	ELE_KEY_STORE_AUTH_FAIL = 0x09,
	ELE_ROM_PING_FAILURE = 0x0A,
	ELE_KEY_NOT_USABLE = 0x0E,
	ELE_KEY_STORE_CONFLICT = 0x0F,
	ELE_MONOTONIC_MAX_UPDATE = 0x10,
	ELE_FEATURE_UNSUPPORTED,
	ELE_SERVICE_NOT_INIT = 0x13,
	ELE_FW_PING_FAILURE = 0x1A,
	ELE_KEY_NOT_SUPPORTED,
	ELE_CANT_DEL_PERM_KEY,
	ELE_FASTBOOT_DISABLE = 0x90,
	ELE_FASTBOOT_ILLEGAL,
	ELE_GEN_FW_AUTH_FAILURE,
	ELE_GEN_OEM_AUTH_FAILURE,
	ELE_FAST_IMAGE_VERIF_FAILURE,
	ELE_UNALIGNED_PAYLOAD = 0xA6,
	ELE_WRONG_SIZE,
	ELE_ENCRYPT_FAILURE,
	ELE_DECRYPT_FAILURE,
	ELE_OTP_PROG_FAILURE,
	ELE_OTP_LOCKED_FAILURE,
	ELE_OTP_INVALID_INDEX_FAILURE,
	ELE_TIMEOUT = 0xB0,
	ELE_BAD_PAYLOAD,
	ELE_WRONG_ADDRESS = 0xB4,
	ELE_DMA_FAILURE,
	ELE_DISABLED_FEATURE,
	ELE_MUST_ATTEST_FAILURE,
	ELE_RNG_NOT_STARTED,
	ELE_CRC_ERROR,
	ELE_AUTH_SKIPPED_OR_FAILED = 0xBB,
	ELE_INCONSISTENT_PARAMS,
	ELE_RNG_FAILURE,
	ELE_LOCKED_REGISTER_FAILURE,
	ELE_BAD_ID,
	ELE_INVALID_OPERATION = 0xC0,
	ELE_NON_SECURE_STATE,
	ELE_MSG_TRUNCATED,
	ELE_BAD_IMAGE_NUM,
	ELE_BAD_IMAGE_ADDRESS,
	ELE_BAD_IMAGE_PARAMS,
	ELE_BAD_IMAGE_TYPE,
	ELE_APC_ALREADY_ENABLED = 0xCB,
	ELE_RTC_ALREADY_ENABLED,
	ELE_WRONG_BOOT_MODE,
	ELE_OLD_VERSION,
	ELE_CSTM_FAILURE,
	ELE_CORRUPTED_SRK = 0xD0,
	ELE_INTERNAL_OUT_OF_MEMORY,
	ELE_MUST_SIGNED = 0xE0,
	ELE_NO_AUTHENTICATION = 0xEE,
	ELE_BAD_SRK_SET,
	ELE_BAD_SIGNATURE = 0xF0,
	ELE_BAD_HASH,
	ELE_INVALID_LIFECYCLE,
	ELE_PERMISSION_DENIED,
	ELE_INVALID_MESSAGE,
	ELE_BAD_VALUE,
	ELE_BAD_FUSE_ID,
	ELE_BAD_CONTAINER,
	ELE_BAD_VERSION,
	ELE_INVALID_KEY,
	ELE_BAD_KEY_HASH,
	ELE_NO_VALID_CONTAINER,
	ELE_BAD_CERTIFICATE,
	ELE_BAD_UID,
	ELE_BAD_MONOTONIC_COUNTER,
	ELE_ABORT = 0xFF
};

static TEE_Result ele_status_to_tee_result(uint32_t word)
{
	struct response_code rsp_code = {};

	rsp_code = get_response_code(word);
	if (rsp_code.status == ELE_COMMAND_SUCCEED)
		return TEE_SUCCESS;

	switch (rsp_code.indication) {
	case ELE_INTERNAL_OUT_OF_MEMORY:
	case ELE_OUT_OF_MEMORY:
		return TEE_ERROR_OUT_OF_MEMORY;
	case ELE_UNALIGNED_PAYLOAD:
	case ELE_WRONG_SIZE:
	case ELE_BAD_PAYLOAD:
	case ELE_INCONSISTENT_PARAMS:
	case ELE_BAD_ID:
	case ELE_BAD_IMAGE_NUM:
	case ELE_BAD_IMAGE_ADDRESS:
	case ELE_BAD_IMAGE_PARAMS:
	case ELE_BAD_IMAGE_TYPE:
	case ELE_BAD_SRK_SET:
	case ELE_BAD_SIGNATURE:
	case ELE_BAD_HASH:
	case ELE_INVALID_LIFECYCLE:
	case ELE_INVALID_MESSAGE:
	case ELE_BAD_VALUE:
	case ELE_BAD_FUSE_ID:
	case ELE_BAD_CONTAINER:
	case ELE_WRONG_BOOT_MODE:
	case ELE_BAD_VERSION:
	case ELE_INVALID_KEY:
	case ELE_BAD_KEY_HASH:
	case ELE_NO_VALID_CONTAINER:
	case ELE_BAD_CERTIFICATE:
	case ELE_BAD_UID:
	case ELE_BAD_MONOTONIC_COUNTER:
	case ELE_INVALID_ADDRESS:
	case ELE_INVALID_ID:
	case ELE_INVALID_FLAG:
		return TEE_ERROR_BAD_PARAMETERS;
	case ELE_PERMISSION_DENIED:
		return TEE_ERROR_ACCESS_DENIED;
	case ELE_DISABLED_FEATURE:
	case ELE_KEY_NOT_SUPPORTED:
	case ELE_FEATURE_UNSUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	default:
		break;
	}
	return TEE_ERROR_GENERIC;
}

TEE_Result imx_ele_call(struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	vaddr_t va = 0;

	assert(msg);

	if (msg->header.tag != ELE_REQUEST_TAG) {
		EMSG("Request has invalid tag: %#"PRIx8" instead of %#"PRIx8,
		     msg->header.tag, ELE_REQUEST_TAG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	va = imx_ele_init(ELE_BASE_ADDR, ELE_BASE_SIZE);
	if (!va) {
		EMSG("Fail to get base address");
		return TEE_ERROR_GENERIC;
	}

	ele_trace_print_msg(*msg);

	res = imx_mu_call(va, msg, true);
	if (res) {
		EMSG("Failed to transmit message: %#" PRIx32, res);
		return res;
	}

	if (msg->header.tag != ELE_RESPONSE_TAG) {
		EMSG("Response has invalid tag: %#" PRIx8
		     " instead of %#" PRIx8,
		     msg->header.tag, ELE_RESPONSE_TAG);
		return TEE_ERROR_GENERIC;
	}

	ele_trace_print_msg(*msg);

	return ele_status_to_tee_result(msg->data.u32[0]);
}

TEE_Result imx_ele_session_open(uint32_t *session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct open_session_cmd {
		uint8_t rsvd1;
		uint8_t interrupt_num;
		uint16_t rsvd2;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t rsvd3;
	} __packed cmd = {
		.rsvd1 = 0,
		.interrupt_num = ELE_MU_IRQ,
		.rsvd2 = 0,
		.priority = 0,
		.op_mode = 0,
		.rsvd3 = 0,
	};
	struct open_session_rsp {
		uint32_t rsp_code;
		uint32_t session_handle;
	} rsp = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_OPEN,
	};

	assert(session_handle);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*session_handle = rsp.session_handle;

	return TEE_SUCCESS;
}

TEE_Result imx_ele_session_close(uint32_t session_handle)
{
	struct close_session_cmd {
		uint32_t session_handle;
	} cmd = {
		.session_handle = session_handle,
	};
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

TEE_Result imx_ele_get_device_info(struct get_info_rsp *rsp)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf output = { };
	struct {
		uint32_t addr_msb;
		uint32_t addr_lsb;
		uint16_t size;
	} __packed cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_GET_INFO,
	};

	if (!rsp)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&output, NULL, sizeof(*rsp));
	if (res)
		goto out;

	cmd.addr_msb = output.paddr_msb;
	cmd.addr_lsb = output.paddr_lsb;
	cmd.size = sizeof(*rsp);

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	res = imx_ele_buf_copy(&output, (uint8_t *)rsp, sizeof(*rsp));
out:
	imx_ele_buf_free(&output);

	return res;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	static uint32_t uid[4];
	static bool is_fetched;
	struct get_info_rsp rsp = { };

	assert(buffer && len);

	if (!is_fetched) {
		if (imx_ele_get_device_info(&rsp))
			panic("Fail to get the device UID");

		memcpy(uid, rsp.uid, MIN(sizeof(rsp.uid), len));
		is_fetched = true;
	}

	memcpy(buffer, uid, MIN(sizeof(uid), len));

	return 0;
}

/*
 * Initialize EdgeLock Enclave services
 */
static TEE_Result __maybe_unused imx_ele_sab_init(void)
{
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SAB_INIT,
	};

	return imx_ele_call(&msg);
}

TEE_Result imx_ele_get_global_session_handle(uint32_t *session_handle)
{
	static uint32_t imx_ele_session_handle;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!session_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	if (imx_ele_session_handle) {
		res = TEE_SUCCESS;
		goto out;
	}

	res = imx_ele_session_open(&imx_ele_session_handle);
	if (res) {
		EMSG("Failed to open global session");
		return res;
	}

out:
	*session_handle = imx_ele_session_handle;
	return res;
}

static TEE_Result imx_ele_global_init(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = imx_ele_ecc_init();
	if (res)
		EMSG("ELE ECC driver registration failed");

	return res;
}

driver_init(imx_ele_global_init);

#if defined(CFG_MX93) || defined(CFG_MX91) || defined(CFG_MX95) || \
	defined(CFG_MX943) || defined(CFG_MX952)
/*
 * Key buffer pointer must be align on a cache line
 * as cache invalidate is done after key derivation.
 * As key derivation can be done in secure OnChip RAM buffer,
 * to prevent secret key leak in DDR, we could not used
 * a temporary allocated aligned imx_ele_buffer to derive a key.
 * Cause it would expose the derived key in DDR.
 */
TEE_Result imx_ele_derive_key(const uint8_t *ctx, size_t ctx_size, uint8_t *key,
			      size_t key_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t msb = 0;
	uint32_t lsb = 0;
	paddr_t pa = 0;
	struct key_derive_cmd {
		uint32_t key_addr_msb;
		uint32_t key_addr_lsb;
		uint32_t ctx_addr_msb;
		uint32_t ctx_addr_lsb;
		uint16_t key_size;
		uint16_t ctx_size;
		uint32_t crc;
	} __packed cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_DERIVE_KEY,
	};
	struct imx_ele_buf ele_ctx = { };

	assert(ctx && key);

	/*
	 * As we do a cache invalidate on key we must ensure that the buffer
	 * is aligned on a cache line
	 */
	if (!IS_ALIGNED((uintptr_t)key, CACHELINE_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&ele_ctx, ctx, ctx_size);
	if (res)
		return res;

	pa = virt_to_phys((void *)key);
	/*
	 * ELE need address align on 4 bytes.
	 * Check is needed as no copy could be done.
	 * Key buffer is potentially allocated in
	 * OCRAM and must not be exposed to DDR.
	 */
	if (!IS_ALIGNED_WITH_TYPE(pa, uint32_t)) {
		EMSG("Key address is not aligned");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Intermediate msb and lsb values are needed. Directly using
	 * key_addr_msb and key_addr_lsb might be unaligned because of the
	 * __packed attribute of key_derive_cmd {}
	 */
	reg_pair_from_64((uint64_t)pa, &msb, &lsb);

	cmd.key_addr_lsb = lsb;
	cmd.key_addr_msb = msb;
	cmd.key_size = key_size;

	cmd.ctx_addr_lsb = ele_ctx.paddr_lsb;
	cmd.ctx_addr_msb = ele_ctx.paddr_msb;
	cmd.ctx_size = ctx_size;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	memzero_explicit(key, key_size);
	cache_operation(TEE_CACHEFLUSH, (void *)key, key_size);

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	cache_operation(TEE_CACHEINVALIDATE, (void *)key, key_size);
out:
	imx_ele_buf_free(&ele_ctx);

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	static const char pattern[] = "TEE_for_HUK_ELE";
	static uint8_t key[HW_UNIQUE_KEY_LENGTH] __aligned(CACHELINE_SIZE);
	static bool is_fetched;

	if (is_fetched)
		goto out;

	if (imx_ele_derive_key((const uint8_t *)pattern, sizeof(pattern), key,
			       sizeof(key)))
		panic("Fail to get HUK from ELE");

	is_fetched = true;
out:
	memcpy(hwkey->data, key,
	       MIN(sizeof(key), (size_t)HW_UNIQUE_KEY_LENGTH));

	return TEE_SUCCESS;
}

/*
 * Get the current state of the ELE TRNG
 */
static TEE_Result imx_ele_rng_get_trng_state(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_get_trng_state_msg_rsp {
		uint32_t rsp_code;
		uint8_t trng_state;
		uint8_t ele_rng_ctx_state;
	} __packed rsp = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_TRNG_STATE,
	};

	res = imx_ele_call(&msg);
	if (res)
		return res;

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	if (rsp.trng_state != IMX_ELE_TRNG_STATUS_READY ||
	    rsp.ele_rng_ctx_state != IMX_ELE_RNG_CTX_STATUS_READY)
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

/*
 * Initialize ELE RNG context
 */
static TEE_Result imx_ele_start_rng(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_BASELINE,
		.header.size = 1,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_START_RNG,
	};

	res = imx_ele_call(&msg);
	if (res)
		return res;

	return TEE_SUCCESS;
}

/*
 * Get random data from the EdgeLock Enclave.
 *
 * This function can be called when the MMU is off or on.
 * virtual/physical address translation and cache maintenance
 * is performed if needed.
 *
 * @buffer: data output
 * @size: RNG data size
 */
static TEE_Result imx_ele_rng_get_random(uint8_t *buffer, size_t size,
					 uint16_t flags)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf rng = { };
	struct rng_get_random_cmd {
		uint16_t rsvd;
		uint16_t flags;
		uint32_t addr;
		uint32_t size;
	} cmd = { };
	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};

	if (!buffer || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	cmd.flags = flags;

	if (cpu_mmu_enabled()) {
		res = imx_ele_buf_alloc(&rng, NULL, size);
		if (res != TEE_SUCCESS)
			return res;

		cmd.addr = rng.paddr;
	} else {
		paddr_t pa = (paddr_t)buffer;

		if (!IS_ALIGNED_WITH_TYPE(pa, uint32_t))
			return TEE_ERROR_BAD_PARAMETERS;

		cmd.addr = pa;
	}

	cmd.size = (uint32_t)size;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res)
		goto out;

	if (cpu_mmu_enabled())
		res = imx_ele_buf_copy(&rng, buffer, size);
out:
	imx_ele_buf_free(&rng);

	return res;
}

unsigned long plat_get_aslr_seed(void)
{
	uint64_t timeout = timeout_init_us(10 * 1000);
	unsigned long __aligned(CACHELINE_SIZE) aslr = 0;

	if (imx_ele_start_rng())
		panic("Start RNG failed");

	/*
	 * Check the current TRNG state of the ELE. The TRNG must be
	 * started with a command earlier in the boot to allow the TRNG
	 * to generate enough entropy.
	 */
	while (imx_ele_rng_get_trng_state() == TEE_ERROR_BUSY)
		if (timeout_elapsed(timeout))
			panic("ELE RNG is busy");

	if (imx_ele_rng_get_random((uint8_t *)&aslr, sizeof(aslr),
				   ELE_RNG_FLAGS_NO_RESEED))
		panic("Cannot retrieve random data from ELE");

	return aslr;
}

#ifndef CFG_WITH_SOFTWARE_PRNG
TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return imx_ele_rng_get_random((uint8_t *)buf, len,
				      ELE_RNG_FLAGS_NO_RESEED);
}
#endif /* CFG_WITH_SOFTWARE_PRNG */
#else
TEE_Result imx_ele_derive_key(const uint8_t *ctx __unused,
			      size_t ctx_size __unused, uint8_t *key __unused,
			      size_t key_size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_MX93 || CFG_MX91 || CFG_MX95 || CFG_MX943 */