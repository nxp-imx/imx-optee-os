// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    imx_huk.c
 *
 * @brief   i.MX Hardware Unique Key generation.\n
 *          Call CAAM operation to generate the key derived
 *          from the master key
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#ifdef CFG_IMX_SNVS
#include <drivers/imx_snvs.h>
#endif
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <utee_defines.h>

/* Platform includes */
#include <imx.h>

/* Library i.MX includes */
#include <crypto_extension.h>

/* Local includes */

/**
 * @brief   Return a HW unique key value.\n
 *          On i.MX device, return a derivation of the Master Key
 *          by calling the CAAM Blob master key verification
 *          operation using a key modifier corresponding of the
 *          first 16 bytes of the Die ID
 *
 * @param[out] huk  HW Unique key
 */
void tee_otp_get_hw_unique_key(struct tee_hw_unique_key *huk)
{
	TEE_Result ret;

	struct nxpcrypt_buf cryptohuk = {0};

	/* Initialize the HUK value */
	memset(huk->data, 0, sizeof(huk->data));

#ifdef CFG_IMX_SNVS
	/* Select the OTPMK as Master Key */
	snvs_set_master_otpmk();
#endif

	cryptohuk.length = sizeof(huk->data);
	cryptohuk.data   = huk->data;

	ret = crypto_generate_huk(&cryptohuk);

	/*
	 * If the device is closed and there is an error
	 * during the Master key derivation, the device
	 * is not safe, hence we cannot boot
	 */
	if (imx_is_device_closed() && (ret != TEE_SUCCESS))
		panic();
}

