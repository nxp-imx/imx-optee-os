/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef _IMX_TRUSTED_ARM_CE_H
#define _IMX_TRUSTED_ARM_CE_H

#include <kernel/thread_arch.h>
#include <sm/optee_smc.h>
#include <tee_api_types.h>

/*
 * Do AES CBC Encryption
 *
 * Call register usage:
 * a0	SMC Function ID, IMX_SMC_ENCRYPT_CBC
 * a1	Key ids
 * a2	Initial vector physical address
 * a3	Input buffer physical address
 * a4	Input buffer length
 * a5	Output buffer physical address
 * a6	Output buffer length
 * a7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1-3	Not used
 * a4-7	Preserved
 */
#define IMX_SMC_FUNCID_ENCRYPT_CBC U(20)
#define IMX_SMC_ENCRYPT_CBC OPTEE_SMC_FAST_CALL_VAL(IMX_SMC_FUNCID_ENCRYPT_CBC)

/*
 * Do AES CBC Decryption
 *
 * Call register usage:
 * a0	SMC Function ID, IMX_SMC_DECRYPT_CBC
 * a1	Key ids
 * a2	Initial vector physical address
 * a3	Input buffer physical address
 * a4	Input buffer length
 * a5	Output buffer physical address
 * a6	Output buffer length
 * a7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1-3	Not used
 * a4-7	Preserved
 */
#define IMX_SMC_FUNCID_DECRYPT_CBC U(21)
#define IMX_SMC_DECRYPT_CBC OPTEE_SMC_FAST_CALL_VAL(IMX_SMC_FUNCID_DECRYPT_CBC)

/*
 * Do AES XTS Encryption
 *
 * Call register usage:
 * a0	SMC Function ID, IMX_SMC_ENCRYPT_XTS
 * a1	Key ids
 * a2	Initial vector physical address
 * a3	Input buffer physical address
 * a4	Input buffer length
 * a5	Output buffer physical address
 * a6	Output buffer length
 * a7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1-3	Not used
 * a4-7	Preserved
 */
#define IMX_SMC_FUNCID_ENCRYPT_XTS U(22)
#define IMX_SMC_ENCRYPT_XTS OPTEE_SMC_FAST_CALL_VAL(IMX_SMC_FUNCID_ENCRYPT_XTS)

/*
 * Do AES XTS Decryption
 *
 * Call register usage:
 * a0	SMC Function ID, IMX_SMC_DECRYPT_XTS
 * a1	Key ids
 * a2	Initial vector physical address
 * a3	Input buffer physical address
 * a4	Input buffer length
 * a5	Output buffer physical address
 * a6	Output buffer length
 * a7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1-3	Not used
 * a4-7	Preserved
 */
#define IMX_SMC_FUNCID_DECRYPT_XTS U(23)
#define IMX_SMC_DECRYPT_XTS OPTEE_SMC_FAST_CALL_VAL(IMX_SMC_FUNCID_DECRYPT_XTS)

/*
 * Trusted ARM CE aes cbc Fast SMC call
 *
 * @args: SMC call arguments
 * @encrypt: true for encryption, false otherwise
 */
TEE_Result imx_smc_cipher_cbc(struct thread_smc_args *args, bool encrypt);

/*
 * Trusted ARM CE aes xts Fast SMC call
 *
 * @args: SMC call arguments
 * @encrypt: true for encryption, false otherwise
 */
TEE_Result imx_smc_cipher_xts(struct thread_smc_args *args, bool encrypt);

#endif /* _IMX_TRUSTED_ARM_CE_H */
