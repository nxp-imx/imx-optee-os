// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Definition of the Hash's OID
 */

/* Driver Crypto includes */
#include <drvcrypt_asn1_oid.h>

/*
 * Hash OID values
 */
const struct drvcrypt_oid drvcrypt_hash_oid[] = {
	/* empty entry */
	{ NULL, 0 },
	/* MD5 */
	{ OID_ID_MD5, OID_LEN(OID_ID_MD5) },
	/* SHA1 */
	{ OID_ID_SHA1, OID_LEN(OID_ID_SHA1) },
	/* SHA224 */
	{ OID_ID_SHA224, OID_LEN(OID_ID_SHA224) },
	/* SHA256 */
	{ OID_ID_SHA256, OID_LEN(OID_ID_SHA256) },
	/* SHA384 */
	{ OID_ID_SHA384, OID_LEN(OID_ID_SHA384) },
	/* SHA512 */
	{ OID_ID_SHA512, OID_LEN(OID_ID_SHA512) },
};
