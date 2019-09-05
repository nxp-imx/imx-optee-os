/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM driver trace include file.
 *         Definition of the internal driver trace macros.
 */

#ifndef __CAAM_TRACE_H__
#define __CAAM_TRACE_H__

#include <trace.h>
#include <util.h>

/*
 * Debug Macros function of CAAM Debug Level setting
 * The CFG_CAAM_DBG is a bit mask 32 bits value defined
 * as followed:
 */
#define DBG_TRACE_HAL     BIT32(0)  /* HAL trace */
#define DBG_TRACE_CTRL    BIT32(1)  /* Controller trace */
#define DBG_TRACE_MEM     BIT32(2)  /* Memory utility trace */
#define DBG_TRACE_SGT     BIT32(3)  /* Scatter Gather trace */
#define DBG_TRACE_PWR     BIT32(4)  /* Power trace */
#define DBG_TRACE_JR      BIT32(5)  /* Job Ring trace */
#define DBG_DESC_JR       BIT32(6)  /* Job Ring dump descriptor */
#define DBG_TRACE_RNG     BIT32(7)  /* RNG trace */
#define DBG_DESC_RNG      BIT32(8)  /* RNG dump descriptor */
#define DBG_TRACE_HASH    BIT32(9)  /* Hash trace */
#define DBG_DESC_HASH     BIT32(10) /* Hash dump descriptor */
#define DBG_BUF_HASH      BIT32(11) /* Hash dump Buffer */
#define DBG_TRACE_BLOB    BIT32(12) /* BLOB trace */
#define DBG_DESC_BLOB     BIT32(13) /* BLOB dump descriptor */
#define DBG_BUF_BLOB      BIT32(14) /* BLOB dump Buffer */
#define DBG_TRACE_CIPHER  BIT32(15) /* Cipher trace */
#define DBG_DESC_CIPHER   BIT32(16) /* Cipher dump descriptor */
#define DBG_BUF_CIPHER    BIT32(17) /* Cipher dump Buffer */
#define DBG_TRACE_ECC     BIT32(18) /* ECC trace */
#define DBG_DESC_ECC      BIT32(19) /* ECC dump descriptor */
#define DBG_BUF_ECC       BIT32(20) /* ECC dump Buffer */
#define DBG_TRACE_RSA     BIT32(21) /* RSA trace */
#define DBG_DESC_RSA      BIT32(22) /* RSA dump descriptor */
#define DBG_BUF_RSA       BIT32(23) /* RSA dump Buffer */
#define DBG_TRACE_MP      BIT32(24) /* MP trace */
#define DBG_DESC_MP       BIT32(25) /* MP dump descriptor */
#define DBG_BUF_MP        BIT32(26) /* MP dump Buffer */

/* HAL */
#if (CFG_CAAM_DBG & DBG_TRACE_HAL)
#define HAL_TRACE DRV_TRACE
#else
#define HAL_TRACE(...)
#endif

/* Controller */
#if (CFG_CAAM_DBG & DBG_TRACE_CTRL)
#define CTRL_TRACE DRV_TRACE
#else
#define CTRL_TRACE(...)
#endif

/* Memory Utility */
#if (CFG_CAAM_DBG & DBG_TRACE_MEM)
#define MEM_TRACE DRV_TRACE
#else
#define MEM_TRACE(...)
#endif

/* Scatter Gether Table */
#if (CFG_CAAM_DBG & DBG_TRACE_SGT)
#define SGT_TRACE DRV_TRACE
#else
#define SGT_TRACE(...)
#endif

/* Power */
#if (CFG_CAAM_DBG & DBG_TRACE_PWR)
#define PWR_TRACE DRV_TRACE
#else
#define PWR_TRACE(...)
#endif

/* Job Ring */
#if (CFG_CAAM_DBG & DBG_TRACE_JR)
#define JR_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_JR)
#define JR_DUMPDESC(desc)                                                      \
	do {                                                                   \
		JR_TRACE("Descriptor");                                        \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define JR_DUMPDESC(desc)
#endif
#else
#define JR_TRACE(...)
#define JR_DUMPDESC(desc)
#endif

/* RNG */
#if (CFG_CAAM_DBG & DBG_TRACE_RNG)
#define RNG_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_RNG)
#define RNG_DUMPDESC(desc)                                                     \
	do {                                                                   \
		RNG_TRACE("RNG Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define RNG_DUMPDESC(desc)
#endif
#else
#define RNG_TRACE(...)
#define RNG_DUMPDESC(desc)
#endif

/* Hash */
#if (CFG_CAAM_DBG & DBG_TRACE_HASH)
#define HASH_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_HASH)
#define HASH_DUMPDESC(desc)                                                    \
	do {                                                                   \
		HASH_TRACE("HASH Descriptor");                                 \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define HASH_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_HASH)
#define HASH_DUMPBUF DRV_DUMPBUF
#else
#define HASH_DUMPBUF(...)
#endif
#else
#define HASH_TRACE(...)
#define HASH_DUMPDESC(desc)
#define HASH_DUMPBUF(...)
#endif

/* BLOB */
#if (CFG_CAAM_DBG & DBG_TRACE_BLOB)
#define BLOB_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_BLOB)
#define BLOB_DUMPDESC(desc)                                                    \
	do {                                                                   \
		BLOB_TRACE("BLOB Descriptor");                                 \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define BLOB_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_BLOB)
#define BLOB_DUMPBUF DRV_DUMPBUF
#else
#define BLOB_DUMPBUF(...)
#endif
#else
#define BLOB_TRACE(...)
#define BLOB_DUMPDESC(desc)
#define BLOB_DUMPBUF(...)
#endif

/* Cipher */
#if (CFG_CAAM_DBG & DBG_TRACE_CIPHER)
#define CIPHER_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_CIPHER)
#define CIPHER_DUMPDESC(desc)                                                  \
	do {                                                                   \
		CIPHER_TRACE("CIPHER Descriptor");                             \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define CIPHER_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_CIPHER)
#define CIPHER_DUMPBUF DRV_DUMPBUF
#else
#define CIPHER_DUMPBUF(...)
#endif
#else
#define CIPHER_TRACE(...)
#define CIPHER_DUMPDESC(desc)
#define CIPHER_DUMPBUF(...)
#endif

/* ECC */
#if (CFG_CAAM_DBG & DBG_TRACE_ECC)
#define ECC_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_ECC)
#define ECC_DUMPDESC(desc)                                                     \
	do {                                                                   \
		ECC_TRACE("ECC Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define ECC_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_ECC)
#define ECC_DUMPBUF DRV_DUMPBUF
#else
#define ECC_DUMPBUF(...)
#endif
#else
#define ECC_TRACE(...)
#define ECC_DUMPDESC(desc)
#define ECC_DUMPBUF(...)
#endif

/* RSA */
#if (CFG_CAAM_DBG & DBG_TRACE_RSA)
#define RSA_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_RSA)
#define RSA_DUMPDESC(desc)                                                     \
	do {                                                                   \
		RSA_TRACE("RSA Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define RSA_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_RSA)
#define RSA_DUMPBUF DRV_DUMPBUF
#else
#define RSA_DUMPBUF(...)
#endif
#else
#define RSA_TRACE(...)
#define RSA_DUMPDESC(desc)
#define RSA_DUMPBUF(...)
#endif

/* MP */
#if (CFG_CAAM_DBG & DBG_TRACE_MP)
#define MP_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_MP)
#define MP_DUMPDESC(desc)                                                      \
	do {                                                                   \
		MP_TRACE("MP Descriptor");                                     \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define MP_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_MP)
#define MP_DUMPBUF DRV_DUMPBUF
#else
#define MP_DUMPBUF(...)
#endif
#else
#define MP_TRACE(...)
#define MP_DUMPDESC(desc)
#define MP_DUMPBUF(...)
#endif

#if (TRACE_LEVEL >= TRACE_DEBUG)
#define DRV_TRACE(...)                                                         \
	trace_printf(__func__, __LINE__, TRACE_DEBUG, true, __VA_ARGS__)
#define DRV_DUMPDESC(desc) dump_desc(desc)

#define DRV_DUMPBUF(title, buf, len)                                           \
	do {                                                                   \
		__typeof__(buf) _buf = (buf);                                  \
		__typeof__(len) _len = (len);                                  \
									       \
		DRV_TRACE("%s @%p : %zu", title, _buf, _len);                  \
		dhex_dump(NULL, 0, 0, _buf, _len);                             \
	} while (0)

#else
#define DRV_TRACE(...)
#define DRV_DUMPDESC(...)
#define DRV_DUMPBUF(...)
#endif

#endif /* CAAM_TRACE_H__ */
