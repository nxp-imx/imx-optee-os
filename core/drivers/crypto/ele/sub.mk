incdirs-y += include

srcs-y += ele.c
srcs-y += memutils.c
srcs-y += key_store.c
srcs-y += key_mgmt.c
srcs-y += fuse.c
srcs-y += utils_trace.c
srcs-y += sign_verify.c
srcs-y += asym_cipher.c
subdirs-$(CFG_IMX_ELE_ACIPHER_DRV) += acipher
