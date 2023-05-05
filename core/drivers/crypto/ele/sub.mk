incdirs-y += include

srcs-y += ele.c
srcs-y += memutils.c
srcs-y += key_store.c
srcs-y += key_mgmt.c
srcs-y += utils_trace.c
subdirs-$(CFG_IMX_ELE_ACIPHER_DRV) += acipher
