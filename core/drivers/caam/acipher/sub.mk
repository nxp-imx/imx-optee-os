COMMON_HAL = ../hal/common

incdirs-y += $(COMMON_HAL)/registers

incdirs-y += ../include
incdirs-y += include

srcs-y += caam_prime.c
srcs-y += caam_math.c
srcs-$(CFG_CRYPTO_RSA_HW) += caam_rsa.c
srcs-$(CFG_CRYPTO_ECC_HW) += caam_ecc.c

