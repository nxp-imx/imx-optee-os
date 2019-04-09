#!/bin/bash

CROSS_COMPILE="${CROSS_COMPILE:-arm-linux-gnueabihf-}"
CROSS_COMPILE64="${CROSS_COMPILE64:-aarch64-linux-gnu-}"
O="${O:-.}"

platform=ls-ls1046ardb && \
make CFG_ARM64_core=y CFG_NXP_CAAM=y CFG_NXPCRYPT=y CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
	PLATFORM=$platform CFG_TEE_CORE_LOG_LEVEL=1 O=${O}/build.$platform && \
${CROSS_COMPILE64}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin
