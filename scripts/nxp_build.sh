#!/bin/bash -e
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright 2021 NXP
#
boards_list=(
	imx-mx6dhmbedge \
	imx-mx6dlsabreauto \
	imx-mx6dlsabresd \
	imx-mx6dlhmbedge \
	imx-mx6qsabrelite \
	imx-mx6qsabresd \
	imx-mx6qsabreauto
	imx-mx6qhmbedge \
	imx-mx6qpsabresd \
	imx-mx6qpsabreauto \
	imx-mx6shmbedge \
	imx-mx6slevk \
	imx-mx6sllevk \
	imx-mx6solosabresd \
	imx-mx6solosabreauto \
	imx-mx6sxsabreauto \
	imx-mx6sxsabresd \
	imx-mx6sxudooneofull \
	imx-mx6ulevk \
	imx-mx6ul9x9evk \
	imx-mx6ulccimx6ulsbcpro\
	imx-mx6ullevk \
	imx-mx7dsabresd \
	imx-mx7dpico_mbl \
	imx-mx7swarp7 \
	imx-mx7swarp7_mbl \
	imx-mx7dclsom \
	imx-mx7ulpevk \
	imx-mx8dxmek \
	imx-mx8mqevk \
	imx-mx8mmevk \
	imx-mx8mnevk \
	imx-mx8mpevk \
	imx-mx8qxpmek \
	imx-mx8qmmek \
	imx-mx8qmmekcockpita53 \
	imx-mx8qmmekcockpita72 \
	imx-mx8dxlevk \
	imx-mx8ulpevk \
	ls-ls1021atwr \
	ls-ls1021aqds \
	ls-ls1012ardb \
	ls-ls1012afrwy \
	ls-ls1043ardb \
	ls-ls1046ardb \
	ls-ls1088ardb \
	ls-ls2088ardb \
	ls-lx2160ardb \
)

CROSS_COMPILE="${CROSS_COMPILE:-arm-linux-gnueabihf-}"
CROSS_COMPILE64="${CROSS_COMPILE64:-aarch64-linux-gnu-}"
CCACHE="${CCACHE:-ccache}"
MKIMAGE="${MKIMAGE:-mkimage}"
O="${O:-.}"
NB_CORES="${NB_CORES:-1}"
CFG_TEE_CORE_LOG_LEVEL="${CFG_TEE_CORE_LOG_LEVEL:-1}"
CFG_TEE_TA_LOG_LEVEL="${CFG_TEE_TA_LOG_LEVEL:-0}"

usage()
{
cat << EOF
Usage: $(basename "$0") [all] [all-silence] [list] [<board>]
	all          compile all platform supported
	all-silence  compile all platforms supported with build error only
	list         list of supported platforms
	<board>      build the given platform
EOF
}

# Build the board given in parameter $1
build()
{
	set -e
	local plat="$1"

	# Use ccache if installed
	if [[ "$(command -v "$CCACHE" )" ]]
	then
		_CROSS_COMPILE=""$CCACHE" "$CROSS_COMPILE""
		_CROSS_COMPILE64=""$CCACHE" "$CROSS_COMPILE64""
	else
		_CROSS_COMPILE="$CROSS_COMPILE"
		_CROSS_COMPILE64="$CROSS_COMPILE64"
	fi

	# Compile the tee.bin for all platforms
	make -j"$NB_CORES" \
		CROSS_COMPILE="$_CROSS_COMPILE" \
		CROSS_COMPILE64="$_CROSS_COMPILE64" \
		CFG_TEE_CORE_LOG_LEVEL="$CFG_TEE_CORE_LOG_LEVEL" \
		CFG_TEE_TA_LOG_LEVEL="$CFG_TEE_TA_LOG_LEVEL" \
		CFG_WERROR=y \
		PLATFORM="$plat" \
		O="$O"/build."$plat" || return 1

	ln -s -rf "$O"/build."$plat"/core/tee.bin \
		"$O"/build."$plat"/tee-"$plat".bin

	# Generate the uTee binary for armv7 platforms
	if [[ "$plat" == *mx[6-7]* ]];
	then
		# Fetch the platform load address
		imx_load_addr="$("$CROSS_COMPILE"readelf -h \
			"$O"/build."$plat"/core/tee.elf | \
			grep "Entry point address" | \
			awk '{print $4}')"

		if [[ -z "$imx_load_addr" ]]
		then
			echo "Error, imx_load_addr is empty"
			return 1
		fi

		# Generate the uTee file
		"$MKIMAGE" -A arm -O linux -C none -a "$imx_load_addr" \
			-e "$imx_load_addr" \
			-d "$O"/build."$plat"/core/tee.bin \
			"$O"/build."$plat"/uTee || return 1

		ln -s -rf "$O"/build."$plat"/uTee \
			"$O"/build."$plat"/uTee-"$plat"
	fi

	return 0
}

build_all()
{
	start=`date +%s`
	for b in "${boards_list[@]}"
	do
		echo "=============Building ""$b""================"

		build "$b"

		if [ $? -ne 0 ]
		then
			echo "=============Fail building ""$b""================"
			exit 1
		fi
	done
	end=`date +%s`
	echo "Compilation time ""$((end-start))"" seconds"

	return 0
}

list_board()
{
	for b in "${boards_list[@]}"
	do
		echo "$b"
	done

	return 0
}

# Main
[[ $# -eq 0 ]] && usage && exit 1
[[ "$1" == "help" ]] && usage && exit 0
[[ "$1" == "list" ]] && list_board && exit 0
[[ "$1" == "all" ]] && build_all && exit 0

build "$1"

exit 0
