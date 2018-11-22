#!/bin/bash

boards_list=(mx6ulevk mx6ul9x9evk mx6ullevk mx6slevk mx6sllevk mx6sxsabreauto \
	mx6sxsabresd mx6qsabrelite mx6qsabresd mx6qsabreauto mx6qpsabresd mx6qpsabreauto \
	mx6dlsabresd mx6dlsabreauto mx6solosabresd mx6solosabreauto mx7dsabresd mx7ulpevk \
	mx8mqevk mx8mmevk mx8qmmek mx8qmlpddr4arm2 mx8qxpmek mx8qxplpddr4arm2 )

CROSS_COMPILE="${CROSS_COMPILE:-arm-linux-gnueabihf-}"
CROSS_COMPILE64="${CROSS_COMPILE64:-aarch64-linux-gnu-}"
MKIMAGE="${MKIMAGE:-mkimage}"
O="${O:-.}"

mx67build()
{
	platform=$1 && \
	make CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
		PLATFORM=imx PLATFORM_FLAVOR=$platform CFG_TEE_CORE_LOG_LEVEL=1 O=${O}/build.$platform && \
	${CROSS_COMPILE}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin && \
	imx_load_addr=`cat ${O}/build.$platform/core/tee-init_load_addr.txt` && \
	${MKIMAGE} -A arm -O linux -C none -a $imx_load_addr -e $imx_load_addr \
			-d ${O}/build.$platform/tee.bin ${O}/build.$platform/uTee.$platform && \
	return 0
}

mx8build()
{
	platform=$1 && \
	make CROSS_COMPILE=${CROSS_COMPILE} CROSS_COMPILE64=${CROSS_COMPILE64} \
		PLATFORM=imx PLATFORM_FLAVOR=$platform  CFG_TEE_CORE_LOG_LEVEL=1 O=${O}/build.$platform && \
	${CROSS_COMPILE64}objcopy -O binary ${O}/build.$platform/core/tee.elf ${O}/build.$platform/tee.bin && \
	return 0
}

build()
{
	case $1 in
		mx[6-7]*) mx67build $1 ;;&
		mx8*) mx8build $1 ;;&
	esac
		
}

list_board()
{

	i=0

	while ((i<=${#boards_list[@]}))
	do
		echo ${boards_list[i]}
		let ++i
	done
}

help()
{
	echo "Make sure you have you cross compile toolchain ready"
	echo "./build.sh help"
	echo "Build all boards"
	echo "./build.sh all"
	echo "Build all boards with only building error output"
	echo "./build.sh all-silence"
	echo "Build specfic board"
	echo "./build.sh 'boardname'"
	echo "supported boards:"
	list_board
}

arg_num=$#
if [ ${arg_num} -eq 0 ]
then
	help
	exit 0
fi

if [ "$1" == "help" ]
then
	help
	exit 0
fi

if [ "$1" == "all" ]
then
	i=0

	while ((i<${#boards_list[@]}))
	do
		echo "=============Building ${boards_list[i]}================"
		build ${boards_list[i]}
		if [ $? -ne 0 ]; then
			echo "=============Fail building ${boards_list[i]}================"
			exit 1
		fi
		let ++i
	done
fi

if [ "$1" == "all-silence" ]
then
	i=0

	while ((i<${#boards_list[@]}))
	do
		echo "=============Building ${boards_list[i]}================"
		build ${boards_list[i]} > /dev/null
		if [ $? -ne 0 ]; then
			echo "=============Fail building ${boards_list[i]}================"
			exit 1
		fi
		let ++i
	done
fi

build $1

