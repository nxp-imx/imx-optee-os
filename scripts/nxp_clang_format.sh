#!/bin/bash -e
# Copyright 2021 NXP

usage() {
cat << EOF
Usage:
./$(basename "$0") [--working]                 Format working area
./$(basename "$0") --diff <commit> [<commit>]  If zero or one commits are given, run clang-format on all lines that differ
                                               between the working directory and <commit>, which defaults to HEAD.
                                               If two commits are given, run clang-format on all lines in the
                                               second <commit> that differ from the first <commit>.
./$(basename "$0") --help                      This help
EOF
}

clang_format_working_area() {
	[[ $# -ne 0 ]] && usage && exit 1

	echo "Formatting working area ..."

	"$GIT_CLANG_FORMAT_BIN" \
		--binary "$CLANG_FORMAT_BIN" \
		--style='file' \
		--extensions c,h \
		--quiet \
		--diff -v

	exit 0
}

clang_format_diff() {
	[[ $# -ne 2 ]] && [[ $# -ne 3 ]] && usage && exit 1

	c1=$1
	c2=${2:-HEAD}

	echo "Formatting diff (diff $c1...$c2) ..."

	"$GIT_CLANG_FORMAT_BIN" \
		--binary "$CLANG_FORMAT_BIN" \
		--style='file' \
		--extensions c,h \
		--quiet \
		--diff -v \
		"$c1" "$c2"

	exit 0
}

clang_format_commit() {
	[[ $# -ne 1 ]] && usage && exit 1

	echo "Formatting commit "$1" ..."

	"$GIT_CLANG_FORMAT_BIN" \
		--binary "$CLANG_FORMAT_BIN" \
		--style='file' \
		--extensions c,h \
		--quiet \
		--diff -v \
		"$1"~1 "$1"

	exit 0
}

# MAIN
GIT_CLANG_FORMAT_BIN=${GIT_CLANG_FORMAT_BIN:-git-clang-format}
CLANG_FORMAT_BIN=${CLANG_FORMAT_BIN:-clang-format}
CLANG_FILE_FORMAT=${CLANG_FILE_FORMAT:-.clang-format}

[[ ! -x "$(command -v "$GIT_CLANG_FORMAT_BIN")" ]] && echo "Error: $GIT_CLANG_FORMAT_BIN not found" && exit 1
[[ ! -x "$(command -v "$CLANG_FORMAT_BIN")" ]] && echo "Error: $CLANG_FORMAT_BIN not found" && exit 1
[[ ! -f "$CLANG_FILE_FORMAT" ]] && echo "Error: $CLANG_FILE_FORMAT not found" && exit 1

op=${1:---working}
case "$op" in
	--working)
		clang_format_working_area
		;;
	--diff)
		clang_format_diff "$2" "$3"
		;;
	--commit)
		clang_format_commit "$2"
		;;
	--help|-h)
		usage
		;;
	*)
		usage
		;;
esac

