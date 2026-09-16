#!/bin/sh
# Assert that a binary really is a fat Actually Portable Executable.
#
# The whole point of building with cosmocc is one binary that runs on
# Linux/macOS/Windows/FreeBSD/OpenBSD/NetBSD on both x86_64 and aarch64. It is
# easy to lose the aarch64 half by accident -- a single unsupported compiler
# flag does it (see the stack-protector note in the Makefile) -- and the build
# otherwise still "succeeds". So we check, every build.
set -eu

status=0
for bin in "$@"; do
	if [ ! -f "$bin" ]; then
		echo "check-fat: $bin: missing" >&2
		status=1
		continue
	fi

	# Cosmopolitan stores a per-architecture symbol table inside the APE's
	# zip directory; both must be present for a fat build.
	members=$(unzip -l "$bin" 2>/dev/null || true)
	have_amd64=$(printf '%s' "$members" | grep -c '\.symtab\.amd64' || true)
	have_arm64=$(printf '%s' "$members" | grep -c '\.symtab\.arm64' || true)

	# The APE polyglot header starts with "MZqFpD" so it is simultaneously a
	# DOS/PE image, an ELF, and a shell script.
	magic=$(dd if="$bin" bs=1 count=6 2>/dev/null || true)

	if [ "$magic" != "MZqFpD" ]; then
		echo "check-fat: $bin: not an APE (magic \"$magic\", want MZqFpD)" >&2
		status=1
	elif [ "$have_amd64" -lt 1 ] || [ "$have_arm64" -lt 1 ]; then
		echo "check-fat: $bin: NOT FAT (amd64=$have_amd64 arm64=$have_arm64)" >&2
		status=1
	else
		echo "fat  $bin (x86_64 + aarch64 APE)"
	fi
done
exit $status
