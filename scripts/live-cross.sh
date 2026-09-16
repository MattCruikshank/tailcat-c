#!/bin/sh
# Cross-platform check: the same fat APE binary talking to itself across two
# operating systems, in both directions, through a real DERP relay.
#
# Run this from Git Bash on Windows, NOT from inside WSL -- it needs to launch
# processes on both sides:
#
#     sh scripts/live-cross.sh
#
# The point is that build/cosmo/tailcat-c and build/tailcat-c.exe are byte for
# byte the same file. One is executed by Linux, the other by Windows.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

WIN_BIN=build/tailcat-c.exe
WSL_BIN=./build/cosmo/tailcat-c
RELAY="${TC_RELAY:-tc301a.ipn.dev}"

if [ ! -f build/cosmo/tailcat-c ]; then
	echo "live-cross: build first: scripts/wslmake.sh 'make'" >&2
	exit 1
fi
cp -f build/cosmo/tailcat-c "$WIN_BIN"

if ! cmp -s build/cosmo/tailcat-c "$WIN_BIN"; then
	echo "live-cross: the two binaries differ; that would defeat the point" >&2
	exit 1
fi
echo "one binary, $(wc -c < "$WIN_BIN") bytes, run by both operating systems"
echo "relay: $RELAY"

fail=0

wait_addr() {
	# $1 = file the server's stderr is going to
	i=0
	while [ $i -lt 30 ]; do
		A=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$1" \
			2>/dev/null | head -1)
		[ -n "$A" ] && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

# ---- direction A: Windows transmits, Linux receives ----------------------

echo
echo "== A: Windows transmits -> Linux receives =="
rm -f build/x-a.out build/x-a.err
(sh scripts/wslmake.sh "printf '' | $WSL_BIN serve --relay $RELAY --timeout 70 \
	> build/x-a.out 2> build/x-a.err" >/dev/null 2>&1 &)

if ! wait_addr build/x-a.err; then
	echo "  FAIL: the Linux server never printed an address" >&2
	cat build/x-a.err >&2 || true
	fail=1
else
	MSG_A="hello from Windows $(date +%s)"
	printf '%s\n' "$MSG_A" | "$WIN_BIN" "$A" >/dev/null 2>&1 || true
	sleep 3
	if grep -qF "$MSG_A" build/x-a.out 2>/dev/null; then
		echo "  the Linux server received: $(cat build/x-a.out)"
		echo "  ok"
	else
		echo "  FAIL: nothing arrived" >&2
		fail=1
	fi
fi

# ---- direction B: Linux transmits, Windows receives ----------------------

echo
echo "== B: Linux transmits -> Windows receives =="
rm -f build/x-b.out build/x-b.err
(printf '' | "$WIN_BIN" serve --relay "$RELAY" --timeout 70 \
	> build/x-b.out 2> build/x-b.err &)

if ! wait_addr build/x-b.err; then
	echo "  FAIL: the Windows server never printed an address" >&2
	cat build/x-b.err >&2 || true
	fail=1
else
	MSG_B="hello from Linux $(date +%s)"
	sh scripts/wslmake.sh "printf '%s\n' '$MSG_B' | $WSL_BIN '$A'" \
		>/dev/null 2>&1 || true
	sleep 3
	if grep -qF "$MSG_B" build/x-b.out 2>/dev/null; then
		echo "  the Windows server received: $(cat build/x-b.out)"
		echo "  ok"
	else
		echo "  FAIL: nothing arrived" >&2
		fail=1
	fi
fi

echo
if [ "$fail" -eq 0 ]; then
	echo "ok   live-cross               one fat APE, two operating systems,"
	echo "                              both directions, through a real relay"
	exit 0
fi
echo "live-cross: FAILED" >&2
exit 1
