#!/bin/sh
# `tailcat-c ls` listing a directory served by the real Go tailcat.
#
# This is the interoperability claim for the client half. live-sshloop runs our
# client against our server, which proves it works and nothing about whether it
# speaks SSH -- both ends were written from the same reading of the same RFCs,
# and bug 22 is what that costs. Here the far end is a Go implementation using
# golang.org/x/crypto/ssh and github.com/pkg/sftp, written from neither.
#
# What a pass covers, end to end: our SSH client's version exchange and
# KEXINIT, its check of the server's signature over the exchange hash, the
# cipher in both directions with the client's key assignment, the `none`
# authentication method that upstream's own `ls` uses, a session channel, the
# sftp subsystem, and an SFTP client that can stat, open, read and page a
# directory.
set -eu

CLI="${CLI:-${BUILD:-build/cosmo}/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

if [ ! -x "$CLI" ]; then
	echo "live-ls: $CLI not built -- run make first" >&2
	exit 1
fi
if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK/files/sub"
echo "alpha" > "$WORK/files/alpha.txt"
head -c 4096 /dev/zero | tr '\0' 'b' > "$WORK/files/bravo.bin"
echo "nested" > "$WORK/files/sub/charlie.txt"

echo "starting the real Go tailcat as a file server"
"$UPSTREAM" serve --files "$WORK/files" > "$WORK/srv.log" 2>&1 < /dev/null &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 60 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$WORK/srv.log" |
		head -1)
	[ -n "$ADDR" ] && break
	if ! kill -0 "$SRV_PID" 2>/dev/null; then
		echo "live-ls: the server exited before printing an address:" >&2
		cat "$WORK/srv.log" >&2
		exit 1
	fi
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-ls: the server never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

echo
echo "\$ tailcat-c ls <addr>"
if ! timeout 90 "$CLI" ls "$ADDR" > "$WORK/out" 2> "$WORK/err"; then
	echo "live-ls: ls failed" >&2
	cat "$WORK/err" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi
sed 's/^/    /' "$WORK/out"

for want in alpha.txt bravo.bin sub/; do
	if ! grep -qx "$want" "$WORK/out"; then
		echo "live-ls: FAIL -- the listing is missing $want" >&2
		cat "$WORK/out" >&2
		exit 1
	fi
done
# Sorted, as upstream sorts it, and a directory carries a trailing slash.
if [ "$(sort "$WORK/out" | tr -d '\n')" != "$(tr -d '\n' < "$WORK/out")" ]; then
	echo "live-ls: FAIL -- the listing is not sorted" >&2
	exit 1
fi
echo "ok   live-ls                 listed a real Go tailcat file server"

echo
echo "\$ tailcat-c ls -l <addr>"
if ! timeout 90 "$CLI" ls -l "$ADDR" > "$WORK/outl" 2> "$WORK/err"; then
	echo "live-ls: ls -l failed" >&2
	cat "$WORK/err" >&2
	exit 1
fi
sed 's/^/    /' "$WORK/outl"
# The size column has to be right, which is the one field a listing that
# merely reached the server could still get wrong.
if ! grep -qE '^-rw.* +4096 .*bravo\.bin$' "$WORK/outl"; then
	echo "live-ls: FAIL -- the long listing lost the mode or the size" >&2
	cat "$WORK/outl" >&2
	exit 1
fi
if ! grep -qE '^d' "$WORK/outl"; then
	echo "live-ls: FAIL -- the subdirectory was not reported as one" >&2
	exit 1
fi
echo "ok   live-ls                 -l reported modes and sizes"

echo
echo "\$ tailcat-c ls <addr>:sub"
if ! timeout 90 "$CLI" ls "$ADDR:sub" > "$WORK/outs" 2> "$WORK/err"; then
	echo "live-ls: listing a subdirectory failed" >&2
	cat "$WORK/err" >&2
	exit 1
fi
sed 's/^/    /' "$WORK/outs"
if ! grep -qx 'charlie.txt' "$WORK/outs"; then
	echo "live-ls: FAIL -- the subdirectory listing is wrong" >&2
	exit 1
fi
echo "ok   live-ls                 listed a path under the served root"
