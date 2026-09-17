#!/bin/sh
# `tailcat-c recv` receiving a real file from a real scp, through a real relay.
#
# live-dropbox drives the same drop box over a plain TCP socket, which proves
# the SFTP policy and the SSH server. This proves the part that only the
# tunnel exercises: the SSH server is a blocking state machine and the bytes
# it waits for arrive through the serve event loop, so its read callback has
# to *drive* that loop rather than wait on it. Nothing offline can reach that
# code, because nothing offline has a tunnel.
#
# Both ends are ours, and `cp` execs the system scp with tailcat-c as its
# ProxyCommand -- so the client half is real OpenSSH throughout.
set -eu

BUILD="${BUILD:-build/cosmo}"
CLI="$BUILD/tailcat-c"

if [ ! -x "$CLI" ]; then
	echo "live-recv-serve: $CLI not built -- run make first" >&2
	exit 1
fi
if ! command -v scp > /dev/null 2>&1; then
	echo "live-recv-serve: scp is needed (apt install openssh-client)" >&2
	# 77 is automake's "skipped", and it is for whoever runs this
	# script by hand -- the diagnostic harness never sees it. Every
	# stage reaches this through make, and make flattens any recipe
	# failure to exit 2, so no exit code survives to mean anything
	# specific. The harness decides separately, with --need.
	exit 77
fi

tmp=$(mktemp -d)
cleanup() {
	# `[ -n x ] && kill` is an AND-list, and an AND-list that ends
	# non-zero -- which it does whenever the server has already
	# exited -- trips `set -e` here inside the trap, so the rm
	# below never ran and the script exited 1 with every check
	# passed. Cleanup is the one path that must not stop early.
	if [ -n "${srv_pid:-}" ]; then
		kill "$srv_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/box"
head -c 40000 /dev/urandom > "$tmp/payload.bin"
printf 'ORIGINAL' > "$tmp/box/existing.txt"

echo "\$ tailcat-c recv $tmp/box"
"$CLI" -v --timeout 120 recv "$tmp/box" > "$tmp/srv.out" 2>&1 &
srv_pid=$!

ADDR=""
for _ in $(seq 1 120); do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$tmp/srv.out" |
		head -1)
	[ -n "$ADDR" ] && break
	if ! kill -0 "$srv_pid" 2>/dev/null; then
		echo "live-recv-serve: recv exited before printing an address:" >&2
		cat "$tmp/srv.out" >&2
		exit 1
	fi
	sleep 0.5
done
if [ -z "$ADDR" ]; then
	echo "live-recv-serve: recv never printed an address:" >&2
	cat "$tmp/srv.out" >&2
	exit 1
fi
echo "# address: $(printf '%s' "$ADDR" | cut -c1-24)..."

# ---- an ordinary upload -------------------------------------------------
echo "\$ tailcat-c cp payload.bin <addr>:"
if ! timeout 120 "$CLI" cp "$tmp/payload.bin" "$ADDR:payload.bin" \
	> "$tmp/cp.out" 2>&1; then
	echo "live-recv-serve: cp failed" >&2
	cat "$tmp/cp.out" >&2
	cat "$tmp/srv.out" >&2
	exit 1
fi
if ! cmp -s "$tmp/payload.bin" "$tmp/box/payload.bin"; then
	echo "live-recv-serve: the file did not arrive intact" >&2
	ls -la "$tmp/box" >&2
	cat "$tmp/srv.out" >&2
	exit 1
fi
echo "ok   live-recv-serve         40000 bytes arrived intact through the tunnel"

# ---- and the guarantees still hold over the tunnel ----------------------
#
# The policy is the same code live-dropbox already drives, so this is not
# retesting it -- it is checking that nothing about carrying it over a tunnel
# loosened it, which is the kind of thing that is obvious only once it is not
# true.
echo "\$ tailcat-c cp payload.bin <addr>:../../escaped.bin"
timeout 120 "$CLI" cp "$tmp/payload.bin" "$ADDR:../../escaped.bin" \
	> /dev/null 2>&1 || true
if [ -e "$tmp/escaped.bin" ]; then
	echo "live-recv-serve: a file escaped the drop box" >&2
	exit 1
fi
echo "ok   live-recv-serve         a traversal stayed inside the box"

echo "\$ tailcat-c cp replacement <addr>:existing.txt"
printf 'REPLACED' > "$tmp/replacement.txt"
timeout 120 "$CLI" cp "$tmp/replacement.txt" "$ADDR:existing.txt" \
	> /dev/null 2>&1 || true
if [ "$(cat "$tmp/box/existing.txt")" != "ORIGINAL" ]; then
	echo "live-recv-serve: an existing file was overwritten" >&2
	exit 1
fi
echo "ok   live-recv-serve         an existing file survived a same-name upload"

kill "$srv_pid" 2>/dev/null || true
srv_pid=""
echo "ok   live-recv-serve         recv served a real scp over a real relay"
