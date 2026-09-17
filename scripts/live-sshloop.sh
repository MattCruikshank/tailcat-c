#!/bin/sh
# Our SSH client against our SSH server, over loopback.
#
# No network and no third party, which is both the point and the limitation.
# Both halves were written from the same reading of the same RFCs, so a
# misunderstanding shared by the two of them passes here -- that is what bug
# 22 was, and it took a real OpenSSH to find. The interoperability claim rests
# on live-sshd (a real client against our server) and live-ls (our client
# against a real server); this one proves the client half exists and works.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$BUILD/livesshd"
SSHCLI="$BUILD/livesshcli"

for b in "$SSHD" "$SSHCLI"; do
	if [ ! -x "$b" ]; then
		echo "live-sshloop: $b not built -- run make first" >&2
		exit 1
	fi
done

tmp=$(mktemp -d)
cleanup() {
	[ -n "${srv_pid:-}" ] && kill "$srv_pid" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# A random client seed and the public key the server will authorise. No
# ssh-keygen here: neither end of this test is OpenSSH, so a key in OpenSSH's
# file format would only have to be decoded again.
seed_hex=$(od -An -v -tx1 -N 32 < /dev/urandom | tr -d ' \n')
pub_hex=$("$SSHCLI" --pub "$seed_hex") || {
	echo "live-sshloop: could not derive the public key" >&2
	exit 1
}

port=$((23000 + $$ % 16000))
"$SSHD" "$port" "$(printf '%064d' 0 | tr '0' 'b')" "$pub_hex" \
	> "$tmp/srv.out" 2> "$tmp/srv.err" &
srv_pid=$!
for _ in $(seq 1 100); do
	grep -q '^listening ' "$tmp/srv.out" 2>/dev/null && break
	kill -0 "$srv_pid" 2>/dev/null || break
	sleep 0.1
done
if ! grep -q '^listening ' "$tmp/srv.out" 2>/dev/null; then
	echo "live-sshloop: the server never listened" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

set +e
out=$(timeout 30 "$SSHCLI" "$port" "$seed_hex" 2> "$tmp/cli.err")
rc=$?
set -e
wait "$srv_pid" 2>/dev/null || true
srv_pid=""

if [ "$rc" -ne 0 ]; then
	echo "live-sshloop: FAIL -- the client exited $rc" >&2
	cat "$tmp/cli.err" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

# The server names the subsystem it was asked for, so this checks the channel
# request arrived rather than merely that a channel opened.
if ! printf '%s' "$out" | grep -q 'subsystem sftp'; then
	echo "live-sshloop: FAIL -- the subsystem request did not arrive" >&2
	printf '%s\n' "$out" >&2
	exit 1
fi
# And it counts what we sent, which checks the client's send direction: 27
# bytes of greeting.
if ! printf '%s' "$out" | grep -q 'received 27 bytes'; then
	echo "live-sshloop: FAIL -- the client's data did not arrive intact" >&2
	printf '%s\n' "$out" >&2
	exit 1
fi

echo "ok   live-sshloop            our client completed a session with our server"
