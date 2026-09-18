#!/bin/sh
# Every authorized-key algorithm, against a real OpenSSH client.
#
# The unit tests verify golden vectors: signatures openssl made over messages
# this project assembled. That covers the formats but not the negotiation, and
# the negotiation is where RSA quietly stops working.
#
# An OpenSSH client that is not told which signature algorithms a server takes
# assumes SHA-1 `ssh-rsa` is all there is, and has declined to use that by
# default since 8.8 -- so it never offers an RSA key, and the user sees
# "Permission denied (publickey)" while holding a perfectly good key. Nothing
# about that failure points at the server having been silent. The only way to
# see it is to put a real client in front of a real server and watch which
# algorithm it picks, which is what this does.
#
# What a pass proves, per algorithm: ssh-keygen wrote a key, our
# authorized_keys parser read it, EXT_INFO told the client we could verify it,
# the client chose that algorithm, signed with it, and we accepted the
# signature. And that none of the other keys would have worked.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$(cd "$(dirname "$BUILD")" && pwd)/$(basename "$BUILD")/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-sshkeys: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v ssh > /dev/null 2>&1 || ! command -v ssh-keygen > /dev/null 2>&1
then
	cat >&2 <<'EOF'
live-sshkeys: no OpenSSH client found, so key algorithm negotiation stayed
untested against a real peer.

  sudo apt install openssh-client       # Debian/Ubuntu, including WSL
EOF
	exit 77
fi

tmp=$(mktemp -d)
srv_pid=""
cleanup() {
	if [ -n "${srv_pid:-}" ]; then
		kill "$srv_pid" 2> /dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

host_seed=$(printf '%064d' 0 | tr '0' 'c')
port_base=$((20000 + $$ % 20000))
port_n=0
fails=0

echo "== $(ssh -V 2>&1) =="

# keygen <name> <-t type> [<-b bits>]
keygen() {
	name=$1
	shift
	ssh-keygen -q -N '' -C "$name@live" -f "$tmp/$name" "$@" > /dev/null
}

# start_server <authorized-keys-text> -> sets $port, $srv_pid
start_server() {
	port_n=$((port_n + 1))
	port=$((port_base + port_n))
	"$SSHD" "$port" "$host_seed" "$1" shell \
		> "$tmp/srv.$port.out" 2> "$tmp/srv.$port.err" &
	srv_pid=$!
	i=0
	while [ "$i" -lt 100 ]; do
		if grep -q '^listening ' "$tmp/srv.$port.out" 2> /dev/null; then
			return 0
		fi
		if ! kill -0 "$srv_pid" 2> /dev/null; then
			srv_pid=""
			return 1
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

# try_connect <keyfile> <port> -> 0 if authentication succeeded.
# -vvv because the algorithm actually chosen is only visible in the debug log,
# and the algorithm actually chosen is the whole point.
try_connect() {
	set +e
	timeout 30 ssh -vvv \
		-i "$1" \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o GlobalKnownHostsFile=/dev/null \
		-o IdentitiesOnly=yes \
		-o BatchMode=yes \
		-p "$2" tester@127.0.0.1 "true" \
		< /dev/null > "$tmp/out.$2" 2> "$tmp/err.$2"
	rc=$?
	set -e
	return $rc
}

fail() {
	echo "live-sshkeys: FAIL -- $*" >&2
	fails=$((fails + 1))
}

# ---- the algorithms we accept -------------------------------------------
#
# Each line is: <name> <expected signature algorithm> <ssh-keygen args...>
# The expected algorithm is what the client should end up signing with, and
# checking it is what makes this more than "some key worked": an RSA key
# accepted under `ssh-rsa` would mean SHA-1, which we do not implement, so
# seeing rsa-sha2-512 here is seeing EXT_INFO having been received and used.
run_ok_case() {
	name=$1
	want=$2
	shift 2
	keygen "$name" "$@"

	if ! start_server "$(cat "$tmp/$name.pub")"; then
		fail "$name: the server did not start"
		cat "$tmp/srv.$port.err" >&2
		return 0
	fi

	if try_connect "$tmp/$name" "$port"; then
		# "signing using <algorithm>" is OpenSSH's own record of what it
		# chose, and that choice is the thing being tested. A check that
		# only looked at the exit status would be satisfied by an RSA key
		# accepted under SHA-1 `ssh-rsa`, which this server cannot even
		# compute -- so the exit status alone would prove the opposite of
		# what it looked like.
		got=$(sed -n 's/.*sign_and_send_pubkey: signing using \([a-z0-9@.-]*\) .*/\1/p' \
			"$tmp/err.$port" | head -1)
		if [ "$got" != "$want" ]; then
			fail "$name: signed with '${got:-nothing we could find}', wanted $want"
		elif ! grep -q "server-sig-algs=<.*$want" "$tmp/err.$port"; then
			# And it chose that because we told it we could verify it.
			fail "$name: the client never saw $want in server-sig-algs"
		else
			echo "ok   live-sshkeys            $name authenticated with $want"
		fi
	else
		fail "$name: authentication failed"
		grep -E 'Offering|Server accepts|sign_and_send|Permission denied|server-sig-algs' \
			"$tmp/err.$port" >&2 || true
		cat "$tmp/srv.$port.err" >&2
	fi
	wait "$srv_pid" 2> /dev/null || true
	srv_pid=""
}

run_ok_case ed25519 ssh-ed25519 -t ed25519
run_ok_case rsa2048 rsa-sha2-512 -t rsa -b 2048
run_ok_case rsa4096 rsa-sha2-512 -t rsa -b 4096
run_ok_case nistp256 ecdsa-sha2-nistp256 -t ecdsa -b 256
run_ok_case nistp384 ecdsa-sha2-nistp384 -t ecdsa -b 384

# ---- and the ones we do not ---------------------------------------------
#
# Refused at the authorized_keys stage rather than at verification time. A key
# we cannot check that was nonetheless accepted into the list would look
# configured and never work, which is the failure that takes an afternoon.
echo "== keys we cannot verify are refused when the list is built =="
for spec in "dss -t dsa" "nistp521 -t ecdsa -b 521"; do
	# shellcheck disable=SC2086
	set -- $spec
	name=$1
	shift
	if ! keygen "$name" "$@" 2> "$tmp/keygen.$name.err"; then
		echo "skip live-sshkeys            this ssh-keygen will not make a $name key"
		continue
	fi
	port_n=$((port_n + 1))
	p=$((port_base + port_n))
	if "$SSHD" "$p" "$host_seed" "$(cat "$tmp/$name.pub")" shell \
		> "$tmp/srv.$p.out" 2> "$tmp/srv.$p.err"; then
		fail "$name: the server started with a key it cannot verify"
	else
		echo "ok   live-sshkeys            a $name key is refused, not silently ignored"
	fi
done

# ---- a key that is not on the list --------------------------------------
echo "== an unauthorized key is refused =="
keygen stranger -t ed25519
if ! start_server "$(cat "$tmp/ed25519.pub")"; then
	fail "the server did not start for the stranger case"
else
	if try_connect "$tmp/stranger" "$port"; then
		fail "a key that is not on the list authenticated"
	else
		echo "ok   live-sshkeys            an unauthorized ed25519 key is refused"
	fi
	wait "$srv_pid" 2> /dev/null || true
	srv_pid=""
fi

# The same, with an RSA key -- worth its own case because the RSA path is the
# one with two algorithm names in it, and "accepts anything under rsa-sha2-*"
# is a mistake that only shows up here.
keygen stranger_rsa -t rsa -b 2048
if ! start_server "$(cat "$tmp/rsa2048.pub")"; then
	fail "the server did not start for the RSA stranger case"
else
	if try_connect "$tmp/stranger_rsa" "$port"; then
		fail "an RSA key that is not on the list authenticated"
	else
		echo "ok   live-sshkeys            an unauthorized RSA key is refused"
	fi
	wait "$srv_pid" 2> /dev/null || true
	srv_pid=""
fi

# ---- several keys, one of which is the client's -------------------------
echo "== a list of many keys =="
if ! start_server "$(cat "$tmp/stranger.pub" "$tmp/nistp384.pub" \
	"$tmp/rsa2048.pub")"; then
	fail "the server did not start with three keys"
else
	if try_connect "$tmp/nistp384" "$port"; then
		echo "ok   live-sshkeys            one key among three of different types"
	else
		fail "a key in the middle of a mixed list was not found"
		cat "$tmp/srv.$port.err" >&2
	fi
	wait "$srv_pid" 2> /dev/null || true
	srv_pid=""
fi

if [ "$fails" -ne 0 ]; then
	echo "live-sshkeys: $fails failure(s)" >&2
	exit 1
fi
echo "ok   live-sshkeys            every accepted algorithm, negotiated by OpenSSH"
