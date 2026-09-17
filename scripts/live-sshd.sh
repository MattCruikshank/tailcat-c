#!/bin/sh
# Serve one SSH connection to a real OpenSSH client.
#
# This is the only check in the project that can tell whether our SSH subset
# actually speaks SSH. Every offline test compares us against vectors produced
# by Go code written from the same specification as the C, so any misreading of
# that specification is reproduced on both sides and passes. OpenSSH was
# written from neither.
#
# What a pass proves, end to end: the version exchange, KEXINIT negotiation,
# curve25519-sha256, the exchange hash, an ssh-ed25519 host key signature the
# client verifies, chacha20-poly1305@openssh.com in both directions, publickey
# authentication over the session id, the session channel, the exec request,
# channel data both ways, flow control and the exit status.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$BUILD/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-sshd: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v ssh > /dev/null 2>&1; then
	cat >&2 <<'EOF'
live-sshd: no ssh client found, so the SSH subset stayed untested against a
real peer.

  sudo apt install openssh-client       # Debian/Ubuntu, including WSL
EOF
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

echo "== generating a client key with ssh-keygen =="
ssh-keygen -t ed25519 -N '' -C tailcat-c-test -f "$tmp/id" > /dev/null

# The authorized key, as raw hex. The blob is
#   string "ssh-ed25519" || string <32-byte key>
# so the last 32 bytes are the key itself.
pub_hex=$(awk '{print $2}' "$tmp/id.pub" | base64 -d | tail -c 32 |
	od -An -v -tx1 | tr -d ' \n')
if [ "${#pub_hex}" -ne 64 ]; then
	echo "live-sshd: could not extract the client key (got ${#pub_hex} hex digits)" >&2
	exit 1
fi

# A fixed host seed, so the host key is the same on every run and a stale
# known_hosts entry is a deliberate choice rather than an accident. The test
# still tells ssh not to keep one.
host_seed=$(printf '%064d' 0 | tr '0' 'a')

# Port 0 is not usable here because the server prints the port it was told,
# so pick a high one and let bind fail loudly if it is taken.
port=$((20000 + $$ % 20000))

echo "== starting our server on port $port =="
"$SSHD" "$port" "$host_seed" "$pub_hex" > "$tmp/srv.out" 2> "$tmp/srv.err" &
srv_pid=$!

# Wait for the listening line rather than sleeping.
for _ in $(seq 1 100); do
	if grep -q '^listening ' "$tmp/srv.out" 2>/dev/null; then
		break
	fi
	if ! kill -0 "$srv_pid" 2>/dev/null; then
		echo "live-sshd: the server exited before listening" >&2
		cat "$tmp/srv.err" >&2
		exit 1
	fi
	sleep 0.1
done
if ! grep -q '^listening ' "$tmp/srv.out" 2>/dev/null; then
	echo "live-sshd: the server never started listening" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

echo "== connecting with $(ssh -V 2>&1) =="
set +e
out=$(echo "hello from the client" | ssh \
	-i "$tmp/id" \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null \
	-o GlobalKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes \
	-o BatchMode=yes \
	-o LogLevel=ERROR \
	-p "$port" tester@127.0.0.1 "uptime" 2>"$tmp/ssh.err")
ssh_rc=$?
set -e

wait "$srv_pid" 2>/dev/null || true
srv_pid=""

echo "--- what ssh printed ---"
printf '%s\n' "$out"
echo "------------------------"

if [ "$ssh_rc" -ne 0 ]; then
	echo "live-sshd: FAIL -- ssh exited $ssh_rc" >&2
	echo "--- ssh stderr ---" >&2
	cat "$tmp/ssh.err" >&2
	echo "--- server stderr ---" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

# The exec request must have reached us with its command intact.
if ! printf '%s' "$out" | grep -q 'tailcat-c ssh subset: exec uptime'; then
	echo "live-sshd: FAIL -- the exec request did not arrive intact" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

# And the channel must have carried the client's stdin to us. 22 bytes:
# "hello from the client" plus the newline echo adds.
if ! printf '%s' "$out" | grep -q 'received 22 bytes'; then
	echo "live-sshd: FAIL -- the client's data did not arrive intact" >&2
	printf '%s\n' "$out" >&2
	cat "$tmp/srv.err" >&2
	exit 1
fi

# ssh exiting zero is itself the exit-status check: without our exit-status
# message ssh reports 255.
echo "ok   live-sshd               real OpenSSH completed a session against our server"

# ---- and a rekey works, repeatedly ---------------------------------------
#
# OpenSSH starts a key exchange on its own schedule, and RFC 4253 section 9
# has the initiator wait for a KEXINIT in reply -- so a server that ignores
# the request leaves the client blocked until its own timeout with nothing in
# stderr to say why. That is what this server did before rekeying was
# implemented, and `timeout` is what catches it: a hang and a failure look
# alike to a check that only tests the exit status.
#
# RekeyLimit=16K over 2MB forces on the order of a hundred exchanges, so this
# covers the repeated case and not just the first one. The byte count is the
# integrity check across all of them: sequence numbers do not reset at a
# rekey, and keys that came out wrong would corrupt the stream rather than
# stop it.
echo "== forcing repeated rekeys =="
port2=$((port + 1))
"$SSHD" "$port2" "$host_seed" "$pub_hex" > "$tmp/srv2.out" 2> "$tmp/srv2.err" &
srv_pid=$!
for _ in $(seq 1 100); do
	grep -q '^listening ' "$tmp/srv2.out" 2>/dev/null && break
	sleep 0.1
done

start=$(date +%s)
set +e
out2=$(head -c 2000000 /dev/zero | tr '\0' 'x' | timeout 60 ssh \
	-i "$tmp/id" \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null \
	-o GlobalKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes \
	-o BatchMode=yes \
	-o LogLevel=ERROR \
	-o RekeyLimit=16K \
	-p "$port2" tester@127.0.0.1 "uptime" 2> "$tmp/rekey.err")
rc=$?
set -e
elapsed=$(( $(date +%s) - start ))
kill "$srv_pid" 2>/dev/null || true
srv_pid=""

if [ "$rc" -eq 124 ]; then
	echo "live-sshd: FAIL -- the client hung for ${elapsed}s during a rekey" >&2
	echo "  A rekey request must be answered. Before it was implemented the" >&2
	echo "  request was dropped and the client waited here for ever." >&2
	exit 1
fi
if [ "$rc" -ne 0 ]; then
	echo "live-sshd: FAIL -- ssh exited $rc across a rekey" >&2
	cat "$tmp/rekey.err" >&2
	cat "$tmp/srv2.err" >&2
	exit 1
fi

# Every byte, across every rekey.
if ! printf '%s' "$out2" | grep -q 'received 2000000 bytes'; then
	echo "live-sshd: FAIL -- data was lost or corrupted across a rekey" >&2
	printf '%s\n' "$out2" >&2
	exit 1
fi

# And a rekey must actually have happened. Without this the check passes on a
# client that quietly ignored RekeyLimit, which is the same shape of mistake
# as a fuzzer that stopped reaching the code it was aimed at.
rekeys=$(printf '%s' "$out2" | sed -n 's/.*after \([0-9][0-9]*\) rekeys.*/\1/p')
if [ -z "$rekeys" ] || [ "$rekeys" -lt 1 ]; then
	echo "live-sshd: FAIL -- no rekey took place, so this proved nothing" >&2
	printf '%s\n' "$out2" >&2
	exit 1
fi

echo "ok   live-sshd               2MB across $rekeys rekeys, intact, in ${elapsed}s"
