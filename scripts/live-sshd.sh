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
	exit 2
fi

tmp=$(mktemp -d)
cleanup() {
	[ -n "${srv_pid:-}" ] && kill "$srv_pid" 2>/dev/null
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

# ---- and a rekey is refused, not ignored ---------------------------------
#
# OpenSSH starts a key exchange on its own schedule. RFC 4253 section 9 has
# the initiator wait for a KEXINIT in reply, so a server that ignores the
# request leaves the client blocked until its own timeout with nothing in
# stderr to say why -- which is what this server did until the handler was
# added. RekeyLimit forces the case in a second rather than in a gigabyte.
#
# The check is deliberately "named failure, quickly" rather than "success":
# we cannot rekey, and the point is that we say so.
echo "== forcing a rekey =="
port2=$((port + 1))
"$SSHD" "$port2" "$host_seed" "$pub_hex" > "$tmp/srv2.out" 2> "$tmp/srv2.err" &
srv_pid=$!
for _ in $(seq 1 100); do
	grep -q '^listening ' "$tmp/srv2.out" 2>/dev/null && break
	sleep 0.1
done

start=$(date +%s)
set +e
head -c 200000 /dev/zero | tr '\0' 'x' | timeout 20 ssh \
	-i "$tmp/id" \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile=/dev/null \
	-o GlobalKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes \
	-o BatchMode=yes \
	-o LogLevel=ERROR \
	-o RekeyLimit=16K \
	-p "$port2" tester@127.0.0.1 "uptime" > /dev/null 2> "$tmp/rekey.err"
rc=$?
set -e
elapsed=$(( $(date +%s) - start ))
kill "$srv_pid" 2>/dev/null || true
srv_pid=""

if [ "$rc" -eq 124 ]; then
	echo "live-sshd: FAIL -- the client hung for ${elapsed}s on a rekey" >&2
	echo "  A rekey request must be answered, even to refuse it." >&2
	exit 1
fi
if ! grep -q 'rekeying is not implemented' "$tmp/rekey.err"; then
	echo "live-sshd: FAIL -- a rekey did not draw our disconnect" >&2
	cat "$tmp/rekey.err" >&2
	cat "$tmp/srv2.err" >&2
	exit 1
fi
echo "ok   live-sshd               a rekey is refused by name in ${elapsed}s, not ignored"
