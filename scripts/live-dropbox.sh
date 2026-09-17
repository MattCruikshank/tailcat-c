#!/bin/sh
# Drive the write-only drop box with a real OpenSSH scp and sftp.
#
# test_dropbox.c checks the policy against requests this project constructs.
# That leaves one thing unproven and it is the thing that matters: whether the
# refusals still hold when a real client is doing the asking. A client sends
# requests we did not think to build -- scp opens with flags we did not
# predict, sftp resolves paths before it does anything -- and a policy that is
# right against our own test vectors can still have a gap a real client walks
# through.
#
# So each case below is an attack carried out by the genuine tool, and the
# check is on the filesystem afterwards rather than on what the client printed.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$BUILD/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-dropbox: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v scp > /dev/null 2>&1 || ! command -v sftp > /dev/null 2>&1; then
	echo "live-dropbox: scp and sftp are needed (apt install openssh-client)" >&2
	exit 2
fi

tmp=$(mktemp -d)
cleanup() {
	[ -n "${srv_pid:-}" ] && kill "$srv_pid" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/box" "$tmp/outside"
ssh-keygen -t ed25519 -N '' -C tailcat-c-test -f "$tmp/id" > /dev/null
pub_hex=$(awk '{print $2}' "$tmp/id.pub" | base64 -d | tail -c 32 |
	od -An -v -tx1 | tr -d ' \n')
host_seed=$(printf '%064d' 0 | tr '0' 'a')
base_port=$((21000 + $$ % 18000))
n=0

SSHOPTS="-i $tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o BatchMode=yes -o LogLevel=ERROR"

# start_server runs one single-shot server and waits for it to listen.
start_server() {
	n=$((n + 1))
	port=$((base_port + n))
	"$SSHD" "$port" "$host_seed" "$pub_hex" "$tmp/box" \
		> "$tmp/srv.$n.out" 2> "$tmp/srv.$n.err" &
	srv_pid=$!
	for _ in $(seq 1 100); do
		grep -q '^listening ' "$tmp/srv.$n.out" 2>/dev/null && return 0
		kill -0 "$srv_pid" 2>/dev/null || break
		sleep 0.1
	done
	echo "live-dropbox: server $n never listened" >&2
	cat "$tmp/srv.$n.err" >&2
	exit 1
}

fail() {
	echo "live-dropbox: FAIL -- $1" >&2
	ls -la "$tmp/box" >&2
	exit 1
}

echo "== an ordinary upload works =="
head -c 50000 /dev/urandom > "$tmp/payload.bin"
start_server
timeout 30 scp $SSHOPTS -P "$port" "$tmp/payload.bin" \
	tester@127.0.0.1:payload.bin > /dev/null 2>&1 || fail "scp exited non-zero"
cmp -s "$tmp/payload.bin" "$tmp/box/payload.bin" ||
	fail "the uploaded file does not match"
echo "ok   live-dropbox            scp delivered 50000 bytes intact"

echo "== a traversal stays in the box =="
echo "escaped" > "$tmp/evil.txt"
start_server
# Exit status is not the check here: what matters is where the bytes landed.
timeout 30 scp $SSHOPTS -P "$port" "$tmp/evil.txt" \
	"tester@127.0.0.1:../../evil.txt" > /dev/null 2>&1 || true
[ -e "$tmp/outside/evil.txt" ] && fail "a file escaped into ../outside"
[ -e "$tmp/evil.txt.1" ] && fail "a file escaped one level up"
[ -e "$tmp/box/evil.txt" ] || fail "the file did not land in the box either"
echo "ok   live-dropbox            ../../evil.txt landed inside the box"

echo "== an upload cannot overwrite =="
printf 'ORIGINAL' > "$tmp/box/existing.txt"
printf 'REPLACED' > "$tmp/replacement.txt"
start_server
timeout 30 scp $SSHOPTS -P "$port" "$tmp/replacement.txt" \
	"tester@127.0.0.1:existing.txt" > /dev/null 2>&1 || true
[ "$(cat "$tmp/box/existing.txt")" = "ORIGINAL" ] ||
	fail "an existing file was overwritten"
echo "ok   live-dropbox            an existing file survived a same-name upload"

echo "== the directory cannot be listed =="
start_server
out=$(printf 'ls\n' | timeout 30 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
# The listing must be refused, and the refusal must not name what is there.
printf '%s' "$out" | grep -q 'Permission denied' ||
	fail "readdir was not refused: $out"
printf '%s' "$out" | grep -q 'existing.txt' &&
	fail "the refusal leaked a filename"
echo "ok   live-dropbox            sftp ls was refused and leaked nothing"

echo "== a file cannot be read back =="
start_server
out=$(printf 'get existing.txt\n' | timeout 30 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
[ -e existing.txt ] && { rm -f existing.txt; fail "a file was downloaded"; }
# "not found" rather than "permission denied" is the point: a sender must not
# be able to confirm that a name exists, and a denial would confirm it.
#
# Note which barrier this exercises. sftp gives up at the stat, so it never
# reaches the open -- which means the refusal of a read-open is covered by
# test_dropbox.c and not here. Two independent barriers, one tested at each
# level; removing the inner one alone does not fail this script, and that is
# a fact about the test rather than a gap in the server.
printf '%s' "$out" | grep -q 'not found' ||
	fail "a read was not refused as a missing file: $out"
echo "ok   live-dropbox            a download was refused without confirming the file"

echo "== the box holds what it should and nothing else =="
# payload.bin, evil.txt, existing.txt, existing.txt.1 -- and the last is the
# refused overwrite, stored under a name the server chose.
[ -f "$tmp/box/existing.txt.1" ] ||
	fail "the refused overwrite was not kept under a new name"
echo "ok   live-dropbox            the refused overwrite was kept as existing.txt.1"
