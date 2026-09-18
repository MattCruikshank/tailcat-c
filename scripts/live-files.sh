#!/bin/sh
# Drive `serve files` with a real OpenSSH sftp and scp.
#
# test_fileserv.c checks the policy against requests this project constructs,
# which leaves the thing that matters unproven: whether the fence still holds
# when a real client is doing the asking. A client sends requests we did not
# think to build -- sftp resolves and stats before it fetches, scp opens with
# flags we did not predict, and both of them walk directories in their own
# order -- so a policy that is right against our own vectors can still have a
# gap a real client falls through.
#
# There are two halves here and they are different in kind. The read-only
# half has to *work*: a served directory that refuses everything would pass
# any number of attack tests. The rest are the attacks, and for those the
# check is on the filesystem afterwards rather than on what the client
# printed -- scp and sftp both report success in situations where nothing
# happened.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$(cd "$(dirname "$BUILD")" && pwd)/$(basename "$BUILD")/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-files: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v scp > /dev/null 2>&1 || ! command -v sftp > /dev/null 2>&1; then
	echo "live-files: scp and sftp are needed (apt install openssh-client)" >&2
	# 77 is automake's "skipped", and it is for whoever runs this by hand.
	# Every stage reaches this through make, and make flattens any recipe
	# failure to exit 2, so no exit code survives to mean anything specific.
	# The harness decides separately, with --need.
	exit 77
fi

tmp=$(mktemp -d)
cleanup() {
	# Cleanup is the one path that must not stop early: an AND-list that
	# ends non-zero trips `set -e` inside a trap, and then the rm never
	# runs and the script exits 1 with every check passed.
	if [ -n "${srv_pid:-}" ]; then
		kill "$srv_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/pub/sub" "$tmp/outside"
printf 'the published file\n' > "$tmp/pub/hello.txt"
head -c 40000 /dev/urandom > "$tmp/pub/blob.bin"
printf 'nested\n' > "$tmp/pub/sub/nested.txt"
printf 'the secret\n' > "$tmp/outside/secret.txt"
# A link out of the tree. If the filesystem will not make one the symlink
# cases are skipped and say so rather than passing quietly.
if ln -s "$tmp/outside/secret.txt" "$tmp/pub/escape.txt" 2> /dev/null; then
	have_links=1
else
	have_links=0
fi

ssh-keygen -t ed25519 -N '' -C tailcat-c-test -f "$tmp/id" > /dev/null
pub_hex=$(awk '{print $2}' "$tmp/id.pub" | base64 -d | tail -c 32 |
	od -An -v -tx1 | tr -d ' \n')
host_seed=$(printf '%064d' 0 | tr '0' 'a')
base_port=$((39000 + $$ % 15000))
n=0

SSHOPTS="-i $tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o BatchMode=yes -o LogLevel=ERROR"

# start_server runs one single-shot server in the given mode.
start_server() {
	n=$((n + 1))
	port=$((base_port + n))
	"$SSHD" "$port" "$host_seed" "$pub_hex" "$tmp/pub" "$1" \
		> "$tmp/srv.$n.out" 2> "$tmp/srv.$n.err" &
	srv_pid=$!
	for _ in $(seq 1 100); do
		grep -q '^listening ' "$tmp/srv.$n.out" 2>/dev/null && return 0
		kill -0 "$srv_pid" 2>/dev/null || break
		sleep 0.1
	done
	echo "live-files: server $n never listened" >&2
	cat "$tmp/srv.$n.err" >&2
	exit 1
}

fail() {
	echo "live-files: FAIL -- $1" >&2
	ls -la "$tmp/pub" >&2
	exit 1
}

cd "$tmp"

echo "== read-only: a download works =="
start_server ro
timeout 30 scp $SSHOPTS -P "$port" tester@127.0.0.1:blob.bin \
	"$tmp/got.bin" > /dev/null 2>&1 || fail "scp exited non-zero"
cmp -s "$tmp/pub/blob.bin" "$tmp/got.bin" ||
	fail "the downloaded file does not match"
echo "ok   live-files              scp fetched 40000 bytes intact"

echo "== read-only: a listing works and is complete =="
start_server ro
out=$(printf 'ls\n' | timeout 30 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
# All three real entries, from a server that answers READDIR one name at a
# time: this is the check that the loop actually loops rather than stopping
# after the first reply.
for want in hello.txt blob.bin sub; do
	printf '%s' "$out" | grep -q "$want" ||
		fail "the listing is missing $want: $out"
done
echo "ok   live-files              sftp ls returned every entry"

echo "== read-only: a nested path works =="
start_server ro
out=$(printf 'get sub/nested.txt %s/nested.got\n' "$tmp" |
	timeout 30 sftp $SSHOPTS -P "$port" tester@127.0.0.1 2>&1 || true)
cmp -s "$tmp/pub/sub/nested.txt" "$tmp/nested.got" ||
	fail "a file one level down did not come back: $out"
echo "ok   live-files              a file below the root came back intact"

echo "== read-only: an upload is refused =="
printf 'REPLACED' > "$tmp/replacement.txt"
start_server ro
timeout 30 scp $SSHOPTS -P "$port" "$tmp/replacement.txt" \
	tester@127.0.0.1:hello.txt > /dev/null 2>&1 || true
[ "$(cat "$tmp/pub/hello.txt")" = "the published file" ] ||
	fail "a read-only server was written to"
[ -e "$tmp/pub/replacement.txt" ] && fail "a read-only server took a new file"
echo "ok   live-files              a read-only server refused both writes"

echo "== nothing escapes the root =="
start_server ro
out=$(printf 'get ../outside/secret.txt %s/leak.txt\n' "$tmp" |
	timeout 30 sftp $SSHOPTS -P "$port" tester@127.0.0.1 2>&1 || true)
[ -e "$tmp/leak.txt" ] && fail "a file outside the root was downloaded"
echo "ok   live-files              ../outside/secret.txt was not served"

start_server ro
out=$(printf 'ls /\nls ..\n' | timeout 30 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
# "/" is the root, so it lists; ".." is above it, so it must not. A listing
# of the real parent would show `outside`, which is the tell.
printf '%s' "$out" | grep -q 'outside' &&
	fail "a listing reached above the root: $out"
echo "ok   live-files              .. did not list the parent directory"

if [ "$have_links" = 1 ]; then
	echo "== a symlink out of the tree is refused =="
	start_server ro
	timeout 30 sftp $SSHOPTS -P "$port" tester@127.0.0.1 \
		> /dev/null 2>&1 << EOF || true
get escape.txt $tmp/via-link.txt
EOF
	[ -e "$tmp/via-link.txt" ] && fail "a symlink was followed out of the root"
	echo "ok   live-files              a symlink out of the tree was not followed"
else
	echo "skip live-files              symlink cases (no symlinks here)"
fi

echo "== read-write: an upload works =="
start_server rw
timeout 30 scp $SSHOPTS -P "$port" "$tmp/replacement.txt" \
	tester@127.0.0.1:uploaded.txt > /dev/null 2>&1 ||
	fail "scp to a read-write server exited non-zero"
[ "$(cat "$tmp/pub/uploaded.txt" 2> /dev/null)" = "REPLACED" ] ||
	fail "the upload did not arrive"
echo "ok   live-files              scp uploaded to a read-write server"

echo "== read-write: the fence has not moved =="
start_server rw
timeout 30 scp $SSHOPTS -P "$port" "$tmp/replacement.txt" \
	"tester@127.0.0.1:../outside/planted.txt" > /dev/null 2>&1 || true
[ -e "$tmp/outside/planted.txt" ] &&
	fail "a read-write server wrote outside its root"
echo "ok   live-files              a read-write server still refused ../outside"

echo "== the served directory holds what it should =="
# The whole point, stated as an inventory: everything that was there is
# still there, plus exactly the one file that was legitimately uploaded.
have=$(ls -A "$tmp/pub" | sort | tr '\n' ' ')
if [ "$have_links" = 1 ]; then
	want="blob.bin escape.txt hello.txt sub uploaded.txt "
else
	want="blob.bin hello.txt sub uploaded.txt "
fi
[ "$have" = "$want" ] || fail "the directory holds \"$have\", wanted \"$want\""
echo "ok   live-files              the directory holds exactly what it should"

echo "ok   live-files              all checks passed"
