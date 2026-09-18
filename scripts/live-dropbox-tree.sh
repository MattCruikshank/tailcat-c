#!/bin/sh
# Drive the recursive drop box (`:wo+`) with a real OpenSSH scp and sftp.
#
# live-dropbox does this for the flat mode, where the guarantee is one
# sentence and the tests are the attacks on it. Here the guarantee is
# deliberately weaker -- a sender chooses names and can tell that a directory
# exists -- so this script has two jobs, and the second matters more:
#
#   1. The mode has to *work*. A recursive drop box that refuses `cp -r` is
#      pointless, and the whole reason the trade is worth making is that a
#      tree arrives with its own names and shape.
#   2. Everything the mode did *not* trade away has to still hold, against a
#      real client rather than against requests we constructed. The tempting
#      way to implement this is to loosen the flat mode's checks, and the
#      symptom of having done that is not visible in the happy path.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$(cd "$(dirname "$BUILD")" && pwd)/$(basename "$BUILD")/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-dropbox-tree: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v scp > /dev/null 2>&1 || ! command -v sftp > /dev/null 2>&1; then
	echo "live-dropbox-tree: scp and sftp are needed (apt install openssh-client)" >&2
	# 77 is automake's "skipped", for whoever runs this by hand. The harness
	# decides separately, with --need: make flattens any recipe failure to
	# exit 2, so no exit code survives to mean anything here.
	exit 77
fi

tmp=$(mktemp -d)
cleanup() {
	# Cleanup is the one path that must not stop early: an AND-list ending
	# non-zero trips `set -e` inside a trap, and then the rm never runs.
	if [ -n "${srv_pid:-}" ]; then
		kill "$srv_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# The box sits one level down, so "outside" is a directory this test owns.
# Pointing an escape check at a shared parent means it can fail because of
# somebody else's leftovers, or pass because somebody else tidied up.
mkdir -p "$tmp/box" "$tmp/outside"
printf 'the secret\n' > "$tmp/outside/secret.txt"
printf 'ORIGINAL' > "$tmp/box/existing.txt"

# The tree to send: nested directories, a file in each, and one big enough to
# cross a few SFTP packets.
mkdir -p "$tmp/tree/photos/2024" "$tmp/tree/notes"
printf 'alpha\n' > "$tmp/tree/photos/a.txt"
printf 'beta\n' > "$tmp/tree/photos/2024/b.txt"
printf 'gamma\n' > "$tmp/tree/notes/c.txt"
head -c 60000 /dev/urandom > "$tmp/tree/blob.bin"

ssh-keygen -t ed25519 -N '' -q -C tailcat-c-test -f "$tmp/id"
pub_hex=$(awk '{print $2}' "$tmp/id.pub" | base64 -d | tail -c 32 |
	od -An -v -tx1 | tr -d ' \n')
host_seed=$(printf '%064d' 0 | tr '0' 'a')
base_port=$((47000 + $$ % 8000))
n=0

SSHOPTS="-i $tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o BatchMode=yes -o LogLevel=ERROR"

# start_server runs one single-shot server in the given mode.
start_server() {
	n=$((n + 1))
	port=$((base_port + n))
	"$SSHD" "$port" "$host_seed" "$pub_hex" "$tmp/box" "$1" \
		> "$tmp/srv.$n.out" 2> "$tmp/srv.$n.err" &
	srv_pid=$!
	for _ in $(seq 1 100); do
		grep -q '^listening ' "$tmp/srv.$n.out" 2>/dev/null && return 0
		kill -0 "$srv_pid" 2>/dev/null || break
		sleep 0.1
	done
	echo "live-dropbox-tree: server $n never listened" >&2
	cat "$tmp/srv.$n.err" >&2
	exit 1
}

fail() {
	echo "live-dropbox-tree: FAIL -- $1" >&2
	find "$tmp/box" >&2
	exit 1
}

echo "== a whole tree arrives, with its own names and shape =="
start_server "wo+"
timeout 60 scp $SSHOPTS -r -P "$port" "$tmp/tree" \
	tester@127.0.0.1:tree > /dev/null 2>&1 || true
# Checked on the filesystem rather than on what scp printed: scp reports
# success in situations where nothing happened.
for want in tree/photos/a.txt tree/photos/2024/b.txt tree/notes/c.txt; do
	[ -f "$tmp/box/$want" ] || fail "$want did not arrive"
done
cmp -s "$tmp/tree/blob.bin" "$tmp/box/tree/blob.bin" ||
	fail "the 60000-byte file did not arrive intact"
echo "ok   live-dropbox-tree       scp -r delivered a nested tree intact"

echo "== the names are the sender's, which is the point of the mode =="
# The flat mode renames everything; this one must not, or a tree cannot be
# reassembled. Stated as its own check because it is the thing being bought.
[ -f "$tmp/box/tree/notes/c.txt" ] ||
	fail "a file was stored under a name the sender did not choose"
echo "ok   live-dropbox-tree       requested names were kept"

echo "== nothing escapes, even with directories allowed =="
start_server "wo+"
printf 'escaped' > "$tmp/evil.txt"
timeout 60 scp $SSHOPTS -P "$port" "$tmp/evil.txt" \
	"tester@127.0.0.1:../outside/evil.txt" > /dev/null 2>&1 || true
[ -e "$tmp/outside/evil.txt" ] && fail "a file escaped into ../outside"
timeout 60 scp $SSHOPTS -P "$port" "$tmp/evil.txt" \
	"tester@127.0.0.1:../../evil.txt" > /dev/null 2>&1 || true
[ -e "$tmp/evil.txt.1" ] && fail "a file escaped two levels up"
echo "ok   live-dropbox-tree       ../ did not escape the box"

echo "== and mkdir cannot escape either =="
start_server "wo+"
printf 'mkdir ../outside/planted\nmkdir ../planted\n' |
	timeout 60 sftp $SSHOPTS -P "$port" tester@127.0.0.1 > /dev/null 2>&1 ||
	true
[ -e "$tmp/outside/planted" ] && fail "a directory was made outside the box"
[ -e "$tmp/planted" ] && fail "a directory was made one level up"
echo "ok   live-dropbox-tree       mkdir ../ was refused"

echo "== an existing file is still never overwritten =="
start_server "wo+"
printf 'REPLACED' > "$tmp/replacement.txt"
timeout 60 scp $SSHOPTS -P "$port" "$tmp/replacement.txt" \
	tester@127.0.0.1:existing.txt > /dev/null 2>&1 || true
[ "$(cat "$tmp/box/existing.txt")" = "ORIGINAL" ] ||
	fail "an existing file was overwritten"
echo "ok   live-dropbox-tree       a same-name upload did not overwrite"

echo "== it still cannot be read or listed =="
start_server "wo+"
out=$(printf 'ls\n' | timeout 60 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
printf '%s' "$out" | grep -q 'Permission denied' ||
	fail "the listing was not refused: $out"
printf '%s' "$out" | grep -q 'existing.txt' &&
	fail "the refusal leaked a filename"
echo "ok   live-dropbox-tree       sftp ls was refused and leaked nothing"

start_server "wo+"
out=$(printf 'get existing.txt %s/stolen.txt\n' "$tmp" |
	timeout 60 sftp $SSHOPTS -P "$port" tester@127.0.0.1 2>&1 || true)
[ -e "$tmp/stolen.txt" ] && fail "a file was downloaded from the drop box"
echo "ok   live-dropbox-tree       a download was refused"

echo "== a file the sender did not send stays invisible =="
# The half of the guarantee this mode keeps. Directories are visible, because
# a recursive upload has to resolve its destinations; files are not.
start_server "wo+"
out=$(printf 'ls -l existing.txt\n' | timeout 60 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
printf '%s' "$out" | grep -qi 'not found\|no such file' ||
	fail "stat of somebody else's file did not say \"not found\": $out"
echo "ok   live-dropbox-tree       stat of another sender's file said nothing"

echo "== the flat mode did not acquire any of this =="
# The check that the second mode was added beside the first rather than by
# loosening it -- against a real client, which is where a loosened check
# shows up as an upload that suddenly works.
start_server "wo"
out=$(printf 'mkdir sub\n' | timeout 60 sftp $SSHOPTS -P "$port" \
	tester@127.0.0.1 2>&1 || true)
[ -d "$tmp/box/sub" ] && fail "the flat mode made a directory"
echo "ok   live-dropbox-tree       the flat mode still refuses mkdir"

echo "== the box holds what it should =="
[ "$(cat "$tmp/box/existing.txt")" = "ORIGINAL" ] ||
	fail "existing.txt changed after all that"
[ -d "$tmp/box/tree/photos/2024" ] || fail "the tree is not there any more"
echo "ok   live-dropbox-tree       all checks passed"
