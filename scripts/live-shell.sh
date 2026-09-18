#!/bin/sh
# Drive `serve ssh` with a real OpenSSH client.
#
# A shell is not like the other services. The drop box and the file server
# answer questions -- one request, one reply, and a test can check the reply.
# A shell produces output whether or not anyone is typing, carries an exit
# status, and has to keep both directions moving at once. None of that is
# visible to a test that only checks whether the session opened.
#
# So each case here is something that only works if the *pumping* is right,
# and the last one is the important one: a large output has to arrive whole.
# Two separate bugs made it arrive truncated -- once because the drain loop
# stopped when the child exited rather than when its output ended, and once
# because closing a socket with unread bytes on it sends RST and discards
# whatever had not left the send buffer. Both produced a plausible-looking
# transfer that was simply short, and neither was visible in any smaller test.
set -eu

BUILD="${BUILD:-build/cosmo}"
SSHD="$(cd "$(dirname "$BUILD")" && pwd)/$(basename "$BUILD")/livesshd"

if [ ! -x "$SSHD" ]; then
	echo "live-shell: $SSHD not built -- run make first" >&2
	exit 1
fi
if ! command -v ssh > /dev/null 2>&1; then
	echo "live-shell: ssh is needed (apt install openssh-client)" >&2
	exit 77
fi

tmp=$(mktemp -d)
cleanup() {
	if [ -n "${srv_pid:-}" ]; then
		kill "$srv_pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

ssh-keygen -t ed25519 -N '' -q -C tailcat-c-test -f "$tmp/id"
pub_hex=$(awk '{print $2}' "$tmp/id.pub" | base64 -d | tail -c 32 |
	od -An -v -tx1 | tr -d ' \n')
host_seed=$(printf '%064d' 0 | tr '0' 'a')
base_port=$((23000 + $$ % 15000))
n=0

SSHOPTS="-i $tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o BatchMode=yes -o LogLevel=ERROR"

start_server() {
	n=$((n + 1))
	port=$((base_port + n))
	"$SSHD" "$port" "$host_seed" "$pub_hex" shell \
		> "$tmp/srv.$n.out" 2> "$tmp/srv.$n.err" &
	srv_pid=$!
	for _ in $(seq 1 100); do
		grep -q '^listening ' "$tmp/srv.$n.out" 2>/dev/null && return 0
		kill -0 "$srv_pid" 2>/dev/null || break
		sleep 0.1
	done
	echo "live-shell: server $n never listened" >&2
	cat "$tmp/srv.$n.err" >&2
	exit 1
}

fail() {
	echo "live-shell: FAIL -- $1" >&2
	[ -n "${2:-}" ] && echo "$2" >&2
	exit 1
}

echo "== a remote command runs and its output comes back =="
start_server
out=$(timeout 30 ssh $SSHOPTS -p "$port" tester@127.0.0.1 \
	'echo hello-from-exec' 2>/dev/null || true)
printf '%s' "$out" | grep -q 'hello-from-exec' ||
	fail "the command's output did not come back" "$out"
echo "ok   live-shell              a remote command ran"

echo "== the exit status is the command's =="
# The whole point of carrying exit-status: a script that runs something over
# the tunnel has to be able to tell success from failure.
start_server
timeout 30 ssh $SSHOPTS -p "$port" tester@127.0.0.1 'exit 42' \
	> /dev/null 2>&1 && rc=0 || rc=$?
[ "$rc" = "42" ] || fail "exit status was $rc, wanted 42"
echo "ok   live-shell              exit 42 arrived as exit 42"

echo "== stdin reaches the command =="
start_server
out=$(printf 'one\ntwo\nthree\n' | timeout 30 ssh $SSHOPTS -p "$port" \
	tester@127.0.0.1 'wc -l' 2>/dev/null || true)
[ "$(printf '%s' "$out" | tr -d ' \r\n')" = "3" ] ||
	fail "wc -l saw \"$out\", wanted 3"
echo "ok   live-shell              stdin was delivered and ended"

echo "== a pty, when one is asked for =="
start_server
out=$(printf 'echo TTYCOUNT=$(tty | grep -c pts)\necho TERMIS=$TERM\nexit\n' |
	timeout 30 ssh $SSHOPTS -tt -p "$port" tester@127.0.0.1 2>&1 |
	tr -d '\r' || true)
# `tty` naming a pts device is the only proof that this is a real terminal
# and not a pipe with a hopeful name. Wrapped in a marker rather than matched
# on its own line: an interactive session carries bracketed-paste escapes that
# arrive glued to the front of the output, so "^1$" never matches.
printf '%s' "$out" | grep -q 'TTYCOUNT=1' ||
	fail "the shell did not get a terminal" "$out"
printf '%s' "$out" | grep -q 'TERMIS=xterm' ||
	fail "TERM did not reach the shell" "$out"
echo "ok   live-shell              an interactive shell got a real pty"

echo "== and no pty when one is not =="
start_server
out=$(printf 'echo no-tty-ok\nexit\n' |
	timeout 30 ssh $SSHOPTS -T -p "$port" tester@127.0.0.1 2>&1 |
	tr -d '\r' || true)
printf '%s' "$out" | grep -q 'no-tty-ok' ||
	fail "a shell without a pty did not run" "$out"
echo "ok   live-shell              ssh -T got a working shell on a pipe"

echo "== a large output arrives whole =="
# The one that found two bugs. 200000 lines is about 1.2MB, which is several
# times the channel window, so it exercises the window-adjust path, the
# queue, and the shutdown -- none of which a short command touches.
start_server
lines=$(timeout 60 ssh $SSHOPTS -p "$port" tester@127.0.0.1 \
	'seq 1 200000' 2>/dev/null | wc -l)
[ "$lines" = "200000" ] ||
	fail "got $lines lines of 200000 -- output was truncated"
echo "ok   live-shell              200000 lines arrived intact"

echo "== and is not duplicated =="
# The other way a buffered pump goes wrong: re-sending what it already sent
# when a partial write reports "not now". Checked by content, not by count,
# because a duplicate that replaces a line keeps the count the same.
start_server
sum=$(timeout 60 ssh $SSHOPTS -p "$port" tester@127.0.0.1 \
	'seq 1 100000' 2>/dev/null | sort -n | uniq | wc -l)
[ "$sum" = "100000" ] ||
	fail "saw $sum distinct lines of 100000 -- output was duplicated"
echo "ok   live-shell              no line arrived twice"

echo "ok   live-shell              all checks passed"
