#!/bin/sh
# `tailcat-c serve ssh` giving a real OpenSSH client a real shell, through a
# real relay.
#
# live-shell drives the same shell server over a plain TCP socket, which
# proves the pty, the pump, the exit status and the large-output paths. This
# proves the part only the tunnel exercises, and it is a different part: the
# SSH server is a blocking state machine whose bytes arrive through the serve
# event loop, and an interactive session has to move output *while* that loop
# is waiting. On a socket the read callback polls; over the tunnel it drives
# serve_pump_once and then runs the shell's pump. Nothing offline reaches that
# wiring, because nothing offline has a tunnel.
#
# The client half is the system ssh throughout, with tailcat-c as its
# ProxyCommand, so both ends of every check below are real.
set -eu

BUILD="${BUILD:-build/cosmo}"
CLI="$BUILD/tailcat-c"

if [ ! -x "$CLI" ]; then
	echo "live-ssh-serve: $CLI not built -- run make first" >&2
	exit 1
fi
if ! command -v ssh > /dev/null 2>&1 || ! command -v ssh-keygen > /dev/null 2>&1; then
	echo "live-ssh-serve: ssh and ssh-keygen are needed" >&2
	# 77 is automake's "skipped", for whoever runs this by hand. The
	# harness decides separately, with --need: make flattens any recipe
	# failure to exit 2, so no exit code survives to mean anything here.
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

ssh-keygen -t ed25519 -N '' -q -C tailcat-c-live -f "$tmp/id"

SSHOPTS="-i $tmp/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes
	-o BatchMode=yes -o LogLevel=ERROR"

start_server() {
	# $1 is the service word plus any flags, unquoted on purpose.
	# shellcheck disable=SC2086
	"$CLI" -v --timeout 180 serve $1 > "$tmp/srv.out" 2>&1 &
	srv_pid=$!
	ADDR=""
	for _ in $(seq 1 120); do
		ADDR=$(sed -n \
			's/.*address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$tmp/srv.out" |
			head -1)
		[ -n "$ADDR" ] && break
		if ! kill -0 "$srv_pid" 2>/dev/null; then
			echo "live-ssh-serve: the server exited before printing an" \
				"address:" >&2
			cat "$tmp/srv.out" >&2
			exit 1
		fi
		sleep 0.5
	done
	if [ -z "$ADDR" ]; then
		echo "live-ssh-serve: no address was printed:" >&2
		cat "$tmp/srv.out" >&2
		exit 1
	fi
	echo "# address: $(printf '%s' "$ADDR" | cut -c1-24)..."
}

stop_server() {
	kill "$srv_pid" 2>/dev/null || true
	wait "$srv_pid" 2>/dev/null || true
	srv_pid=""
}

fail() {
	echo "live-ssh-serve: FAIL -- $1" >&2
	[ -n "${2:-}" ] && echo "$2" >&2
	cat "$tmp/srv.out" >&2
	exit 1
}

# The authorized key list: this test's own key and nothing else, so an
# accepted session proves the list was consulted rather than bypassed.
pub=$(cat "$tmp/id.pub")

# ---- the warning comes before the address -------------------------------
#
# Checked by line order in the server's own output, because the ordering is
# the point: the address is what gets copied out of a terminal, and a warning
# that it is equivalent to a password is useless after it.
echo "== no-auth-ssh warns before it prints the address =="
start_server "no-auth-ssh"
warn_line=$(grep -n 'WARNING' "$tmp/srv.out" | head -1 | cut -d: -f1)
addr_line=$(grep -n 'address:' "$tmp/srv.out" | head -1 | cut -d: -f1)
[ -n "$warn_line" ] || fail "no warning was printed at all"
[ "$warn_line" -lt "$addr_line" ] ||
	fail "the warning came after the address (line $warn_line vs $addr_line)"
echo "ok   live-ssh-serve          the warning precedes the address"

# ---- and it really does let anyone in -----------------------------------
echo "== no-auth-ssh runs a command for a key it has never seen =="
out=$(timeout 120 "$CLI" ssh "$ADDR" 'echo hello-through-the-tunnel' \
	2>/dev/null || true)
printf '%s' "$out" | grep -q 'hello-through-the-tunnel' ||
	fail "the command's output did not come back" "$out"
echo "ok   live-ssh-serve          a shell ran over the tunnel"
stop_server

# ---- serve ssh consults the list ----------------------------------------
echo "== serve ssh admits a listed key =="
start_server "--ssh-authorized-keys $tmp/id.pub ssh"
out=$(timeout 120 "$CLI" ssh -i "$tmp/id" "$ADDR" 'echo listed-key-ok' \
	2>/dev/null || true)
printf '%s' "$out" | grep -q 'listed-key-ok' ||
	fail "a listed key was not admitted" "$out"
echo "ok   live-ssh-serve          a listed key got a shell"

# ---- the exit status survives the tunnel --------------------------------
#
# Worth its own check here rather than trusting live-shell: the status is
# sent after the last of the output, and the tunnel is where a wind-down
# race would show up.
echo "== the exit status survives the tunnel =="
timeout 120 "$CLI" ssh -i "$tmp/id" "$ADDR" 'exit 42' > /dev/null 2>&1 &&
	rc=0 || rc=$?
[ "$rc" = "42" ] || fail "exit status was $rc, wanted 42"
echo "ok   live-ssh-serve          exit 42 arrived as exit 42"

# ---- a large output, which is where the pump earns its keep -------------
#
# The check live-shell found two truncation bugs with. Over the tunnel it
# also crosses the WireGuard and TCP layers, so a short read anywhere in
# that stack shows up here as a short answer.
echo "== a large output arrives whole =="
lines=$(timeout 180 "$CLI" ssh -i "$tmp/id" "$ADDR" 'seq 1 50000' \
	2>/dev/null | wc -l)
[ "$lines" = "50000" ] ||
	fail "got $lines lines of 50000 -- output was truncated"
echo "ok   live-ssh-serve          50000 lines arrived intact"
stop_server

# ---- an unlisted key is refused -----------------------------------------
#
# The other half of "the list was consulted". Without this, a server that
# ignored the list entirely would pass every check above.
echo "== serve ssh refuses an unlisted key =="
ssh-keygen -t ed25519 -N '' -q -C tailcat-c-stranger -f "$tmp/other"
start_server "--ssh-authorized-keys $tmp/id.pub ssh"
if timeout 60 "$CLI" ssh -i "$tmp/other" "$ADDR" 'echo SHOULD-NOT-RUN' \
	> "$tmp/stranger.out" 2>&1; then
	fail "an unlisted key was admitted" "$(cat "$tmp/stranger.out")"
fi
grep -q 'SHOULD-NOT-RUN' "$tmp/stranger.out" &&
	fail "an unlisted key ran a command"
echo "ok   live-ssh-serve          an unlisted key was refused"

# ---- a forced command ignores what the client asked for -----------------
stop_server
echo "== a forced command is the only thing that runs =="
start_server "--ssh-authorized-keys $tmp/id.pub ssh -- echo forced-only"
out=$(timeout 120 "$CLI" ssh -i "$tmp/id" "$ADDR" 'echo CLIENT-CHOICE' \
	2>/dev/null || true)
printf '%s' "$out" | grep -q 'forced-only' ||
	fail "the forced command did not run" "$out"
printf '%s' "$out" | grep -q 'CLIENT-CHOICE' &&
	fail "the client's own command ran as well"
echo "ok   live-ssh-serve          the forced command replaced the client's"
stop_server

echo "ok   live-ssh-serve          all checks passed"
