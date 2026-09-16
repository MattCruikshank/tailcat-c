#!/bin/sh
# `tailcat-c ssh` and `cp` against the real Go tailcat's SSH server.
#
# Nothing here implements SSH. tailcat-c execs the system ssh with a
# ProxyCommand that runs tailcat-c itself in pipe mode, so the chain is:
#
#   ssh -> tailcat-c (pipe) -> DERP -> WireGuard -> real Go tailcat's sshd
#
# Which means a pass proves three things at once: the ProxyCommand quoting is
# right, the pipe carries an interactive protocol rather than just a blob, and
# the short destination name does not confuse ssh.
#
# Upstream's `serve no-auth-ssh` is an auth-free SSH server, which is what
# makes this testable without provisioning keys.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

command -v ssh >/dev/null 2>&1 || {
	echo "live-ssh: no ssh client in PATH; skipping" >&2
	exit 0
}

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "starting the real Go tailcat with an auth-free SSH server"
"$UPSTREAM" serve no-auth-ssh > "$WORK/srv.log" 2>&1 </dev/null &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$WORK/srv.log" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-ssh: the Go server never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

MARK="ssh-went-through-the-tunnel"

echo
echo "\$ tailcat-c ssh <addr> echo $MARK"
OUT=$(timeout 90 "$CLI" ssh "$ADDR" "echo $MARK" 2>"$WORK/ssh.err" || true)
echo "    got: $OUT"

if ! printf '%s' "$OUT" | grep -qF "$MARK"; then
	echo >&2
	echo "live-ssh: the remote command's output did not come back." >&2
	echo "--- ssh stderr ---" >&2
	sed 's/^/    /' "$WORK/ssh.err" >&2
	echo "--- server log ---" >&2
	tail -20 "$WORK/srv.log" >&2
	exit 1
fi

echo
echo "\$ tailcat-c cp <addr>:/etc/hostname ..."
printf '%s\n' "$MARK" > "$WORK/src.txt"
if timeout 90 "$CLI" cp "$WORK/src.txt" "$ADDR:$WORK/dst.txt" \
     2>"$WORK/cp.err"; then
	if [ -f "$WORK/dst.txt" ] && grep -qF "$MARK" "$WORK/dst.txt"; then
		echo "    a file copied through the tunnel and arrived intact"
	else
		echo "live-ssh: scp reported success but the file is wrong" >&2
		sed 's/^/    /' "$WORK/cp.err" >&2
		exit 1
	fi
else
	echo "live-ssh: scp failed" >&2
	sed 's/^/    /' "$WORK/cp.err" >&2
	exit 1
fi

echo
echo "ok   live-ssh                 the system ssh and scp reached a real"
echo "                              tailcat SSH server through our tunnel"
