#!/bin/sh
# `tailcat-c cp` delivering into a real `tailcat recv` drop box.
#
# This is the client half of the file-transfer story, and it works today
# because `cp` execs the system scp with us as the ProxyCommand: scp speaks
# SFTP over SSH, and upstream's recv serves exactly that. Nothing here is a
# tailcat-specific file protocol.
#
# The server half -- being a drop box -- needs an SSH server and an SFTP
# server, which are PLAN.md 5.4 and 5.5. See the note there: 3.5's original
# estimate assumed a small bespoke framing format, and that was wrong.
#
# What this pins down is upstream's documented flat-mode behaviour: the
# sender does not choose the stored name, and learns nothing about what is
# already in the directory.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

command -v scp >/dev/null 2>&1 || {
	echo "live-recv: no scp in PATH; skipping" >&2
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

mkdir -p "$WORK/inbox"

# A file already in the drop box, to check that flat mode does not let a
# sender discover or overwrite it.
echo "pre-existing, must not be disturbed" > "$WORK/inbox/secret.txt"

echo "starting the real Go tailcat as a drop box"
"$UPSTREAM" recv "$WORK/inbox" > "$WORK/srv.log" 2>&1 </dev/null &
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
	echo "live-recv: the drop box never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi
grep -E 'Serving files' "$WORK/srv.log" | sed 's/^/    /'

MARK="delivered-by-tailcat-c"
printf '%s\n' "$MARK" > "$WORK/payload.txt"

echo
echo "\$ tailcat-c cp payload.txt <addr>:"
if ! timeout 90 "$CLI" cp "$WORK/payload.txt" "$ADDR:" 2>"$WORK/cp.err"; then
	echo "live-recv: cp failed" >&2
	sed 's/^/    /' "$WORK/cp.err" >&2
	exit 1
fi

LANDED=$(grep -rlF "$MARK" "$WORK/inbox" 2>/dev/null | head -1)
if [ -z "$LANDED" ]; then
	echo "live-recv: nothing arrived in the drop box" >&2
	ls -la "$WORK/inbox" >&2
	sed 's/^/    /' "$WORK/cp.err" >&2
	exit 1
fi
echo "    arrived as $(basename "$LANDED")"

# Upstream's flat mode picks the stored name itself; it is not the one the
# sender used. That is the property that keeps a sender from overwriting
# anything or probing for what is already there.
if [ "$(basename "$LANDED")" = "payload.txt" ]; then
	echo >&2
	echo "live-recv: the file kept the sender's name, so this is not the" >&2
	echo "flat write-only mode we believed we were testing." >&2
	exit 1
fi
echo "    the server chose the name, not the sender"

if ! grep -qF "pre-existing" "$WORK/inbox/secret.txt"; then
	echo "live-recv: the existing file was disturbed" >&2
	exit 1
fi
echo "    the file already in the drop box is untouched"

echo
echo "ok   live-recv                tailcat-c cp delivered into a real"
echo "                              tailcat recv drop box over SFTP"
