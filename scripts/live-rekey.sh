#!/bin/sh
# Does a tailcat-c session survive a WireGuard rekey against the real thing?
#
# This is the only check that can answer that. Every other live test finishes
# in seconds, and a session built once and never renewed works perfectly for
# two minutes -- so the bug this exists to catch is invisible to all of them.
#
# WireGuard renews at 120 seconds and refuses a session past 180. The test
# holds one connection open for five minutes, dribbling a numbered line every
# twenty seconds, and requires the Go server to print the lines from *after*
# both boundaries. A tunnel that cannot rekey goes quiet at 180 seconds and
# the late lines never appear.
#
# It takes about six minutes of real time. That is the point: there is no
# shortcut to proving this one.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

INTERVAL="${INTERVAL:-20}"
LINES="${LINES:-15}"
RUNTIME=$((INTERVAL * LINES))
BUDGET=$((RUNTIME + 90))

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

OUT=$(mktemp)
ERR=$(mktemp)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	rm -f "$OUT" "$ERR"
}
trap cleanup EXIT

echo "starting a real tailcat server..."
"$UPSTREAM" > "$OUT" 2>&1 &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' "$OUT" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "live-rekey: the server never printed an address:" >&2
	cat "$OUT" >&2
	exit 1
fi
RESOLVED=$("$UPSTREAM" resolve "$ADDR")

echo
echo "holding one connection open for ${RUNTIME}s, a line every ${INTERVAL}s."
echo "WireGuard rekeys at 120s and rejects a session past 180s, so the lines"
echo "after those marks are the ones that matter."
echo

START=$(date +%s)
(
	n=0
	while [ $n -lt $LINES ]; do
		echo "rekey-probe $n at t=$((n * INTERVAL))s"
		n=$((n + 1))
		sleep "$INTERVAL"
	done
) | "$CLI" -v --timeout "$BUDGET" "$RESOLVED" > /dev/null 2> "$ERR" || true
ELAPSED=$(($(date +%s) - START))

echo "tailcat-c ran for ${ELAPSED}s. Its own log:"
sed 's/^/    /' "$ERR" | head -20

sleep 2

# The last line is sent at (LINES-1)*INTERVAL seconds. Everything must arrive,
# but the ones past 180 seconds are the proof.
missing=""
n=0
while [ $n -lt $LINES ]; do
	if ! grep -qF "rekey-probe $n " "$OUT"; then
		missing="$missing $n"
	fi
	n=$((n + 1))
done

echo
echo "what the go server received:"
grep -c "rekey-probe" "$OUT" | sed 's/^/    /;s/$/ of '"$LINES"' lines/'

# Delivery alone is not proof that *we* rekeyed: WireGuard is deliberately
# redundant, and the Go server renews the session at its own threshold if we
# do not. Disabling our rekey timer still passes a delivery-only check. So the
# summary line has to show that this side initiated a renewal too.
REKEYS=$(sed -n 's/.*wg: .*rekeys=\([0-9][0-9]*\).*/\1/p' "$ERR" | tail -1)
INITIATED=$(sed -n 's/.*wg: initiated=\([0-9][0-9]*\).*/\1/p' "$ERR" | tail -1)
echo "    this side initiated ${INITIATED:-?} handshakes and rotated keys ${REKEYS:-?} times"

if [ -n "$missing" ]; then
	echo >&2
	echo "live-rekey: FAILED. Missing lines:$missing" >&2
	echo "A gap starting around line $((180 / INTERVAL)) is the rekey not working:" >&2
	echo "that is where the first session passes REJECT_AFTER_TIME." >&2
	echo "--- server output ---" >&2
	cat "$OUT" >&2
	exit 1
fi

if [ -z "$REKEYS" ] || [ "$REKEYS" -lt 1 ]; then
	echo >&2
	echo "live-rekey: every line arrived, but this side never rotated a key." >&2
	echo "The Go server must have carried the renewal on its own, so this run" >&2
	echo "proves the responder path and nothing about our rekey timer." >&2
	sed 's/^/    /' "$ERR" >&2
	exit 1
fi
if [ -z "$INITIATED" ] || [ "$INITIATED" -lt 2 ]; then
	echo >&2
	echo "live-rekey: only ${INITIATED:-0} handshake(s) initiated from here;" >&2
	echo "the renewal at 120s did not come from us." >&2
	exit 1
fi

LAST=$((( LINES - 1 ) * INTERVAL))
echo
echo "ok   live-rekey               one session carried traffic for ${LAST}s"
echo "                              to a real tailcat server, across ${REKEYS}"
echo "                              key rotations we initiated ourselves"
