#!/bin/sh
# Saved identities, shared between tailcat-c and the real Go tailcat.
#
# A key file is only worth having if it is the *same* key file. So this goes
# both ways: a key tailcat-c writes is used by the Go binary to serve, and a
# key the Go binary writes is used by tailcat-c to serve. In each case a
# client of the other implementation has to reach it.
#
# The property underneath is that the address is a function of the key. If it
# were not, a saved key would not give a stable address, and the whole reason
# for genkey would be gone.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"

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

MSG="saved-key-works"

# The region pinned below must be one this machine would *not* have chosen.
#
# This test used --region 301 and passed throughout the entire period in which
# a saved key's region was thrown away on every start (bug 35). 301 is the
# nearest relay from where it runs, so the server re-probed, landed on 301
# anyway, and the two addresses matched -- for the wrong reason. A test that
# pins the answer the system would have guessed is not testing the pin.
#
# So ask netcheck which region is preferred here and deliberately pin a
# different one. Self-adjusting, because "the nearest relay" depends on who is
# running this.
PREFERRED=$("$CLI" netcheck 2>/dev/null |
	sed -n 's/^ *\([0-9][0-9]*\) .*<- preferred.*/\1/p' | head -1)
REGION=""
for cand in $("$CLI" genkey --key "$WORK/probe.private.json" --region list \
	2>/dev/null | awk '{print $1}'); do
	case "$cand" in
	'' | *[!0-9]*) continue ;;
	esac
	if [ "$cand" != "${PREFERRED:-none}" ]; then
		REGION="$cand"
		break
	fi
done
rm -f "$WORK/probe.private.json"
if [ -z "$REGION" ]; then
	echo "live-genkey: found no region other than the preferred one" >&2
	exit 1
fi
echo "preferred region here is ${PREFERRED:-unknown}; pinning $REGION instead,"
echo "so a server that re-probed would visibly land somewhere else"

# ---- a key we wrote, used by the Go binary --------------------------------
echo "\$ tailcat-c genkey --key $WORK/ours.private.json --region $REGION"
OUR_ADDR=$("$CLI" genkey --key "$WORK/ours.private.json" --region "$REGION")
echo "    address: $(printf '%s' "$OUR_ADDR" | cut -c1-28)..."

PERMS=$(ls -l "$WORK/ours.private.json" | cut -c1-10)
echo "    mode: $PERMS"
case "$PERMS" in
-rw-------) ;;
*)
	echo "live-genkey: the key file is not 0600; it holds a private key and" >&2
	echo "the pre-shared key, and every byte of it is secret." >&2
	exit 1
	;;
esac

echo
echo "\$ tailcat serve --key $WORK/ours.private.json     # the GO binary"
"$UPSTREAM" --key "$WORK/ours.private.json" serve > "$WORK/go.log" 2>&1 \
	</dev/null &
SRV_PID=$!

GO_ADDR=""
i=0
while [ $i -lt 40 ]; do
	# With a saved key the Go binary says "with saved key ...:" rather
	# than "new address:", so match the address itself. It is long, which
	# is what keeps this from matching an ordinary word starting "tc".
	GO_ADDR=$(grep -o 'tc[A-Za-z0-9_-]\{60,\}' "$WORK/go.log" | head -1)
	[ -n "$GO_ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$GO_ADDR" ]; then
	echo "live-genkey: the Go binary would not use our key:" >&2
	cat "$WORK/go.log" >&2
	exit 1
fi

# The address the Go binary derived from our key must be the one we printed.
# A key that produced a different address on each side would be no better
# than no key at all.
if [ "$GO_ADDR" != "$OUR_ADDR" ]; then
	echo >&2
	echo "live-genkey: the Go binary derived a DIFFERENT address from the" >&2
	echo "same key file." >&2
	echo "  ours: $OUR_ADDR" >&2
	echo "  go:   $GO_ADDR" >&2
	exit 1
fi
echo "    the Go binary derived the same address from our key"

printf '%s\n' "$MSG" | timeout 60 "$CLI" "$GO_ADDR" > "$WORK/out1" 2>&1 || true
sleep 1
if ! grep -qF "$MSG" "$WORK/go.log"; then
	echo "live-genkey: could not pipe to the Go server using our key" >&2
	cat "$WORK/go.log" >&2
	exit 1
fi
echo "    and a client reached it"
kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""

# ---- a key the Go binary wrote, used by us --------------------------------
echo
echo "\$ tailcat genkey --key $WORK/theirs.private.json --region $REGION"
THEIR_ADDR=$("$UPSTREAM" genkey --key "$WORK/theirs.private.json" \
	--region "$REGION" 2>/dev/null)

echo "\$ tailcat-c serve --key $WORK/theirs.private.json"
"$CLI" -v --key "$WORK/theirs.private.json" serve > "$WORK/ours.out" \
	2>"$WORK/ours.log" </dev/null &
SRV_PID=$!

OURS_ADDR=""
i=0
while [ $i -lt 60 ]; do
	OURS_ADDR=$(grep -o 'tc[A-Za-z0-9_-]\{60,\}' "$WORK/ours.log" | head -1)
	[ -n "$OURS_ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$OURS_ADDR" ]; then
	echo "live-genkey: we would not use the Go binary's key:" >&2
	cat "$WORK/ours.log" >&2
	exit 1
fi
if [ "$OURS_ADDR" != "$THEIR_ADDR" ]; then
	echo >&2
	echo "live-genkey: we derived a DIFFERENT address from their key." >&2
	echo "  theirs: $THEIR_ADDR" >&2
	echo "  ours:   $OURS_ADDR" >&2
	exit 1
fi
echo "    we derived the same address from their key"

printf '%s\n' "$MSG" | timeout 60 "$UPSTREAM" "$OURS_ADDR" >/dev/null 2>&1 \
	|| true
sleep 1
if ! grep -qF "$MSG" "$WORK/ours.out"; then
	echo "live-genkey: the Go client could not reach us on their key" >&2
	cat "$WORK/ours.log" >&2
	exit 1
fi
echo "    and the Go client reached it"

echo
echo "ok   live-genkey              a saved identity is the same identity in"
echo "                              both implementations, in both directions"
