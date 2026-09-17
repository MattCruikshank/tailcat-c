#!/bin/sh
# `tailcat-c parse` against `tailcat parse`, byte for byte.
#
# parse prints JSON so that its output can be piped into something. That only
# means anything if the JSON is the *same* JSON the real tailcat prints: a
# field we name differently, a number we render as a string, an omitempty we
# apply where Go does not, and every jq expression written against upstream
# breaks on ours without saying so.
#
# So the check is not "is it valid JSON" but "is it identical output". The
# addresses come from tools/genaddrs, which builds them with the real Go
# library, so they cover embedded regions, multiple nodes, absent optional
# fields, pre-shared keys and disco keys in whatever combinations the
# generator produces -- not just the ones someone thought to write down.
#
# No network: both binaries only decode a string.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"
COUNT="${COUNT:-500}"

if [ ! -x "$CLI" ]; then
	echo "parse-interop: $CLI not built -- run make first" >&2
	exit 1
fi
if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

(cd tools/genaddrs && GOFLAGS=-mod=mod go run . -count "$COUNT") |
	cut -f1 > "$WORK/addrs"

n=$(wc -l < "$WORK/addrs" | tr -d ' ')
if [ "$n" -lt "$COUNT" ]; then
	echo "parse-interop: genaddrs produced $n of $COUNT addresses" >&2
	exit 1
fi

bad=0
checked=0
withregion=0
withpsk=0
while IFS= read -r a; do
	[ -n "$a" ] || continue
	"$UPSTREAM" parse "$a" > "$WORK/want" 2>"$WORK/want.err" || {
		echo "parse-interop: upstream could not parse an address it made:" >&2
		echo "  $a" >&2
		cat "$WORK/want.err" >&2
		exit 1
	}
	"$CLI" parse "$a" > "$WORK/got" 2>"$WORK/got.err" || {
		echo "parse-interop: we could not parse $a" >&2
		cat "$WORK/got.err" >&2
		bad=$((bad + 1))
		continue
	}
	if ! cmp -s "$WORK/want" "$WORK/got"; then
		echo "parse-interop: output differs for $a" >&2
		diff -u "$WORK/want" "$WORK/got" | head -30 >&2
		bad=$((bad + 1))
		[ "$bad" -ge 3 ] && exit 1
	fi
	grep -q '"Region"' "$WORK/want" && withregion=$((withregion + 1))
	grep -q '"PresharedKey"' "$WORK/want" && withpsk=$((withpsk + 1))
	checked=$((checked + 1))
done < "$WORK/addrs"

if [ "$bad" -ne 0 ]; then
	echo "parse-interop: $bad of $checked addresses printed differently" >&2
	exit 1
fi

# A run where every address took the same shape would pass while testing a
# fraction of the code, which is the shape of bug 20's lesson: a harness that
# stops reaching what it exists to exercise has to say so.
if [ "$withregion" -eq 0 ] || [ "$withpsk" -eq 0 ]; then
	echo "parse-interop: the sample did not cover both forms" >&2
	echo "  embedded regions: $withregion, pre-shared keys: $withpsk" >&2
	exit 1
fi

echo "ok   parse-interop           $checked addresses print identically to the"
echo "                             real tailcat ($withregion with embedded"
echo "                             regions, $withpsk with pre-shared keys)"
