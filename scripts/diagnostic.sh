#!/bin/sh
# Tiered local checks, numbered like Starfleet diagnostics: level 5 is the
# quick automated sweep, level 1 is the one where you take the panels off.
#
#   level 5   seconds      "did I just break the build"
#   level 3   minutes      the pre-push default
#   level 1   long         pre-release; talks to the network and the real
#                          tailcat, and is the only level that proves interop
#
# Levels 4 and 2 are deliberately undefined rather than missing. Three tiers
# is what the work actually divides into, and inventing two more would mean
# inventing distinctions nobody would remember.
#
# Every stage prints its own elapsed time, so the cost of each level is a
# measured fact rather than an estimate in a comment.
#
# Usage: sh scripts/diagnostic.sh [1|3|5]
set -eu

LEVEL="${1:-3}"
case "$LEVEL" in
1 | 3 | 5) ;;
*)
	echo "usage: $0 [1|3|5]   (1 = most thorough)" >&2
	exit 2
	;;
esac

START=$(date +%s)
FAILED=""

hms() {
	m=$(($1 / 60))
	s=$(($1 % 60))
	if [ "$m" -gt 0 ]; then printf '%dm%02ds' "$m" "$s"; else printf '%ds' "$s"; fi
}

# stage NAME COMMAND -- runs it, times it, and keeps going on failure so one
# broken thing does not hide the state of everything after it.
stage() {
	name="$1"
	shift
	printf '\n=== %s\n' "$name"
	t0=$(date +%s)
	if sh -c "$*"; then
		printf '    ok   %s [%s]\n' "$name" "$(hms $(($(date +%s) - t0)))"
	else
		printf '    FAIL %s [%s]\n' "$name" "$(hms $(($(date +%s) - t0)))"
		FAILED="$FAILED
      $name"
	fi
}

echo "tailcat-c: level $LEVEL diagnostic"

# ---- level 1 starts from nothing ---------------------------------------
#
# The whole point of the deepest level is that it does not trust anything
# already on disk. A stale object compiled against an older struct linked
# cleanly for the entire history of this project and crashed three call
# frames from the change that exposed it; only a clean build rules that out.
if [ "$LEVEL" -eq 1 ]; then
	stage "clean" "rm -rf build"
fi

# ---- every level: the fat build and the unit tests ----------------------
stage "cosmocc build + tests (fat APE)" "make test"

# ---- levels 3 and 1: the second toolchain -------------------------------
#
# This is where four of the first six bugs in this project came from. Host
# gcc with the sanitizers sees things cosmocc does not, and vice versa, so
# running one without the other is running half the check.
if [ "$LEVEL" -le 3 ]; then
	stage "host gcc + ASan/UBSan build + tests" \
		"make CC=gcc SANITIZE=1 test"

	# The iteration counts differ by more than the level does. At level 3 this
	# is a smoke test -- proof the harnesses still run and nothing obvious
	# regressed -- and it has to stay short enough that nobody resents it.
	# Real fuzzing is a level 1 job. fuzz_crypto gets a much smaller share at
	# both levels because every iteration does actual elliptic-curve work and
	# costs orders of magnitude more than a parser iteration.
	if [ "$LEVEL" -eq 1 ]; then
		ITERS=1000000
		CRYPTO_ITERS=50000
	else
		ITERS=50000
		CRYPTO_ITERS=1000
	fi
	stage "property fuzzing ($ITERS iterations, $CRYPTO_ITERS for crypto)" \
		"make fuzz >/dev/null && fail=0; \
		 for f in build/cosmo/fuzz_*; do \
		   case \$f in *fuzz_crypto) n=$CRYPTO_ITERS ;; *) n=$ITERS ;; esac; \
		   ./\$f \$n || fail=1; \
		 done; exit \$fail"

	stage "differential crosscheck against Go" "make interop"
fi

# ---- level 1 only: generated files, and the network ---------------------
if [ "$LEVEL" -eq 1 ]; then
	# A stale generated header is a test that has quietly stopped checking
	# what it claims to. Regenerating into a scratch copy and diffing is the
	# only way to notice.
	stage "generated vectors are current" '
		cp tests/crypto_vectors.h /tmp/vectors.before &&
		(cd tools/genvectors && GOFLAGS=-mod=mod go run .) &&
		if diff -q /tmp/vectors.before tests/crypto_vectors.h >/dev/null; then
			echo "    tests/crypto_vectors.h matches its generator"
		else
			echo "    tests/crypto_vectors.h is STALE -- commit the regenerated file" >&2
			cp /tmp/vectors.before tests/crypto_vectors.h
			exit 1
		fi'

	# Live interop. These dial Tailscale production relays and run a real
	# tailcat, which is exactly why they are not in any faster level: a robot
	# pointed at someone else'"'"'s infrastructure on every push is rude, and
	# network flakiness would train everyone to ignore the result.
	stage "live: DERP relay round trip and reconnection" "make live"
	stage "live: STUN binding exchange" "make live-stun"
	stage "live: netcheck against the real relay list" "make live-netcheck"
	stage "live: a direct path between two of ours" "make live-direct"
	stage "live: wireguard-go handshake" "make live-wg"
	stage "live: real tailcat server" "make live-tailcat"
	stage "live: CLI to a Go server" "make live-cli"
	stage "live: Go client to our server" "make live-serve"
	stage "live: Go client reaching a local service" "make live-serve-ports"
	stage "live: four Go clients at once" "make live-multi"
	stage "live: forward and socks to a Go server" "make live-forward"
	stage "live: SOCKS5 UDP ASSOCIATE" "make live-socksudp"
	stage "live: reaching a third address via an exit node" "make live-exitnode"
	stage "live: --allow admits and refuses" "make live-allow"
	stage "live: a saved key through both implementations" "make live-genkey"
	stage "live: ssh and scp with us as ProxyCommand" "make live-ssh"
	stage "live: a file into a real tailcat recv drop box" "make live-recv"
	stage "live: session across a rekey (slow, ~6m)" "make live-rekey"
fi

TOTAL=$(hms $(($(date +%s) - START)))
echo
if [ -n "$FAILED" ]; then
	echo "FAIL level $LEVEL diagnostic [$TOTAL]. Failed stages:$FAILED"
	exit 1
fi
echo "ok   level $LEVEL diagnostic passed [$TOTAL]"
