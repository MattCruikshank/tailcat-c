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
1 | 3 | 5 | selftest) ;;
*)
	echo "usage: $0 [1|3|5|selftest]   (1 = most thorough)" >&2
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

# stage [--need TOOL] NAME COMMAND
#
# Runs it, times it, and keeps going on failure so one broken thing does not
# hide the state of everything after it.
#
# --need names a program the stage cannot run without. If it is not on $PATH
# the stage is skipped and said to have been skipped -- because a stage that
# never runs anywhere looks exactly like one that always passes.
#
# The prerequisite is stated here rather than inferred from what the stage
# exits with, and that is the whole design. Every stage below is a make
# target, and make exits 2 for any recipe failure whatsoever: a script's own
# "77, I have no scp" is flattened to the same 2 as "the test failed". There
# is no exit code a stage can return that means anything specific, so the
# harness stops trying to read one. Anything non-zero is now a failure.
#
# This cost a level 1 run to learn. The skip code was 2, the live drop-box
# stage was failing in its cleanup, make turned that into 2 as well, and the
# run reported "passed" with a broken test inside it.
stage() {
	need=""
	if [ "$1" = "--need" ]; then
		need="$2"
		shift 2
	fi
	name="$1"
	shift
	# Exactly one command. `sh -c "$*"` will happily join three arguments
	# into a sentence, which is how a line continuation mangled into a
	# literal backslash-n produced a stage named "n" whose command was its
	# own title. It skipped, so nothing ran and nothing complained.
	if [ "$#" -ne 1 ] || [ -z "$name" ]; then
		printf 'diagnostic.sh: malformed stage: %s %s\n' "$name" "$*" >&2
		exit 1
	fi
	# A comma-separated list, satisfied by any one of them: the aarch64
	# stage takes qemu-aarch64-static or qemu-aarch64, and a harness
	# that insisted on one spelling would skip a stage the script it
	# guards would have been happy to run.
	have=""
	if [ -n "$need" ]; then
		for prog in $(printf '%s' "$need" | tr ',' ' '); do
			if command -v "$prog" > /dev/null 2>&1; then
				have=1
				break
			fi
		done
	fi
	if [ -n "$need" ] && [ -z "$have" ]; then
		printf '\n=== %s\n' "$name"
		# Naming the command as well as the program: skipping happens
		# before the stage runs, so the script's own install hint never
		# prints, and "not installed" without "here is how" is a
		# smaller version of being silent.
		printf '    SKIP %s -- %s is not installed; `%s` says how\n' \
			"$name" "$need" "$*"
		SKIPPED="${SKIPPED:-}
      $name (no $need)"
		return 0
	fi
	if [ -n "${TC_DIAG_DRYRUN:-}" ]; then
		printf '    would run: %s\n' "$name"
		return 0
	fi
	printf '\n=== %s\n' "$name"
	t0=$(date +%s)
	# Tested rather than bare, and that is the whole of what makes the
	# branches below reachable. This script runs under `set -e`, which kills
	# it on any untested non-zero -- so `sh -c "$*"` followed by `rc=$?`
	# meant the shell exited before rc was ever read. Neither FAIL nor the
	# summary had ever run, and a level 1 that reached a stage it could not
	# run stopped there with the whole live tier unexecuted.
	if sh -c "$*"; then rc=0; else rc=$?; fi
	if [ "$rc" -eq 0 ]; then
		printf '    ok   %s [%s]\n' "$name" "$(hms $(($(date +%s) - t0)))"
	else
		printf '    FAIL %s [%s]\n' "$name" "$(hms $(($(date +%s) - t0)))"
		FAILED="$FAILED
      $name"
	fi
}

# ---- selftest: does the harness report what it finds? -------------------
#
# This exists because for most of this project's life it did not, and nothing
# noticed. Two bugs, both found by one level 1 run: stage() ran its command
# bare under `set -e`, so the first non-zero exit killed the script and FAIL,
# SKIP and the summary were all unreachable; and the skip signal was an exit
# code that make cannot carry, so a failing live stage was reported skipped.
#
# So the runner gets the same treatment as the code it runs. It calls the
# real stage() rather than a copy: a copy would be a second implementation
# that agrees with itself, which is the failure this file is about.
if [ "$LEVEL" = selftest ]; then
	out=$(
		stage "selftest: passes" "true"
		stage --need definitely-not-a-real-program-xyzzy \
			"selftest: tooling absent" "exit 1"
		stage --need sh "selftest: tooling present" "true"
		stage --need nope-xyzzy,sh "selftest: one of several present" "true"
		stage --need nope-xyzzy,nope-plugh \
			"selftest: none of several present" "exit 1"
		stage "selftest: fails" "exit 1"
		stage "selftest: exits 2 as make does" "exit 2"
		stage "selftest: exits 77" "exit 77"
		stage "selftest: after the failure" "true"
		# Flattened, because the accumulators are newline-separated and
		# these assertions are line-oriented.
		printf 'SKIPPED=[%s]\n' "$(printf '%s' "${SKIPPED:-}" | tr '\n' ' ')"
		printf 'FAILED=[%s]\n' "$(printf '%s' "$FAILED" | tr '\n' ' ')"
	) || true

	fail=""
	want() {
		if printf '%s\n' "$out" | grep -q "$1"; then
			printf '    ok   %s\n' "$2"
		else
			printf '    FAIL %s (no match for: %s)\n' "$2" "$1"
			fail=1
		fi
	}
	wantnot() {
		if printf '%s\n' "$out" | grep -q "$1"; then
			printf '    FAIL %s (unexpected match: %s)\n' "$2" "$1"
			fail=1
		else
			printf '    ok   %s\n' "$2"
		fi
	}

	want '^    ok   selftest: passes' "a passing stage reports ok"
	want '^    SKIP selftest: tooling absent' \
		"a missing --need program skips the stage"
	wantnot 'selftest: tooling absent.*\[' \
		"a skipped stage is not run at all"
	want '^    ok   selftest: tooling present' \
		"a present --need program runs the stage"
	want '^    ok   selftest: one of several present' \
		"--need is satisfied by any one of its alternatives"
	want '^    SKIP selftest: none of several present' \
		"--need skips only when every alternative is missing"
	want '^    FAIL selftest: fails' "exit 1 reports FAIL"
	# The two that mattered. Every stage runs through make, and make exits 2
	# for any recipe failure at all, so no exit code can mean "skipped".
	want '^    FAIL selftest: exits 2 as make does' \
		"exit 2 reports FAIL, because that is all make ever says"
	want '^    FAIL selftest: exits 77' \
		"no exit code is special-cased into a skip"
	wantnot '^    SKIP selftest: exits' "no exit code is mistaken for a skip"
	want '^    ok   selftest: after the failure' \
		"a failure does not stop the stages after it"
	want 'SKIPPED=\[.*selftest: tooling absent' \
		"the skip reaches the summary"
	want 'FAILED=\[.*selftest: fails' "the failure reaches the summary"
	wantnot 'FAILED=\[.*tooling absent' "a skip is not counted as a failure"
	wantnot 'SKIPPED=\[.*selftest: fails' "a failure is not counted as a skip"

	# Every call site in the file, checked without running one of them. The
	# arity check fires during this, so a stage assembled wrongly -- a
	# mangled line continuation, a missing quote -- is a hard error here
	# rather than a plausible-looking line in a twenty-minute log nobody
	# reads to the end. That is not hypothetical: it is how the aarch64
	# stage spent a run calling itself "n".
	#
	# The assertion is that the levels nest, which is the one thing that is
	# true by construction and would break if a stage were lost. A fixed
	# count would need updating with every new stage, and a rule about the
	# names themselves flagged "clean" the first time it ran.
	n5=0
	n3=0
	n1=0
	for lvl in 5 3 1; do
		if names=$(TC_DIAG_DRYRUN=1 sh "$0" "$lvl" 2>&1); then
			count=$(printf '%s\n' "$names" | grep -c 'would run:')
			eval "n$lvl=$count"
			printf '    ok   level %s dry-runs %s well-formed stages\n' \
				"$lvl" "$count"
		else
			printf '    FAIL level %s does not survive a dry run:\n%s\n' \
				"$lvl" "$names"
			fail=1
		fi
	done
	if [ "$n1" -gt "$n3" ] && [ "$n3" -gt "$n5" ] && [ "$n5" -gt 0 ]; then
		printf '    ok   the levels nest: %s < %s < %s stages\n' \
			"$n5" "$n3" "$n1"
	else
		printf '    FAIL the levels do not nest: 5=%s 3=%s 1=%s\n' \
			"$n5" "$n3" "$n1"
		fail=1
	fi

	echo
	if [ -n "$fail" ]; then
		echo "FAIL the diagnostic harness does not report what it finds"
		exit 1
	fi
	echo "ok   diagnostic harness reports ok, SKIP and FAIL correctly"
	exit 0
fi

echo "tailcat-c: level $LEVEL diagnostic"

# The harness before the code. This is two seconds, it runs at every level,
# and it is not run through stage() on purpose: if stage() is the thing that
# is broken, a check routed through it is a check that cannot report.
# Not during a dry run. The selftest asserts that every level survives a
# dry run, and a dry run that re-entered the selftest would be a shell
# forking itself until the machine gave out -- which is exactly what it
# did the first time this check was written.
if [ -z "${TC_DIAG_DRYRUN:-}" ] && ! sh "$0" selftest; then
	echo >&2
	echo "tailcat-c: the diagnostic harness is broken, so nothing it says" >&2
	echo "about anything else can be trusted. Stopping here." >&2
	exit 1
fi

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

# src/cli/main.c is a program, so no unit test links against it. These are the
# parts of it that can be checked without dialling anything, which is why they
# run at every level rather than with the live stages.
stage "command-line checks that need no network" "make cli-offline"

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
	stage "parse prints what the real tailcat prints" "make parse-interop"
fi

# ---- level 1 only: generated files, and the network ---------------------
if [ "$LEVEL" -eq 1 ]; then
	# A stale generated header is a test that has quietly stopped checking
	# what it claims to. Regenerating into a scratch copy and diffing is the
	# only way to notice.
	#
	# One block is excluded, and the exclusion is the interesting part.
	# kCookieExchangeVectors is produced by wireguard-go's CookieChecker,
	# which draws its mac2 secret and every reply nonce from crypto/rand --
	# so those lines differ on every run and can never match. They are a
	# captured artefact rather than a derivation: valid as a test (our code
	# still has to open a reply wireguard-go really built) and meaningless
	# as a freshness check.
	#
	# This check was added in Phase 2.1 and those vectors in 2.3, so it has
	# been failing ever since -- unnoticed, because level 1 is the only level
	# that runs it and level 1 had not been run in between. Comparing
	# everything else keeps the check honest about what it can actually
	# promise.
	stage "generated vectors are current" '
		strip_random() { grep -v "{ \"exchange-" "$1"; }
		cp tests/crypto_vectors.h /tmp/vectors.before &&
		(cd tools/genvectors && GOFLAGS=-mod=mod go run .) &&
		strip_random /tmp/vectors.before > /tmp/vectors.a &&
		strip_random tests/crypto_vectors.h > /tmp/vectors.b &&
		cp /tmp/vectors.before tests/crypto_vectors.h &&
		if diff -q /tmp/vectors.a /tmp/vectors.b >/dev/null; then
			echo "    tests/crypto_vectors.h matches its generator"
			echo "    (kCookieExchangeVectors excluded: not reproducible)"
		else
			echo "    tests/crypto_vectors.h is STALE -- commit the regenerated file" >&2
			diff /tmp/vectors.a /tmp/vectors.b | head -10 >&2
			exit 1
		fi'

	# The SSH vectors are wholly reproducible -- Ed25519 is deterministic and
	# the seeds are fixed -- so this one needs no exclusions, unlike the block
	# above. That is worth keeping true: a generator with a random input is a
	# freshness check that can never pass, which is what bug 19 was.
	stage "generated SSH vectors are current" '
		cp tests/ssh_vectors.h /tmp/ssh_vectors.before &&
		(cd tools/genssh && GOFLAGS=-mod=mod go run . -o ../../tests/ssh_vectors.h) &&
		if diff -q /tmp/ssh_vectors.before tests/ssh_vectors.h >/dev/null; then
			echo "    tests/ssh_vectors.h matches its generator"
		else
			cp /tmp/ssh_vectors.before tests/ssh_vectors.h
			echo "    tests/ssh_vectors.h is STALE -- commit the regenerated file" >&2
			exit 1
		fi'

	# tests/sshauth_vectors.h is the one generated file that is NOT checked by
	# regenerating and diffing. It cannot be: every run makes new keys, and
	# ECDSA signatures are randomized, so a diff would fail every time and
	# the check would be worse than nothing -- that is bug 19 exactly.
	#
	# What is worth checking is the property the file exists for: that fresh
	# output from ssh-keygen and openssl still verifies. So this regenerates
	# into the tree, runs the test against the new vectors, and puts the
	# committed ones back. A break here means the generator or the verifier
	# moved, which a diff would have told us in a much more confusing way.
	stage --need ssh-keygen "vectors regenerated from ssh-keygen still verify" '
		cp tests/sshauth_vectors.h /tmp/sshauth_vectors.before &&
		python3 tools/gen-sshauth-vectors.py &&
		rc=0 &&
		{ make build/cosmo/test_sshauth >/dev/null 2>&1 &&
		  ./build/cosmo/test_sshauth; } || rc=$? &&
		cp /tmp/sshauth_vectors.before tests/sshauth_vectors.h &&
		make build/cosmo/test_sshauth >/dev/null 2>&1 &&
		exit $rc'

	# src/usage_text.c is doc/usage.md turned into a C string literal, and is
	# committed so that a build needs no Python. That makes it possible to
	# edit the prose and ship the old text, which nothing else would notice:
	# the generated file compiles either way. Unlike the CA bundle -- whose
	# source is a download and so cannot be checked this way -- this one is a
	# pure function of a file in the tree.
	stage "the embedded usage text matches doc/usage.md" '
		cp src/usage_text.c /tmp/usage.before &&
		python3 scripts/gen-usage.py 2>/dev/null &&
		if diff -q /tmp/usage.before src/usage_text.c >/dev/null; then
			echo "    src/usage_text.c matches doc/usage.md"
		else
			cp /tmp/usage.before src/usage_text.c
			echo "    src/usage_text.c is STALE -- run scripts/gen-usage.py and commit" >&2
			exit 1
		fi'

	# Live interop. These dial Tailscale production relays and run a real
	# tailcat, which is exactly why they are not in any faster level: a robot
	# pointed at someone else'"'"'s infrastructure on every push is rude, and
	# network flakiness would train everyone to ignore the result.
	# The other half of every binary we ship. Character signedness differs
	# between the two architectures, so the first of these runs the whole
	# suite under aarch64's semantics on x86_64 hardware; the second runs
	# real aarch64 instructions under qemu, when qemu is installed.
	stage "the suite under aarch64 char semantics" "make test-unsigned-char"
	stage --need qemu-aarch64-static,qemu-aarch64 "the suite on aarch64 instructions (qemu)" "make test-aarch64"

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
	stage "live: a browser sent to the port we listened on" "make live-browse"
	stage "live: one proxy, two servers, chosen by request" "make live-socks-many"
	stage "live: a command per connection (exec)" "make live-exec"
	stage "live: SOCKS5 UDP ASSOCIATE" "make live-socksudp"
	stage "live: reaching a third address via an exit node" "make live-exitnode"
	stage "live: --allow admits and refuses" "make live-allow"
	stage "live: a saved key through both implementations" "make live-genkey"
	stage --need ssh "live: real OpenSSH against our SSH server" "make live-sshd"
	stage --need ssh "live: every authorized-key algorithm, negotiated" \
		"make live-sshkeys"
	stage --need sftp "live: scp and sftp against the write-only drop box" "make live-dropbox"
	stage --need sftp "live: a tree into the recursive drop box" "make live-dropbox-tree"
	stage --need sftp "live: scp and sftp against a served directory" "make live-files"
	stage --need ssh "live: a real shell, pty and all" "make live-shell"
	stage --need scp "live: recv receiving a real scp over a real relay" "make live-recv-serve"
	stage --need ssh "live: serve ssh over a real relay" "make live-ssh-serve"
	stage "live: our client and a real client against each other" "make live-sshloop"
	stage "live: ls against a real Go file server" "make live-ls"
	stage "live: ssh and scp with us as ProxyCommand" "make live-ssh"
	stage "live: a file into a real tailcat recv drop box" "make live-recv"
	stage "live: session across a rekey (slow, ~6m)" "make live-rekey"
fi

TOTAL=$(hms $(($(date +%s) - START)))
echo
if [ -n "${SKIPPED:-}" ]; then
	echo "skipped (tooling not installed):${SKIPPED}"
	echo
fi
if [ -n "$FAILED" ]; then
	echo "FAIL level $LEVEL diagnostic [$TOTAL]. Failed stages:$FAILED"
	exit 1
fi
echo "ok   level $LEVEL diagnostic passed [$TOTAL]"
