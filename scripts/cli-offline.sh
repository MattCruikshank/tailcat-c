#!/bin/sh
# The parts of the command line that need no network at all.
#
# Most of what the CLI does ends in a relay, so most of its checks are live
# ones that run only at level 1. These are the exceptions: arguments that are
# accepted or refused before anything is dialled, and files written from them.
# They are cheap, they are deterministic, and the failures they catch are the
# ones a user meets first -- a flag that silently does nothing, or an error
# that arrives days later from a key file written wrong today.
#
# The unit tests cannot reach any of this: it lives in src/cli/main.c, which
# is a program rather than a library.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"

if [ ! -x "$CLI" ]; then
	echo "cli-offline: $CLI not built -- run make first" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

fails=0
checks=0

fail() {
	echo "cli-offline: FAIL -- $*" >&2
	fails=$((fails + 1))
}

# accepts <description> <args...>
accepts() {
	desc=$1
	shift
	checks=$((checks + 1))
	if ! "$CLI" "$@" > "$tmp/out" 2> "$tmp/err"; then
		fail "$desc: refused, and should not have"
		sed 's/^/    /' "$tmp/err" >&2
	fi
}

# refuses <description> <expected-text-in-stderr> <args...>
#
# The expected text matters as much as the exit status: a refusal for the
# wrong reason is a different bug wearing the right result, and every one of
# these has a neighbouring case it could be confused with.
refuses() {
	desc=$1
	want=$2
	shift 2
	checks=$((checks + 1))
	if "$CLI" "$@" > "$tmp/out" 2> "$tmp/err"; then
		fail "$desc: accepted, and should not have"
		return 0
	fi
	if ! grep -qF "$want" "$tmp/err"; then
		fail "$desc: refused, but not for the stated reason"
		echo "    wanted: $want" >&2
		sed 's/^/    got:    /' "$tmp/err" >&2
	fi
}

# ---- genkey --region=<relay hostname> -----------------------------------
#
# The form for a relay the published DERP map does not list. It is the one
# genkey path that fetches nothing, so it belongs here rather than among the
# live checks.
echo "== genkey --region with relay hostnames =="

accepts "one relay hostname" \
	genkey --key "$tmp/one" --region=derp9.example.com
accepts "several relay hostnames" \
	genkey --force --key "$tmp/many" \
	--region=derp1.example.com,derp2.example.com

# The address is a function of the key, so the same key must print the same
# address twice. That is the entire promise of genkey.
addr1=$("$CLI" parse "$("$CLI" genkey --force --key "$tmp/stable" \
	--region=derp9.example.com 2> /dev/null)")
checks=$((checks + 1))
case $addr1 in
	*'"HostName": "derp9.example.com"'*) ;;
	*)
		fail "the address does not carry the relay hostname"
		printf '%s\n' "$addr1" >&2
		;;
esac

# And no region ID beside it: an address carries the hostname or the ID, and
# a reader given both would have two answers to one question.
checks=$((checks + 1))
case $addr1 in
	*'"RegionID"'*)
		fail "the address carries a region ID as well as the hostname"
		printf '%s\n' "$addr1" >&2
		;;
esac

echo "== and the ways it is refused =="

refuses "an empty label" "empty label" \
	genkey --force --key "$tmp/bad" --region=derp..example.com
refuses "a leading dot" "empty label" \
	genkey --force --key "$tmp/bad" --region=.example.com
refuses "a trailing dot" "empty label" \
	genkey --force --key "$tmp/bad" --region=example.com.
refuses "a trailing comma" "empty hostname" \
	genkey --force --key "$tmp/bad" --region=derp1.example.com,
refuses "a space in a hostname" "is not a hostname" \
	genkey --force --key "$tmp/bad" --region="derp 1.example.com"
refuses "a pasted URL" "is not a hostname" \
	genkey --force --key "$tmp/bad" --region=https://derp.example.com
refuses "a leading hyphen" "is not a hostname" \
	genkey --force --key "$tmp/bad" --region=-derp.example.com

# --client, which upstream also refuses: a client key has no relay of its
# own, so this is someone expecting something the key cannot do.
refuses "--client with --region" "no relay region of their own" \
	genkey --force --key "$tmp/bad" --client --region=derp.example.com

# Two flags naming the relay by different means.
refuses "--fixed-region with hostnames" "pick one" \
	genkey --force --key "$tmp/bad" --fixed-region --region=derp.example.com
refuses "--embed-derp-map with hostnames" "already embeds them" \
	genkey --force --key "$tmp/bad" --embed-derp-map \
	--region=derp.example.com

# Refusing to overwrite is the safety of the whole command: a key file is the
# only copy of an identity and the address is derived from it.
refuses "overwriting without --force" "already exists" \
	genkey --key "$tmp/one" --region=derp9.example.com

# ---- ssh -p <port|ip|ip:port> -------------------------------------------
#
# The value reaches the ProxyCommand as a string, which that child parses
# again -- so what matters is not only that it was accepted but exactly what
# was passed on. A stub `ssh` on PATH prints the ProxyCommand and exits, which
# gets the whole of that without connecting to anything.
echo "== ssh -p, and what the ProxyCommand is told =="

mkdir -p "$tmp/bin"
cat > "$tmp/bin/ssh" <<'STUB'
#!/bin/sh
for a in "$@"; do
	case $a in
		ProxyCommand=*) printf '%s\n' "$a" ;;
	esac
done
STUB
chmod +x "$tmp/bin/ssh"

# A real address, from the one genkey form that needs no network.
addr=$("$CLI" genkey --force --key "$tmp/pkey" --region=derp9.example.com \
	2> /dev/null)
checks=$((checks + 1))
case $addr in
	tc*) ;;
	*) fail "could not make an address to test -p with" ;;
esac

# proxies_as <description> <-p value> <expected last argument>
proxies_as() {
	desc=$1
	value=$2
	want=$3
	checks=$((checks + 1))
	got=$(PATH="$tmp/bin:$PATH" "$CLI" ssh -p "$value" "$addr" \
		2> "$tmp/err" | sed "s/.*'\\(.*\\)'\$/\\1/")
	if [ "$got" != "$want" ]; then
		fail "$desc: the ProxyCommand ends in '$got', wanted '$want'"
		sed 's/^/    /' "$tmp/err" >&2
	fi
}

proxies_as "a plain port" 22 22
proxies_as "another port" 2222 2222
# Canonicalised, so the child parses one spelling however it was typed.
proxies_as "a padded port" 022 22
# A bare address means its port 22, which is upstream's rule.
proxies_as "a bare IPv4 address" 10.0.0.1 10.0.0.1:22
proxies_as "a bare IPv6 address" "[2001:db8::1]" "[2001:db8::1]:22"
proxies_as "an IPv4 address and port" 10.0.0.1:2222 10.0.0.1:2222
proxies_as "an IPv6 address and port" "[2001:db8::1]:2222" "[2001:db8::1]:2222"

echo "== and the -p values that are not values =="

refuses "port zero" "bad port" ssh -p 0 "$addr"
refuses "a port above the range" "bad port" ssh -p 65536 "$addr"
refuses "a service name" "bad port" ssh -p ssh "$addr"
refuses "port zero on an address" "port 0 is not a port" \
	ssh -p 10.0.0.1:0 "$addr"
refuses "unbracketed IPv6" "must be written in brackets" \
	ssh -p 2001:db8::1 "$addr"
refuses "a DNS name" "is not a literal IP address" \
	ssh -p example.com:22 "$addr"
refuses "brackets round an IPv4 address" "is not an IPv6 address" \
	ssh -p "[10.0.0.1]:22" "$addr"

# The pipe takes the same destination in the same spelling. Only the
# refusals can be checked here: an accepted one would dial a relay.
echo "== the pipe's destination argument =="

refuses "the pipe, port zero" "bad port" "$addr" 0
refuses "the pipe, a service name" "bad port" "$addr" ssh
refuses "the pipe, unbracketed IPv6" "must be written in brackets" \
	"$addr" 2001:db8::1
refuses "the pipe, a DNS name" "is not a literal IP address" \
	"$addr" example.com:22

if [ "$fails" -ne 0 ]; then
	echo "cli-offline: $fails failure(s) in $checks checks" >&2
	exit 1
fi
echo "ok   cli-offline             $checks checks, no network touched"
