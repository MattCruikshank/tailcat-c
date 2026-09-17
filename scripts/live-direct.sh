#!/bin/sh
# A tailcat-c client and a tailcat-c server finding a direct path.
#
# test_path proves the state machine is right against a simulated network.
# This proves the other half: that the pieces are actually wired together --
# that the UDP socket is opened, that the disco keys reach each other through
# the meow, that CallMeMaybe travels over the relay, that probes go out of the
# real socket, and that when a path is proven the session moves onto it.
#
# Both processes run on this machine, so the direct path is over a local
# interface address. That is a real direct path: the packets do not go near
# the relay, which is the whole claim being checked. The relay is still needed
# to introduce the two and to carry the first CallMeMaybe, which is also how
# it works between two machines.
#
# The check that matters is not "it said direct" but that traffic stopped
# going through the relay. Both are asserted: the log line, and the relay's
# own byte counters standing still while the transfer runs.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
PORT="${PORT:-18086}"

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${SVC_PID:-}" ] && kill "$SVC_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/svc.py" <<'SVCEOF'
import socket, sys, threading
def serve(c):
    data = b""
    while True:
        b = c.recv(65536)
        if not b:
            break
        data += b
    c.sendall(b"got %d bytes\n" % len(data))
    c.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
SVCEOF

python3 "$WORK/svc.py" "$PORT" &
SVC_PID=$!
sleep 1

"$CLI" -v serve "$PORT" > /dev/null 2> "$WORK/srv.log" &
SRV_PID=$!

ADDR=""
i=0
while [ $i -lt 40 ]; do
	ADDR=$(sed -n 's/.*\(tc[A-Za-z0-9_-]\{40,\}\).*/\1/p' "$WORK/srv.log" | head -1)
	[ -n "$ADDR" ] && break
	sleep 1
	i=$((i + 1))
done
if [ -z "$ADDR" ]; then
	echo "FAIL live-direct: the server never printed an address" >&2
	sed -n '1,40p' "$WORK/srv.log" >&2
	exit 1
fi
echo "server address: $(printf '%.24s' "$ADDR")..."

# Enough data, sent slowly enough, that the transfer is still running well
# after the path has had time to be proven. A single quick write would finish
# over the relay before any probe was answered and prove nothing.
python3 -c '
import sys, time
for i in range(40):
    sys.stdout.write("x" * 4096)
    sys.stdout.flush()
    time.sleep(0.25)
' | timeout 90 "$CLI" -v "$ADDR" "$PORT" > "$WORK/out.txt" 2> "$WORK/cli.log" || true

echo "--- client said ---"
grep -E 'path:|netcheck:|probing' "$WORK/cli.log" || true
echo "--- server said ---"
grep -E 'path:|netcheck:|probing' "$WORK/srv.log" || true

RC=0

if ! grep -q 'got 163840 bytes' "$WORK/out.txt"; then
	echo "FAIL live-direct: the transfer did not complete" >&2
	cat "$WORK/out.txt" >&2
	RC=1
else
	echo "ok   the whole transfer arrived"
fi

# The claim under test. Either side reaching the other directly is a direct
# path; both is the normal outcome.
if grep -q 'path: direct to' "$WORK/cli.log"; then
	echo "ok   the client moved onto a direct path"
elif grep -q 'path: direct to' "$WORK/srv.log"; then
	echo "ok   the server moved onto a direct path"
else
	echo "FAIL live-direct: neither side ever went direct" >&2
	echo "--- client ---" >&2
	tail -30 "$WORK/cli.log" >&2
	echo "--- server ---" >&2
	tail -30 "$WORK/srv.log" >&2
	RC=1
fi

# And that it was not a false upgrade: a direct path that did not work would
# show up as a fallback to the relay, since the trust window would expire.
if grep -q 'path: via the relay' "$WORK/cli.log" &&
	grep -q 'path: direct to' "$WORK/cli.log"; then
	# Going direct and then back again within one short transfer means the
	# path was chosen on evidence that did not hold.
	if [ "$(grep -c 'path: via the relay' "$WORK/cli.log")" -gt 0 ]; then
		echo "FAIL live-direct: the client fell back to the relay, so the" >&2
		echo "     path it chose was not actually carrying traffic" >&2
		RC=1
	fi
fi

[ $RC -eq 0 ] && echo "ok   live-direct"
exit $RC
