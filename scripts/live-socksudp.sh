#!/bin/sh
# SOCKS5 UDP ASSOCIATE, end to end through a real relay.
#
# The unit tests prove the relay header parses and builds. What they cannot
# prove is that the whole chain agrees: that the association's bound address
# is reported back in a form the client can use, that a datagram's destination
# survives the tunnel, that the answer comes back naming where it came from,
# and that two destinations on one association do not get each other's
# replies.
#
# The last one is the point. A UDP relay that mixes up two flows still moves
# bytes, and looks like it works right up until something depends on which
# answer was which.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
PORT_A="${PORT_A:-18091}"
PORT_B="${PORT_B:-18092}"
SOCKS_PORT="${SOCKS_PORT:-11080}"

WORK=$(mktemp -d)
cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${SOCKS_PID:-}" ] && kill "$SOCKS_PID" 2>/dev/null || true
	[ -n "${SVC_PID:-}" ] && kill "$SVC_PID" 2>/dev/null || true
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# Two UDP echo services that say which one they are, so a reply attributed to
# the wrong destination is visible rather than merely wrong.
cat > "$WORK/svc.py" <<'SVCEOF'
import socket, sys, threading
def serve(port, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data, peer = s.recvfrom(65536)
        s.sendto(b"%s:%s" % (name.encode(), data), peer)
for p, n in ((int(sys.argv[1]), "A"), (int(sys.argv[2]), "B")):
    threading.Thread(target=serve, args=(p, n), daemon=True).start()
threading.Event().wait()
SVCEOF
python3 "$WORK/svc.py" "$PORT_A" "$PORT_B" &
SVC_PID=$!
sleep 1

"$CLI" -v serve "$PORT_A,$PORT_B" > /dev/null 2> "$WORK/srv.log" &
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
	echo "FAIL live-socksudp: the server never printed an address" >&2
	sed -n '1,30p' "$WORK/srv.log" >&2
	exit 1
fi

timeout 120 "$CLI" -v socks "$ADDR" "$SOCKS_PORT" > /dev/null 2> "$WORK/socks.log" &
SOCKS_PID=$!
sleep 12

# A minimal SOCKS5 UDP client: negotiate, ask for an association, then send
# datagrams with the RFC 1928 section 7 header in front.
cat > "$WORK/udpclient.py" <<'CLIEOF'
import socket, struct, sys

proxy_port = int(sys.argv[1])
targets = [(int(p), n) for p, n in (a.split("=") for a in sys.argv[2:])]

ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=20)
ctrl.sendall(b"\x05\x01\x00")
if ctrl.recv(2) != b"\x05\x00":
    print("NOAUTH-FAILED")
    sys.exit(1)

# UDP ASSOCIATE, with the "I do not know my address yet" form every real
# client sends.
ctrl.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
rep = ctrl.recv(10)
if len(rep) < 10 or rep[1] != 0:
    print("ASSOCIATE-FAILED", rep.hex() if rep else "no reply")
    sys.exit(1)
bnd_ip = socket.inet_ntoa(rep[4:8])
bnd_port = struct.unpack("!H", rep[8:10])[0]
if bnd_ip == "0.0.0.0":
    bnd_ip = "127.0.0.1"
print("relay at %s:%d" % (bnd_ip, bnd_port))

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(20)

def hdr(port):
    # RSV RSV FRAG ATYP=name "server.tailcat" PORT
    name = b"server.tailcat"
    return b"\x00\x00\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port)

for port, name in targets:
    u.sendto(hdr(port) + b"ping-" + name.encode(), (bnd_ip, bnd_port))

got = {}
for _ in range(len(targets)):
    try:
        data, _ = u.recvfrom(65536)
    except socket.timeout:
        break
    # Strip the reply header: RSV(2) FRAG(1) ATYP(1) then addr+port.
    atyp = data[3]
    off = 4 + (4 if atyp == 1 else 16 if atyp == 4 else 1 + data[4])
    off += 2
    body = data[off:].decode(errors="replace")
    got[body] = True

for k in sorted(got):
    print("got", k)
CLIEOF

OUT=$(timeout 60 python3 "$WORK/udpclient.py" "$SOCKS_PORT" \
	"$PORT_A=a" "$PORT_B=b" 2>&1 || true)
echo "$OUT"
grep -E 'UDP association' "$WORK/socks.log" || true

RC=0
case "$OUT" in
*"ASSOCIATE-FAILED"*|*"NOAUTH-FAILED"*)
	echo "FAIL live-socksudp: the association was refused" >&2
	tail -20 "$WORK/socks.log" >&2
	RC=1
	;;
esac

# Each service prefixes its own name, so the two answers are distinguishable
# and a mixed-up relay shows up as a missing or duplicated one.
if ! printf '%s' "$OUT" | grep -q 'got A:ping-a'; then
	echo "FAIL live-socksudp: service A's answer did not arrive intact" >&2
	RC=1
fi
if ! printf '%s' "$OUT" | grep -q 'got B:ping-b'; then
	echo "FAIL live-socksudp: service B's answer did not arrive intact" >&2
	RC=1
fi

[ $RC -eq 0 ] && echo && echo "ok   live-socksudp"
exit $RC
