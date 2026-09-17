#!/bin/sh
# `forward --open-browser` and `browse` against a real Go tailcat server.
#
# The unit tests prove what argv an opener gets and that it is exec'd. What
# they cannot prove is that the port in the URL is the port the forwarder
# actually listened on -- because with `0:PORT` the kernel picks it, and
# nothing in this program would notice if the browser were sent to a different
# one. So the URL is not merely checked for shape here: it is fetched, through
# the tunnel, and has to come back with the service's own answer.
#
# $BROWSER is set to a script that writes the URL down, which is also how a
# user would point this at something other than their desktop default. No
# browser is opened and nothing needs a screen.
set -eu

CLI="${CLI:-build/cosmo/tailcat-c}"
UPSTREAM="${UPSTREAM:-build/tailcat-upstream}"
SRCDIR="${SRCDIR:-upstream-tailcat}"
SVCPORT="${SVCPORT:-18086}"

if [ ! -x "$UPSTREAM" ]; then
	echo "building upstream tailcat..."
	(cd "$SRCDIR" && GOFLAGS=-mod=mod go build -o "../$UPSTREAM" ./cmd/tailcat)
fi

WORK=$(mktemp -d)
cleanup() {
	for v in SVC_PID SRV_PID FWD_PID BR_PID; do
		eval "pid=\${$v:-}"
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	[ -n "${TC_KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/svc.py" <<SVCEOF
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"tailcat-browse-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", $SVCPORT), H).serve_forever()
SVCEOF

# The stand-in browser. It records the URL and exits 0, which is what
# tc_browser_open reads as "this one worked".
cat > "$WORK/fakebrowser" <<'BREOF'
#!/bin/sh
printf '%s' "$1" > "$TC_BROWSE_RECORD"
BREOF
chmod +x "$WORK/fakebrowser"

echo "starting a local HTTP service on 127.0.0.1:$SVCPORT"
python3 "$WORK/svc.py" >/dev/null 2>&1 </dev/null &
SVC_PID=$!
sleep 1

echo "starting the real Go tailcat serving $SVCPORT"
"$UPSTREAM" serve "$SVCPORT" > "$WORK/srv.log" 2>&1 &
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
	echo "live-browse: the Go server never printed an address:" >&2
	cat "$WORK/srv.log" >&2
	exit 1
fi

# ---- forward --open-browser ----------------------------------------------
echo
echo "\$ tailcat-c forward --open-browser <addr> 0:$SVCPORT"
TC_BROWSE_RECORD="$WORK/url.txt"
export TC_BROWSE_RECORD
BROWSER="$WORK/fakebrowser"
export BROWSER

"$CLI" -v forward --open-browser "$ADDR" "0:$SVCPORT" \
	>/dev/null 2>"$WORK/fwd.log" &
FWD_PID=$!

i=0
while [ $i -lt 60 ]; do
	[ -s "$TC_BROWSE_RECORD" ] && break
	sleep 1
	i=$((i + 1))
done
URL=$(cat "$TC_BROWSE_RECORD" 2>/dev/null || true)
if [ -z "$URL" ]; then
	echo "live-browse: no browser was opened." >&2
	cat "$WORK/fwd.log" >&2
	exit 1
fi
echo "    opened: $URL"

# The listener printed its own address; the URL has to name the same port.
LISTEN=$(sed -n 's/^# \(127\.0\.0\.1:[0-9]*\) ->.*/\1/p' "$WORK/fwd.log" | head -1)
echo "    listening on: $LISTEN"
if [ "$URL" != "http://$LISTEN/" ]; then
	echo "live-browse: the URL does not match the listener." >&2
	echo "  url:      $URL" >&2
	echo "  listener: http://$LISTEN/" >&2
	exit 1
fi
case "$LISTEN" in
*:0 | *:"$SVCPORT")
	echo "live-browse: 0:$SVCPORT should have asked the OS for a port," >&2
	echo "  and got $LISTEN instead." >&2
	exit 1
	;;
esac

# And the URL is not merely well formed: something is behind it.
BODY=$(timeout 40 python3 -c '
import sys, urllib.request
sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=30)
                 .read().decode("utf-8", "replace"))
' "$URL" 2>"$WORK/fetch.err" || true)
echo "    fetched: $BODY"
if [ "$BODY" != "tailcat-browse-ok" ]; then
	echo "live-browse: the opened URL did not serve the service." >&2
	sed 's/^/    /' "$WORK/fetch.err" >&2
	cat "$WORK/fwd.log" >&2
	exit 1
fi
kill "$FWD_PID" 2>/dev/null || true
FWD_PID=""

# ---- browse --------------------------------------------------------------
# Upstream's alias: a kernel-chosen local port to the server's port 80. The
# Go server is not serving 80, so nothing is behind this URL -- what is being
# checked is that `browse` builds that mapping and opens a browser at it,
# which is the whole of what the subcommand does.
echo
echo "\$ tailcat-c browse <addr>"
rm -f "$TC_BROWSE_RECORD"
"$CLI" -v browse "$ADDR" >/dev/null 2>"$WORK/browse.log" &
BR_PID=$!

i=0
while [ $i -lt 60 ]; do
	[ -s "$TC_BROWSE_RECORD" ] && break
	sleep 1
	i=$((i + 1))
done
URL2=$(cat "$TC_BROWSE_RECORD" 2>/dev/null || true)
if [ -z "$URL2" ]; then
	echo "live-browse: browse opened no browser." >&2
	cat "$WORK/browse.log" >&2
	exit 1
fi
echo "    opened: $URL2"
grep -E "^# 127\.0\.0\.1:[0-9]+ -> the server's port 80$" "$WORK/browse.log" |
	sed 's/^/    /'
if ! grep -qE "^# 127\.0\.0\.1:[0-9]+ -> the server's port 80$" \
	"$WORK/browse.log"; then
	echo "live-browse: browse did not forward to the server's port 80." >&2
	cat "$WORK/browse.log" >&2
	exit 1
fi
LISTEN2=$(sed -n "s/^# \(127\.0\.0\.1:[0-9]*\) -> the server's port 80$/\1/p" \
	"$WORK/browse.log" | head -1)
if [ "$URL2" != "http://$LISTEN2/" ]; then
	echo "live-browse: browse's URL does not match its listener." >&2
	echo "  url:      $URL2" >&2
	echo "  listener: http://$LISTEN2/" >&2
	exit 1
fi

echo
echo "ok   live-browse              forward --open-browser sent a browser to"
echo "                              the port it actually listened on, and the"
echo "                              page came back through the tunnel; browse"
echo "                              made the same offer for the server's :80"
