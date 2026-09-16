#!/bin/sh
# Interoperability test: tailcat-c's Noise implementation against a real
# wireguard-go device.
#
# Starts tools/wgpeer (an actual wireguard-go Device with an in-memory TUN),
# drives a handshake against it from build/livewg, and requires that the
# encrypted packet we send reaches wgpeer's TUN. Both must succeed.
#
# Keys are fixed rather than generated so the two processes need no
# coordination channel. They are test keys and are not secret.
set -eu

PORT="${WG_TEST_PORT:-51820}"
LPORT="${WG_TEST_LPORT:-51830}"

# Fixed test keys. wgpeer's private key, and ours; the public keys are
# derived by each side.
WGPEER_PRIV=e884f0c4ba0e4a7f9c6b1d5e3a2f8c7b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f01
OUR_PRIV=a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9
PSK=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# wgpeer needs our public key up front, and we need its public key. Both are
# derived from the fixed private keys, so ask each side for its own.
OUR_PUB=$(./build/livewg -private "$OUR_PRIV" -peer "$WGPEER_PRIV" -port 1 2>/dev/null \
	| sed -n 's/^our public key:  //p' || true)
if [ -z "$OUR_PUB" ]; then
	echo "live-wg: could not derive our public key" >&2
	exit 1
fi

WGPEER_PUB=$(cd tools/wgpeer && GOFLAGS=-mod=mod go run . -pubkey \
	-private "$WGPEER_PRIV" 2>/dev/null || true)
if [ -z "$WGPEER_PUB" ]; then
	echo "live-wg: could not derive wgpeer's public key" >&2
	exit 1
fi

echo "our public key:    $OUR_PUB"
echo "wgpeer public key: $WGPEER_PUB"
echo

# Start the real wireguard-go device.
(cd tools/wgpeer && GOFLAGS=-mod=mod go run . \
	-private "$WGPEER_PRIV" \
	-peer "$OUR_PUB" \
	-psk "$PSK" \
	-port "$PORT" \
	-endpoint "127.0.0.1:$LPORT" \
	-timeout 25s) &
PEER_PID=$!

cleanup() {
	kill "$PEER_PID" 2>/dev/null || true
	wait "$PEER_PID" 2>/dev/null || true
}

# Give the device a moment to bind its UDP socket before we send to it.
sleep 3

if ! ./build/livewg -private "$OUR_PRIV" -peer "$WGPEER_PUB" -psk "$PSK" \
		-port "$PORT" -lport "$LPORT"; then
	echo "live-wg: the C side failed" >&2
	cleanup
	exit 1
fi

# wgpeer exits 0 only if our packet reached its TUN.
if wait "$PEER_PID"; then
	echo
	echo "ok   live-wg                  wireguard-go accepted the handshake and"
	echo "                              delivered our packet to its TUN"
	exit 0
fi

echo "live-wg: wgpeer did not receive the packet" >&2
exit 1
