// SPDX-License-Identifier: BSD-3-Clause

// Command wgpeer runs a real wireguard-go device so the C implementation can
// be tested against it.
//
// This is the strongest check available for M4. The unit tests in
// tests/test_noise.c show that tailcat-c agrees with itself; only speaking to
// the actual WireGuard implementation shows that it agrees with WireGuard.
//
// The device listens on UDP with a fixed private key, expects one peer with a
// fixed public key and pre-shared key, and attaches an in-memory TUN. When
// tailcat-c completes a handshake and sends a transport packet, that packet
// surfaces on the TUN's Outbound channel and this program reports it and
// exits 0. If nothing arrives before the deadline it exits 1.
//
// Keys are supplied on the command line rather than generated so that no
// coordination channel is needed between the two processes.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// publicKeyOf derives a WireGuard public key from a private key, applying the
// same clamping the protocol requires.
func publicKeyOf(privHex string) (string, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != 32 {
		return "", fmt.Errorf("private key must be 64 hex characters")
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

var (
	privHex  = flag.String("private", "", "our WireGuard private key, hex")
	peerHex  = flag.String("peer", "", "the peer's public key, hex")
	pskHex   = flag.String("psk", "", "pre-shared key, hex (optional)")
	port     = flag.Int("port", 51820, "UDP port to listen on")
	timeout  = flag.Duration("timeout", 20*time.Second, "how long to wait")
	verbose  = flag.Bool("v", false, "log wireguard-go internals")
	allowed  = flag.String("allowed", "10.99.0.2/32", "peer's allowed IPs")
	endpoint = flag.String("endpoint", "", "peer endpoint, host:port")
	announce = flag.Bool("announce", true, "print our public key and exit code")
)

var pubOnly = flag.Bool("pubkey", false,
	"print the public key for -private and exit")

var mac1Of = flag.String("mac1", "",
	"compute the expected mac1 over this hex message, for -private's device")

// expectedMac1 reproduces wireguard-go's mac1 calculation so a mismatch can
// be localised: key = BLAKE2s-256("mac1----" || device public key), then
// BLAKE2s-128 of everything before the mac1 field, keyed with that.
func expectedMac1(msgHex, privHex string) (string, string, error) {
	msg, err := hex.DecodeString(msgHex)
	if err != nil || len(msg) < 32 {
		return "", "", fmt.Errorf("message must be hex and at least 32 bytes")
	}
	pubHex, err := publicKeyOf(privHex)
	if err != nil {
		return "", "", err
	}
	pub, _ := hex.DecodeString(pubHex)

	h, _ := blake2s.New256(nil)
	h.Write([]byte("mac1----"))
	h.Write(pub)
	key := h.Sum(nil)

	smac2 := len(msg) - 16
	smac1 := smac2 - 16

	mac, _ := blake2s.New128(key)
	mac.Write(msg[:smac1])
	want := mac.Sum(nil)

	return hex.EncodeToString(want), hex.EncodeToString(msg[smac1:smac2]), nil
}

func main() {
	flag.Parse()

	if *mac1Of != "" {
		want, got, err := expectedMac1(*mac1Of, *privHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wgpeer:", err)
			os.Exit(2)
		}
		fmt.Println("want", want)
		fmt.Println("got ", got)
		if pub, e := publicKeyOf(*privHex); e == nil {
			pb, _ := hex.DecodeString(pub)
			kh, _ := blake2s.New256(nil)
			kh.Write([]byte("mac1----"))
			kh.Write(pb)
			fmt.Println("mac1key", hex.EncodeToString(kh.Sum(nil)))
			fmt.Println("devpub ", pub)
		}
		if want == got {
			fmt.Println("MATCH")
		} else {
			fmt.Println("MISMATCH")
		}
		return
	}

	if *pubOnly {
		pub, err := publicKeyOf(*privHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(pub)
		return
	}

	if *privHex == "" || *peerHex == "" {
		fmt.Fprintln(os.Stderr, "wgpeer: -private and -peer are required")
		os.Exit(2)
	}

	tunDev := tuntest.NewChannelTUN()

	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "wgpeer: ")

	dev := device.NewDevice(tunDev.TUN(), conn.NewDefaultBind(), logger)
	defer dev.Close()

	// Configure through the same UAPI surface wg(8) uses, so this is the
	// device's ordinary configuration path rather than a test-only shortcut.
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\n",
		*privHex, *port, *peerHex)
	if *pskHex != "" {
		cfg += fmt.Sprintf("preshared_key=%s\n", *pskHex)
	}
	if *endpoint != "" {
		cfg += fmt.Sprintf("endpoint=%s\n", *endpoint)
	}
	cfg += fmt.Sprintf("allowed_ip=%s\n", *allowed)

	if err := dev.IpcSet(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: IpcSet: %v\n", err)
		os.Exit(1)
	}
	if err := dev.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: Up: %v\n", err)
		os.Exit(1)
	}

	if *announce {
		priv, err := hex.DecodeString(*privHex)
		if err != nil || len(priv) != 32 {
			fmt.Fprintln(os.Stderr, "wgpeer: bad private key")
			os.Exit(2)
		}
		fmt.Printf("wgpeer: listening on udp 127.0.0.1:%d\n", *port)
		fmt.Printf("wgpeer: waiting up to %s for a packet from the peer\n",
			*timeout)
	}

	// Inbound, not Outbound: the channel names are from the device's point of
	// view, and chTun.Write -- "called by the wireguard device to deliver a
	// packet for routing" -- feeds Inbound. Outbound is what the test would
	// write for the device to send out.
	select {
	case pkt := <-tunDev.Inbound:
		// Reaching the TUN means the handshake completed, the transport keys
		// matched, and the decrypted packet passed the allowed-IPs check.
		fmt.Printf("wgpeer: RECEIVED %d bytes through the tunnel\n", len(pkt))
		fmt.Printf("wgpeer: payload hex: %s\n", hex.EncodeToString(pkt))
		if len(pkt) >= 20 {
			fmt.Printf("wgpeer: ipv4 src=%d.%d.%d.%d dst=%d.%d.%d.%d proto=%d\n",
				pkt[12], pkt[13], pkt[14], pkt[15],
				pkt[16], pkt[17], pkt[18], pkt[19], pkt[9])
		}
		fmt.Println("wgpeer: OK")
		os.Exit(0)
	case <-time.After(*timeout):
		fmt.Fprintln(os.Stderr, "wgpeer: TIMEOUT: nothing arrived on the TUN")
		os.Exit(1)
	}
}
