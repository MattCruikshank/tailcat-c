// SPDX-License-Identifier: BSD-3-Clause

// Command genaddrs emits tailcat addresses produced by the real Go
// implementation, for cross-checking the C parser and encoder against.
//
// Each line of output is:
//
//	<address> TAB <json description of the ConnInfo it parses back to>
//
// The C side (tests/crosscheck.c) parses each address, re-encodes it, and
// requires the result to be byte-identical. That is a much stronger claim
// than "our own tests agree with themselves": it pins our wire format to
// whatever the Go library actually emits today.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	count = flag.Int("count", 200, "how many random addresses to emit")
	seed  = flag.Int64("seed", 1, "PRNG seed, so runs are reproducible")
)

func randomRegion(rnd *rand.Rand, nodes int) *tailcfg.DERPRegion {
	r := &tailcfg.DERPRegion{
		RegionID:   tailcfg.DERPRegionID(rnd.Intn(1000)),
		RegionCode: fmt.Sprintf("r%d", rnd.Intn(100)),
		RegionName: fmt.Sprintf("Region %d", rnd.Intn(100)),
	}
	for i := 0; i < nodes; i++ {
		n := &tailcfg.DERPNode{
			Name:     fmt.Sprintf("%dx", i),
			RegionID: r.RegionID,
			HostName: fmt.Sprintf("derp%d.example.com", rnd.Intn(1000)),
		}
		switch rnd.Intn(4) {
		case 0:
			n.IPv4 = fmt.Sprintf("10.%d.%d.%d", rnd.Intn(256), rnd.Intn(256), rnd.Intn(256))
		case 1:
			n.IPv6 = "2001:db8::1"
		case 2:
			n.IPv4 = "192.0.2.1"
			n.IPv6 = "2001:db8::2"
		}
		if rnd.Intn(3) == 0 {
			n.STUNPort = rnd.Intn(65536)
		}
		if rnd.Intn(3) == 0 {
			n.DERPPort = rnd.Intn(65536)
		}
		if rnd.Intn(5) == 0 {
			n.InsecureForTests = true
		}
		if rnd.Intn(6) == 0 {
			n.CertName = fmt.Sprintf("cert%d.example.com", rnd.Intn(100))
		}
		// Exercise the "no hostname, so the name survives" branch.
		if rnd.Intn(8) == 0 {
			n.HostName = ""
		}
		r.Nodes = append(r.Nodes, n)
	}
	return r
}

func main() {
	flag.Parse()
	rnd := rand.New(rand.NewSource(*seed))
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for i := 0; i < *count; i++ {
		priv := key.NewNode()
		ci := tailcat.ConnInfo{
			ServerPublic: tailcat.NodePublic{NodePublic: priv.Public()},
		}
		if rnd.Intn(4) != 0 {
			ci.ServerDiscoPublic = tailcat.DiscoPublicForNode(priv)
		}
		if rnd.Intn(4) != 0 {
			ci.PresharedKey = tailcat.NewPresharedKey()
		}
		// Either an embedded region or a bare region ID, matching how real
		// addresses are built.
		if rnd.Intn(2) == 0 {
			ci.Region = []*tailcfg.DERPRegion{randomRegion(rnd, 1+rnd.Intn(4))}
		} else {
			ci.RegionID = tailcfg.DERPRegionID(rnd.Intn(1000))
		}

		addr := ci.Addr()

		// Emit the form the address actually parses back to, so the C side
		// compares against the restored fields rather than the inputs.
		back, err := tailcat.ParseAddr(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genaddrs: own address failed to parse: %v\n", err)
			os.Exit(1)
		}
		j, err := json.Marshal(back)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genaddrs: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(w, "%s\t%s\n", addr, j)
	}
}
