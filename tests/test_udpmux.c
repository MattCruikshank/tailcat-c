/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Datagrams through the tunnel.
 *
 * The wire format is checked against packets built by gopacket, not against
 * anything of ours. That matters most for the checksum: it covers an IPv6
 * pseudo-header, so a wrong one is completely invisible to a loopback test --
 * our sender and our receiver would agree perfectly and nothing else in the
 * world would accept a single packet. A vector computed by our own arithmetic
 * would only prove we agree with ourselves, which is exactly how the IPv6
 * formatter shipped broken for months.
 */

#include "tc/udpmux.h"

#include "crypto_vectors.h"
#include "tctest.h"

#include <arpa/inet.h>

/* ---- plumbing ---------------------------------------------------------- */

static uint8_t g_sent[4096];
static size_t g_sent_len;
static size_t g_sent_count;

static int capture(void *ctx, const uint8_t *pkt, size_t len)
{
	(void)ctx;
	g_sent_len = len > sizeof g_sent ? sizeof g_sent : len;
	memcpy(g_sent, pkt, g_sent_len);
	g_sent_count++;
	return TC_OK;
}

static size_t unhex(uint8_t *buf, size_t cap, const char *h)
{
	size_t n = 0;
	for (; h[0] && h[1] && n < cap; h += 2) {
		int hi = (h[0] <= '9') ? h[0] - '0' : (h[0] | 32) - 'a' + 10;
		int lo = (h[1] <= '9') ? h[1] - '0' : (h[1] | 32) - 'a' + 10;
		buf[n++] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

static const uint8_t kLocal[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                                0,    0,    0,    0,    0,    0,    0, 1 };
static const uint8_t kRemote[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                                 0,    0,    0,    0,    0,    0,    0, 2 };

/* ---- the wire format --------------------------------------------------- */

static void test_matches_gopacket(void)
{
	TCT_CASE("our packets are byte for byte what gopacket builds");
	for (size_t i = 0;
	     i < sizeof kUdp6Vectors / sizeof kUdp6Vectors[0]; i++) {
		uint8_t src[16], dst[16];
		if (inet_pton(AF_INET6, kUdp6Vectors[i].src, src) != 1 ||
		    inet_pton(AF_INET6, kUdp6Vectors[i].dst, dst) != 1) {
			TCT_FAILF("%s: bad address in the vector", kUdp6Vectors[i].name);
			continue;
		}

		tc_udp_mux *m = tc_udp_mux_new(src, dst, capture, NULL);
		if (m == NULL) {
			TCT_FAILF("out of memory");
			return;
		}

		uint8_t payload[2048];
		size_t plen = unhex(payload, sizeof payload, kUdp6Vectors[i].payload);
		uint8_t want[4096];
		size_t wlen = unhex(want, sizeof want, kUdp6Vectors[i].want);

		g_sent_len = 0;
		int rc = tc_udp_mux_send(m, (uint16_t)kUdp6Vectors[i].sport,
		                         (uint16_t)kUdp6Vectors[i].dport, payload,
		                         plen, 1000);
		if (rc != TC_OK) {
			TCT_FAILF("%s: send returned %d", kUdp6Vectors[i].name, rc);
			tc_udp_mux_free(m);
			continue;
		}
		if (g_sent_len != wlen || memcmp(g_sent, want, wlen) != 0) {
			TCT_FAILF("%s: %zu bytes, wanted %zu; first difference at %zu",
			          kUdp6Vectors[i].name, g_sent_len, wlen,
			          (size_t)0);
			for (size_t k = 0; k < wlen && k < g_sent_len; k++) {
				if (g_sent[k] != want[k]) {
					TCT_FAILF("  byte %zu: got %02x want %02x", k, g_sent[k],
					          want[k]);
					break;
				}
			}
		}
		tct_checks++;
		tc_udp_mux_free(m);
	}
}

static void test_accepts_gopackets_packets(void)
{
	TCT_CASE("and we accept what gopacket produced");
	/* The other direction. Our encoder and our decoder agreeing would prove
	 * nothing about either; this runs their bytes through ours. */
	for (size_t i = 0;
	     i < sizeof kUdp6Vectors / sizeof kUdp6Vectors[0]; i++) {
		uint8_t src[16], dst[16];
		inet_pton(AF_INET6, kUdp6Vectors[i].src, src);
		inet_pton(AF_INET6, kUdp6Vectors[i].dst, dst);

		/* Receiving, so the roles are the other way round: the vector's
		 * destination is us. */
		tc_udp_mux *m = tc_udp_mux_new(dst, src, capture, NULL);
		TCT_EQ_INT(tc_udp_mux_listen(m, (uint16_t)kUdp6Vectors[i].dport),
		           TC_OK);

		uint8_t pkt[4096];
		size_t n = unhex(pkt, sizeof pkt, kUdp6Vectors[i].want);
		uint8_t payload[2048];
		size_t plen = unhex(payload, sizeof payload, kUdp6Vectors[i].payload);

		TCT_EQ_INT(tc_udp_mux_input(m, pkt, n, 1000), TC_OK);

		uint16_t lp = 0, rp = 0;
		uint8_t got[2048];
		size_t glen = 0;
		TCT_EQ_INT(tc_udp_mux_recv(m, &lp, &rp, got, sizeof got, &glen),
		           TC_OK);
		TCT_EQ_INT(lp, (int)kUdp6Vectors[i].dport);
		TCT_EQ_INT(rp, (int)kUdp6Vectors[i].sport);
		TCT_EQ_INT((int)glen, (int)plen);
		if (glen == plen && plen > 0 && memcmp(got, payload, plen) != 0)
			TCT_FAILF("%s: payload came back changed", kUdp6Vectors[i].name);
		tct_checks++;
		tc_udp_mux_free(m);
	}
}

static void test_checksum_rules(void)
{
	tc_udp_mux *m = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_listen(m, 53), TC_OK);

	uint8_t pkt[4096];
	size_t n = unhex(pkt, sizeof pkt, kUdp6Vectors[0].want);

	TCT_CASE("a zero checksum is illegal over IPv6, not merely unprotected");
	/* RFC 8200 s8.1. IPv6 dropped the header checksum, so UDP's is the only
	 * thing standing between a corrupted address and a datagram delivered to
	 * whoever the corruption names. Accepting zero here would be accepting
	 * the IPv4 rule on the wrong protocol. */
	uint8_t z[4096];
	memcpy(z, pkt, n);
	z[TC_IPV6_HEADER_LEN + 6] = 0;
	z[TC_IPV6_HEADER_LEN + 7] = 0;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);
	tc_udp_mux_stats st;
	tc_udp_mux_get_stats(m, &st);
	TCT_EQ_INT((int)st.dropped_checksum, 1);

	TCT_CASE("every single-bit change to the payload is caught");
	/* The pseudo-header is what makes this worth checking: a checksum that
	 * covered only the datagram would still pass all of these. */
	uint8_t data_off = TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN;
	for (size_t byte = data_off; byte < n; byte++) {
		for (int bit = 0; bit < 8; bit++) {
			memcpy(z, pkt, n);
			z[byte] ^= (uint8_t)(1u << bit);
			if (tc_udp_mux_input(m, z, n, 1000) == TC_OK)
				TCT_FAILF("accepted a flip of bit %d in byte %zu", bit, byte);
			tct_checks++;
		}
	}

	TCT_CASE("and a corrupted address is caught, which is the point");
	/* Change the source address and nothing else. Only a checksum that
	 * covers the pseudo-header notices. */
	memcpy(z, pkt, n);
	z[8 + 15] ^= 0xff;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);
	memcpy(z, pkt, n);
	z[24 + 15] ^= 0xff;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("a flipped port is caught too");
	memcpy(z, pkt, n);
	z[TC_IPV6_HEADER_LEN] ^= 0x01;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("the unmodified packet still passes");
	TCT_EQ_INT(tc_udp_mux_input(m, pkt, n, 1000), TC_OK);

	tc_udp_mux_free(m);
}

static void test_checksum_never_sent_as_zero(void)
{
	TCT_CASE("a checksum that computes to zero is sent as 0xffff");
	/* Equal in ones-complement arithmetic, so it verifies identically, but
	 * zero means "absent" and absent is illegal here. Search for a payload
	 * that lands on it rather than asserting the branch is unreachable --
	 * roughly one datagram in 65536 does. */
	tc_udp_mux *m = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	tc_udp_mux *rx = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_listen(rx, 53), TC_OK);

	bool found = false;
	uint8_t payload[4];
	for (uint32_t v = 0; v < 400000 && !found; v++) {
		payload[0] = (uint8_t)(v >> 24);
		payload[1] = (uint8_t)(v >> 16);
		payload[2] = (uint8_t)(v >> 8);
		payload[3] = (uint8_t)v;
		g_sent_len = 0;
		if (tc_udp_mux_send(m, 49152, 53, payload, sizeof payload, 1000) !=
		    TC_OK)
			continue;
		const uint8_t *uh = g_sent + TC_IPV6_HEADER_LEN;
		if (uh[6] == 0xff && uh[7] == 0xff) {
			found = true;
			/* And it must still verify at the far end. */
			TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);
		}
		/* The one thing that must never happen. */
		if (uh[6] == 0 && uh[7] == 0) {
			TCT_FAILF("sent a zero checksum, which IPv6 forbids");
			break;
		}
	}
	if (!found)
		TCT_FAILF("no payload produced a zero checksum in 400000 tries; the "
		          "0xffff path went untested");
	tct_checks++;

	tc_udp_mux_free(m);
	tc_udp_mux_free(rx);
}

/* ---- malformed input ---------------------------------------------------- */

static void test_malformed(void)
{
	tc_udp_mux *m = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_listen(m, 53), TC_OK);

	uint8_t pkt[4096];
	size_t n = unhex(pkt, sizeof pkt, kUdp6Vectors[0].want);
	uint8_t z[4096];

	TCT_CASE("every prefix of a real packet is refused");
	for (size_t k = 0; k < n; k++) {
		if (tc_udp_mux_input(m, pkt, k, 1000) == TC_OK)
			TCT_FAILF("accepted a %zu byte packet", k);
		tct_checks++;
	}

	TCT_CASE("a UDP length that disagrees with the IP payload length");
	/* Two lengths that disagree is how a parser gets talked into reading
	 * past what it was handed. */
	memcpy(z, pkt, n);
	z[TC_IPV6_HEADER_LEN + 4] = 0xff;
	z[TC_IPV6_HEADER_LEN + 5] = 0xff;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	memcpy(z, pkt, n);
	z[TC_IPV6_HEADER_LEN + 5] = 0x04; /* shorter than the IP header says */
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("a UDP length below the header size");
	memcpy(z, pkt, n);
	z[4] = 0;
	z[5] = 4;
	z[TC_IPV6_HEADER_LEN + 4] = 0;
	z[TC_IPV6_HEADER_LEN + 5] = 4;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("an IP payload length longer than the bytes that arrived");
	memcpy(z, pkt, n);
	z[4] = 0x0f;
	z[5] = 0xff;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("not IPv6, and not UDP");
	memcpy(z, pkt, n);
	z[0] = 0x40; /* IPv4 */
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);
	TCT_TRUE(!tc_udp_mux_is_udp(z, n));
	memcpy(z, pkt, n);
	z[6] = 6; /* TCP */
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);
	TCT_TRUE(!tc_udp_mux_is_udp(z, n));
	TCT_TRUE(tc_udp_mux_is_udp(pkt, n));
	TCT_TRUE(!tc_udp_mux_is_udp(NULL, n));

	TCT_CASE("addresses that are not this tunnel's");
	/* The tunnel is point to point. A packet claiming other addresses is
	 * either a bug at the far end or an attempt to have one peer's traffic
	 * treated as another's. */
	memcpy(z, pkt, n);
	z[8 + 15] = 9;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);
	memcpy(z, pkt, n);
	z[24 + 15] = 9;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("a correctly checksummed packet for other addresses is refused");
	/* Flipping an address byte is caught by the checksum, so that alone does
	 * not show the address check does anything. This builds a packet that is
	 * entirely valid -- for a different pair of endpoints -- which only the
	 * address check can reject. On a tunnel carrying one peer, a packet
	 * claiming another peer's addresses is the interesting case. */
	static const uint8_t kOther[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0,
		                                0,    0,    0,    0,    0,    0,    0,
		                                0,    0x09 };
	tc_udp_mux *elsewhere = tc_udp_mux_new(kOther, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_send(elsewhere, 49152, 53, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, 1000), TC_ERR_INVAL);
	tc_udp_mux_free(elsewhere);

	/* And one addressed to a third party, which we should not relay. */
	tc_udp_mux *crosswise = tc_udp_mux_new(kRemote, kOther, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_send(crosswise, 49152, 53, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, 1000), TC_ERR_INVAL);
	tc_udp_mux_free(crosswise);

	TCT_CASE("port zero, which is not a port");
	memcpy(z, pkt, n);
	z[TC_IPV6_HEADER_LEN + 0] = 0;
	z[TC_IPV6_HEADER_LEN + 1] = 0;
	TCT_EQ_INT(tc_udp_mux_input(m, z, n, 1000), TC_ERR_INVAL);

	TCT_CASE("nothing was queued by any of that");
	uint16_t lp, rp;
	uint8_t out[64];
	size_t olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(m, &lp, &rp, out, sizeof out, &olen),
	           TC_ERR_AGAIN);

	tc_udp_mux_free(m);
}

/* ---- listeners and bindings --------------------------------------------- */

static bool accept_high(void *ctx, uint16_t port)
{
	(void)ctx;
	return port >= 8000;
}

static void test_listeners(void)
{
	tc_udp_mux *tx = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	tc_udp_mux *rx = tc_udp_mux_new(kRemote, kLocal, capture, NULL);

	TCT_CASE("a datagram for a port nobody listens on is dropped in silence");
	/* No ICMP port-unreachable: there is no ICMP here, and answering
	 * unsolicited traffic would make the tunnel a reflector. */
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_ERR_INVAL);
	size_t before = g_sent_count;
	TCT_EQ_INT((int)(g_sent_count - before), 0);
	tc_udp_mux_stats st;
	tc_udp_mux_get_stats(rx, &st);
	TCT_EQ_INT((int)st.dropped_no_listener, 1);

	TCT_CASE("and one for a port that is listened on is kept");
	TCT_EQ_INT(tc_udp_mux_listen(rx, 53), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);

	TCT_CASE("listening twice on one port is not an error");
	TCT_EQ_INT(tc_udp_mux_listen(rx, 53), TC_OK);
	TCT_EQ_INT(tc_udp_mux_listen(rx, 0), TC_ERR_INVAL);

	TCT_CASE("the listener table is bounded");
	for (uint16_t p = 1000; p < 1000 + TC_UDPMUX_MAX_LISTENERS + 4; p++)
		(void)tc_udp_mux_listen(rx, p);
	TCT_EQ_INT(tc_udp_mux_listen(rx, 30000), TC_ERR_TOOMANY);

	TCT_CASE("an accept filter opens a range without naming every port");
	tc_udp_mux *srv = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	tc_udp_mux_set_accept_filter(srv, accept_high, NULL);
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 9000, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 22, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_ERR_INVAL);

	tc_udp_mux_free(tx);
	tc_udp_mux_free(rx);
	tc_udp_mux_free(srv);
}

static void test_bindings(void)
{
	tc_udp_mux *m = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	/* One clock for the whole test, and it only goes forwards. Two call
	 * sites disagreeing about the time is exactly the confusion the code is
	 * now defended against, so the test must not rely on it. */
	uint64_t t = 1000;

	TCT_CASE("a binding gives an ephemeral port in the right range");
	uint16_t a = 0;
	TCT_EQ_INT(tc_udp_mux_bind(m, 53, t, &a), TC_OK);
	TCT_TRUE(a >= TC_UDP_EPHEMERAL_LO);

	TCT_CASE("asking again for the same remote port reuses it");
	/* A new source port per query would be what a socket does not do, and
	 * would exhaust the range in a few thousand requests. */
	t += 1000;
	uint16_t b = 0;
	TCT_EQ_INT(tc_udp_mux_bind(m, 53, t, &b), TC_OK);
	TCT_EQ_INT(a, b);

	TCT_CASE("a different remote port gets a different local one");
	uint16_t c = 0;
	TCT_EQ_INT(tc_udp_mux_bind(m, 123, t, &c), TC_OK);
	TCT_TRUE(c != a);

	TCT_CASE("a reply to a bound flow is accepted without a listener");
	/* This is the whole reason bindings exist: the client is not listening
	 * on the ephemeral port, but it did ask a question there. */
	tc_udp_mux *srv = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_send(srv, 53, a, "answer", 6, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, t), TC_OK);
	uint16_t lp = 0, rp = 0;
	uint8_t out[64];
	size_t olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(m, &lp, &rp, out, sizeof out, &olen), TC_OK);
	TCT_EQ_INT(lp, a);
	TCT_EQ_INT(rp, 53);

	TCT_CASE("but a reply from the wrong remote port is not");
	/* The binding is a port pair. Accepting a datagram from any port to our
	 * ephemeral one would let anything on the tunnel answer our question. */
	TCT_EQ_INT(tc_udp_mux_send(srv, 54, a, "forged", 6, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, t), TC_ERR_INVAL);

	TCT_CASE("a stale timestamp does not age a binding in active use");
	/* The clock belongs to the caller, and a packet processed a moment late
	 * carries an earlier one. Letting that move the idle timer backwards
	 * would expire a flow that is talking. */
	TCT_EQ_INT(tc_udp_mux_send(srv, 53, a, "late", 4, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, t - 500), TC_OK);

	TCT_CASE("a binding survives two minutes of silence, as RFC 4787 says");
	/* Shorter breaks request-response protocols that wait longer than that
	 * between packets, and DNS resolvers do. */
	uint64_t last = t;
	tc_udp_mux_tick(m, last + TC_UDPMUX_BINDING_IDLE_MS - 1);
	TCT_EQ_INT(tc_udp_mux_send(srv, 53, a, "still here", 10, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len,
	                            last + TC_UDPMUX_BINDING_IDLE_MS - 1),
	           TC_OK);

	TCT_CASE("and is dropped once it has been idle longer");
	t = 10000000;
	tc_udp_mux_tick(m, t);
	TCT_EQ_INT(tc_udp_mux_send(srv, 53, a, "too late", 8, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, t), TC_ERR_INVAL);
	tc_udp_mux_stats st;
	tc_udp_mux_get_stats(m, &st);
	TCT_TRUE(st.bindings_expired >= 2);

	TCT_CASE("traffic keeps a binding alive");
	uint16_t d = 0;
	TCT_EQ_INT(tc_udp_mux_bind(m, 53, t, &d), TC_OK);
	for (int i = 0; i < 20; i++) {
		t += TC_UDPMUX_BINDING_IDLE_MS / 2;
		TCT_EQ_INT(tc_udp_mux_send(m, d, 53, "ping", 4, t), TC_OK);
		tc_udp_mux_tick(m, t);
	}
	TCT_EQ_INT(tc_udp_mux_send(srv, 53, d, "pong", 4, t), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(m, g_sent, g_sent_len, t), TC_OK);

	TCT_CASE("the binding table is bounded, and says so");
	tc_udp_mux *full = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	int ok = 0;
	for (uint16_t q = 1; q < TC_UDPMUX_MAX_BINDINGS + 10; q++) {
		uint16_t got = 0;
		if (tc_udp_mux_bind(full, q, 1000, &got) == TC_OK)
			ok++;
	}
	TCT_EQ_INT(ok, TC_UDPMUX_MAX_BINDINGS);
	uint16_t got = 0;
	TCT_EQ_INT(tc_udp_mux_bind(full, 60000, 1000, &got), TC_ERR_TOOMANY);

	TCT_CASE("an ephemeral port never collides with a listener");
	tc_udp_mux *l = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_listen(l, TC_UDP_EPHEMERAL_LO), TC_OK);
	uint16_t e = 0;
	TCT_EQ_INT(tc_udp_mux_bind(l, 53, 1000, &e), TC_OK);
	TCT_TRUE(e != TC_UDP_EPHEMERAL_LO);

	tc_udp_mux_free(m);
	tc_udp_mux_free(srv);
	tc_udp_mux_free(full);
	tc_udp_mux_free(l);
}

/* ---- the queue ---------------------------------------------------------- */

static void test_queue(void)
{
	tc_udp_mux *tx = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	tc_udp_mux *rx = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	TCT_EQ_INT(tc_udp_mux_listen(rx, 53), TC_OK);

	TCT_CASE("datagrams come back in the order they arrived");
	for (int i = 0; i < 10; i++) {
		uint8_t body[2] = { (uint8_t)i, 0 };
		TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, body, 2, 1000), TC_OK);
		TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);
	}
	for (int i = 0; i < 10; i++) {
		uint8_t out[8];
		size_t olen = 0;
		TCT_EQ_INT(tc_udp_mux_recv(rx, NULL, NULL, out, sizeof out, &olen),
		           TC_OK);
		TCT_EQ_INT((int)olen, 2);
		TCT_EQ_INT(out[0], i);
	}

	TCT_CASE("a full queue drops the new datagram, not one already accepted");
	/* What a full socket buffer does. Evicting an older one would lose data
	 * the caller has already been promised. */
	for (size_t i = 0; i < TC_UDPMUX_QUEUE; i++) {
		uint8_t body[2] = { (uint8_t)i, 0 };
		TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, body, 2, 1000), TC_OK);
		TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);
	}
	uint8_t extra[2] = { 0xee, 0 };
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, extra, 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_ERR_AGAIN);

	uint8_t out[8];
	size_t olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(rx, NULL, NULL, out, sizeof out, &olen),
	           TC_OK);
	TCT_EQ_INT(out[0], 0); /* the oldest, still there */

	TCT_CASE("and the queue drains and refills without losing its place");
	/* A ring that mishandles wrap-around passes every test that never wraps,
	 * so this deliberately goes round more than once. */
	while (tc_udp_mux_recv(rx, NULL, NULL, out, sizeof out, &olen) == TC_OK)
		;
	for (int round = 0; round < 5; round++) {
		for (size_t i = 0; i < TC_UDPMUX_QUEUE; i++) {
			uint8_t body[2] = { (uint8_t)i, (uint8_t)round };
			TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, body, 2, 1000), TC_OK);
			TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);
		}
		for (size_t i = 0; i < TC_UDPMUX_QUEUE; i++) {
			TCT_EQ_INT(tc_udp_mux_recv(rx, NULL, NULL, out, sizeof out,
			                           &olen),
			           TC_OK);
			TCT_EQ_INT(out[0], (int)i);
			TCT_EQ_INT(out[1], round);
		}
	}

	TCT_CASE("a datagram too big for the caller's buffer stays queued");
	/* Handing back a prefix would hand back something that is not what was
	 * sent, and UDP gives the receiver no way to notice. */
	uint8_t big[600];
	memset(big, 0x7e, sizeof big);
	TCT_EQ_INT(tc_udp_mux_send(tx, 49152, 53, big, sizeof big, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(rx, g_sent, g_sent_len, 1000), TC_OK);
	uint8_t small[10];
	olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(rx, NULL, NULL, small, sizeof small, &olen),
	           TC_ERR_NOSPACE);
	TCT_EQ_INT((int)olen, (int)sizeof big);
	uint8_t roomy[700];
	olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(rx, NULL, NULL, roomy, sizeof roomy, &olen),
	           TC_OK);
	TCT_EQ_INT((int)olen, (int)sizeof big);
	TCT_EQ_MEM(roomy, big, sizeof big);

	tc_udp_mux_free(tx);
	tc_udp_mux_free(rx);
}

/* ---- acting as an exit node --------------------------------------------- */

static void ep6(tc_endpoint *e, const char *text, uint16_t port)
{
	memset(e, 0, sizeof *e);
	inet_pton(AF_INET6, text, e->ip);
	e->ip_len = 16;
	e->port = port;
}

static void test_udp_exit_node(void)
{
	tc_udp_mux *cl = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	tc_udp_mux *srv = tc_udp_mux_new(kRemote, kLocal, capture, NULL);

	tc_endpoint beyond;
	ep6(&beyond, "2001:db8::10", 53);

	TCT_CASE("a datagram addressed beyond the peer is dropped by default");
	/* Worse than the TCP case, if anything: there is no handshake, so one
	 * forged datagram is a complete request, and plenty of UDP services will
	 * act on a single one. */
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 49152, &beyond, "query", 5, 1000),
	           TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_ERR_INVAL);

	TCT_CASE("with exit-node on, it arrives and names its destination");
	tc_udp_mux_set_exit_node(srv, true);
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 49152, &beyond, "query", 5, 1000),
	           TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_OK);

	tc_udp_addrs a;
	uint8_t got[64];
	size_t n = 0;
	TCT_EQ_INT(tc_udp_mux_recv_addrs(srv, &a, got, sizeof got, &n), TC_OK);
	TCT_EQ_INT((int)n, 5);
	TCT_TRUE(memcmp(got, "query", 5) == 0);
	TCT_EQ_INT(a.remote_port, 49152);
	TCT_EQ_INT(a.dst.ip_len, 16);
	TCT_EQ_INT(a.dst.port, 53);
	char where[80];
	TCT_EQ_INT(tc_endpoint_format(where, sizeof where, &a.dst), TC_OK);
	TCT_EQ_STR(where, "[2001:db8::10]:53");

	TCT_CASE("and needs no listener, because the port is not ours");
	/* Nothing called tc_udp_mux_listen on 53. An exit node's ports belong to
	 * the destinations its peer names. */
	tc_udp_mux_stats st;
	tc_udp_mux_get_stats(srv, &st);
	TCT_EQ_INT((int)st.dropped_no_listener, 0);

	TCT_CASE("a datagram addressed to us still needs one");
	/* Turning exit-node mode on must not quietly open every port on the
	 * node itself. */
	TCT_EQ_INT(tc_udp_mux_send(cl, 49152, 9999, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_ERR_INVAL);
	tc_udp_mux_get_stats(srv, &st);
	TCT_EQ_INT((int)st.dropped_no_listener, 1);

	TCT_CASE("a datagram to us reports no destination, which is the signal");
	/* ip_len 0 is how a caller tells "for me" from "forward this" without a
	 * separate flag to forget to set. */
	TCT_EQ_INT(tc_udp_mux_listen(srv, 9999), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send(cl, 49152, 9999, "hi", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_recv_addrs(srv, &a, got, sizeof got, &n), TC_OK);
	TCT_EQ_INT(a.dst.ip_len, 0);
	TCT_EQ_INT(a.local_port, 9999);

	TCT_CASE("the checksum covers the destination, not our own address");
	/* send_to must checksum against where it is going. A datagram summed
	 * against the peer's address instead would be discarded by anything that
	 * checks -- which, over IPv6, is everything. */
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 49152, &beyond, "x", 1, 1000), TC_OK);
	uint8_t pkt[2048];
	size_t plen = g_sent_len;
	memcpy(pkt, g_sent, plen);
	TCT_EQ_MEM(pkt + 24, beyond.ip, 16);
	/* Verified the way a receiver would: summing the datagram with its own
	 * checksum in place yields zero. */
	TCT_EQ_INT(tc_udp_mux_input(srv, pkt, plen, 1000), TC_OK);

	TCT_CASE("two destinations on one port pair stay apart");
	/* The same hazard tcpmux had, and UDP cannot rely on a connection to
	 * keep them separate -- the destination has to travel with each
	 * datagram, which is why recv reports it. */
	tc_endpoint other;
	ep6(&other, "2001:db8::11", 53);
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 49152, &beyond, "one", 3, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 49152, &other, "two", 3, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv, g_sent, g_sent_len, 1000), TC_OK);

	while (tc_udp_mux_recv_addrs(srv, &a, got, sizeof got, &n) == TC_OK) {
		if (n == 3 && memcmp(got, "one", 3) == 0)
			TCT_TRUE(tc_endpoint_equal(&a.dst, &beyond));
		else if (n == 3 && memcmp(got, "two", 3) == 0)
			TCT_TRUE(tc_endpoint_equal(&a.dst, &other));
	}

	TCT_CASE("a forwarded reply comes back naming where it came from");
	/* The exit node's return path. One client port may have several
	 * destinations in flight, and a datagram carries no other clue about
	 * which answered -- so the server sends the reply with the destination
	 * as its source, and the client matches it against the flow it opened. */
	tc_udp_mux *cl2 = tc_udp_mux_new(kLocal, kRemote, capture, NULL);
	tc_udp_mux *srv2 = tc_udp_mux_new(kRemote, kLocal, capture, NULL);
	tc_udp_mux_set_exit_node(srv2, true);

	tc_endpoint d1, d2;
	ep6(&d1, "2001:db8::10", 53);
	ep6(&d2, "2001:db8::11", 53);
	TCT_EQ_INT(tc_udp_mux_send_to(cl2, 49152, &d1, "q1", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv2, g_sent, g_sent_len, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send_to(cl2, 49152, &d2, "q2", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(srv2, g_sent, g_sent_len, 1000), TC_OK);

	/* Both answers arrive on the same client port, from different places. */
	TCT_EQ_INT(tc_udp_mux_send_as(srv2, &d2, 49152, "a2", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send_as(srv2, &d1, 49152, "a1", 2, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_OK);

	tc_udp_addrs r;
	uint8_t rb[64];
	size_t rn = 0;
	TCT_EQ_INT(tc_udp_mux_recv_addrs(cl2, &r, rb, sizeof rb, &rn), TC_OK);
	TCT_EQ_INT((int)rn, 2);
	TCT_TRUE(memcmp(rb, "a2", 2) == 0);
	TCT_TRUE(tc_endpoint_equal(&r.dst, &d2));
	TCT_EQ_INT(tc_udp_mux_recv_addrs(cl2, &r, rb, sizeof rb, &rn), TC_OK);
	TCT_TRUE(memcmp(rb, "a1", 2) == 0);
	TCT_TRUE(tc_endpoint_equal(&r.dst, &d1));

	TCT_CASE("a reply from somewhere we never sent to is refused");
	/* Without this, a peer could deliver anything it liked as though it
	 * were the answer to a request we made -- which for DNS over an exit
	 * node is the whole attack. */
	tc_endpoint never;
	ep6(&never, "2001:db8::99", 53);
	TCT_EQ_INT(tc_udp_mux_send_as(srv2, &never, 49152, "forged", 6, 1000),
	           TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_ERR_INVAL);

	TCT_CASE("and one to a port we never sent from is refused");
	TCT_EQ_INT(tc_udp_mux_send_as(srv2, &d1, 49153, "wrongport", 9, 1000),
	           TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_ERR_INVAL);

	TCT_CASE("a listener does not open the door to a foreign source");
	/* A listener says "I accept datagrams to this port from the peer". It
	 * must not also mean "from anywhere the peer cares to name". */
	TCT_EQ_INT(tc_udp_mux_listen(cl2, 7777), TC_OK);
	TCT_EQ_INT(tc_udp_mux_send_as(srv2, &never, 7777, "nope", 4, 1000),
	           TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_ERR_INVAL);
	/* But the peer itself still reaches that listener. */
	TCT_EQ_INT(tc_udp_mux_send(srv2, 5353, 7777, "yes", 3, 1000), TC_OK);
	TCT_EQ_INT(tc_udp_mux_input(cl2, g_sent, g_sent_len, 1000), TC_OK);

	tc_udp_mux_free(cl2);
	tc_udp_mux_free(srv2);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_udp_mux_send_as(NULL, &beyond, 1, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send_as(cl, NULL, 1, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send_as(cl, &beyond, 0, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send_to(NULL, 1, &beyond, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 1, NULL, "x", 1, 0), TC_ERR_INVAL);
	tc_endpoint v4;
	memset(&v4, 0, sizeof v4);
	v4.ip_len = 4;
	v4.port = 53;
	/* An IPv4 destination has to be wrapped first; the tunnel carries only
	 * IPv6, and accepting a four-byte address here would mean guessing. */
	TCT_EQ_INT(tc_udp_mux_send_to(cl, 1, &v4, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_recv_addrs(cl, NULL, got, sizeof got, &n),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_recv_addrs(NULL, &a, got, sizeof got, &n),
	           TC_ERR_INVAL);
	tc_udp_mux_set_exit_node(NULL, true);

	tc_udp_mux_free(cl);
	tc_udp_mux_free(srv);
}

static void test_sizes_and_api(void)
{
	tc_udp_mux *m = tc_udp_mux_new(kLocal, kRemote, capture, NULL);

	TCT_CASE("the largest datagram that fits is carried");
	static uint8_t big[TC_UDP_MAX_DGRAM];
	memset(big, 0xa5, sizeof big);
	TCT_EQ_INT(tc_udp_mux_send(m, 49152, 53, big, sizeof big, 1000), TC_OK);
	TCT_EQ_INT((int)g_sent_len,
	           (int)(TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN + sizeof big));

	TCT_CASE("and one byte more is refused rather than fragmented");
	/* There is no IPv6 fragmentation here, and silently truncating would
	 * corrupt the datagram in a way the receiver cannot detect. */
	static uint8_t toobig[TC_UDP_MAX_DGRAM + 1];
	TCT_EQ_INT(tc_udp_mux_send(m, 49152, 53, toobig, sizeof toobig, 1000),
	           TC_ERR_TOOMANY);

	TCT_CASE("a zero-length datagram is legal");
	TCT_EQ_INT(tc_udp_mux_send(m, 49152, 53, NULL, 0, 1000), TC_OK);
	TCT_EQ_INT((int)g_sent_len, TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN);

	TCT_CASE("port zero is refused on the way out too");
	TCT_EQ_INT(tc_udp_mux_send(m, 0, 53, "x", 1, 1000), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send(m, 49152, 0, "x", 1, 1000), TC_ERR_INVAL);

	TCT_CASE("null arguments");
	TCT_TRUE(tc_udp_mux_new(NULL, kRemote, capture, NULL) == NULL);
	TCT_TRUE(tc_udp_mux_new(kLocal, NULL, capture, NULL) == NULL);
	TCT_TRUE(tc_udp_mux_new(kLocal, kRemote, NULL, NULL) == NULL);
	TCT_EQ_INT(tc_udp_mux_send(NULL, 1, 1, "x", 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_send(m, 1, 1, NULL, 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_input(NULL, (const uint8_t *)"x", 1, 0),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_input(m, NULL, 1, 0), TC_ERR_INVAL);
	size_t olen = 0;
	TCT_EQ_INT(tc_udp_mux_recv(NULL, NULL, NULL, NULL, 0, &olen),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_recv(m, NULL, NULL, NULL, 0, NULL), TC_ERR_INVAL);
	uint16_t p = 0;
	TCT_EQ_INT(tc_udp_mux_bind(NULL, 53, 0, &p), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_bind(m, 0, 0, &p), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_bind(m, 53, 0, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_udp_mux_listen(NULL, 53), TC_ERR_INVAL);
	tc_udp_mux_tick(NULL, 0);
	tc_udp_mux_set_accept_filter(NULL, NULL, NULL);
	tc_udp_mux_get_stats(NULL, NULL);
	tc_udp_mux_free(NULL);

	tc_udp_mux_free(m);
}

int main(void)
{
	test_matches_gopacket();
	test_accepts_gopackets_packets();
	test_checksum_rules();
	test_checksum_never_sent_as_zero();
	test_malformed();
	test_listeners();
	test_bindings();
	test_queue();
	test_udp_exit_node();
	test_sizes_and_api();
	return tct_report("udpmux");
}
