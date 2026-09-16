/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The UDP transport, and which of our own addresses are worth advertising.
 *
 * The candidate filter is the part that repays testing. It decides what a
 * peer will spend round trips probing, and both kinds of mistake are quiet:
 * a wrongly accepted address is a probe that can never arrive, and a wrongly
 * rejected one is a direct path that is never found. Neither shows up as a
 * failure anywhere -- the tunnel just stays on the relay.
 *
 * The socket half runs over loopback, so it needs no network.
 */

#include "tc/udp.h"

#include "tctest.h"

#include <string.h>

/* ep4 and ep6 build endpoints compactly. */
static tc_endpoint ep4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                       uint16_t port)
{
	tc_endpoint e;
	memset(&e, 0, sizeof e);
	e.ip[0] = a;
	e.ip[1] = b;
	e.ip[2] = c;
	e.ip[3] = d;
	e.ip_len = 4;
	e.port = port;
	return e;
}

static tc_endpoint ep6(const char *hex16, uint16_t port)
{
	tc_endpoint e;
	memset(&e, 0, sizeof e);
	for (size_t i = 0; i < 16; i++) {
		int hi = (hex16[2 * i] <= '9') ? hex16[2 * i] - '0'
		                               : (hex16[2 * i] | 32) - 'a' + 10;
		int lo = (hex16[2 * i + 1] <= '9')
		             ? hex16[2 * i + 1] - '0'
		             : (hex16[2 * i + 1] | 32) - 'a' + 10;
		e.ip[i] = (uint8_t)((hi << 4) | lo);
	}
	e.ip_len = 16;
	e.port = port;
	return e;
}

static void test_candidates_accepted(void)
{
	TCT_CASE("routable and private addresses are offered");
	/* Private ones stay on purpose: two peers on the same LAN reaching each
	 * other that way is the best path there is, and it is the case a filter
	 * written only with the public internet in mind would throw away. */
	tc_endpoint cases[] = {
		ep4(203, 0, 113, 7, 41641),   /* public */
		ep4(192, 168, 1, 10, 41641),  /* RFC 1918 */
		ep4(10, 0, 0, 5, 41641),      /* RFC 1918 */
		ep4(172, 16, 3, 4, 41641),    /* RFC 1918 */
		ep4(100, 63, 0, 1, 41641),    /* just below the CGNAT range */
		ep4(100, 128, 0, 1, 41641),   /* just above it */
		ep4(1, 1, 1, 1, 41641),
		ep4(223, 255, 255, 255, 41641), /* the last unicast v4 */
	};
	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		if (!tc_endpoint_is_candidate(&cases[i])) {
			char s[64];
			tc_endpoint_format(s, sizeof s, &cases[i]);
			TCT_FAILF("rejected %s, which is reachable", s);
		}
		tct_checks++;
	}

	TCT_CASE("and their IPv6 equivalents");
	tc_endpoint v6[] = {
		ep6("20010db8000000000000000000000001", 41641), /* documentation */
		ep6("fd001234000000000000000000000001", 41641), /* unique-local */
		ep6("2606470000000000000000000000ffff", 41641),
	};
	for (size_t i = 0; i < sizeof v6 / sizeof v6[0]; i++) {
		if (!tc_endpoint_is_candidate(&v6[i])) {
			char s[64];
			tc_endpoint_format(s, sizeof s, &v6[i]);
			TCT_FAILF("rejected %s", s);
		}
		tct_checks++;
	}
}

static void test_candidates_rejected(void)
{
	TCT_CASE("addresses a peer could never reach are not offered");
	struct {
		const char *why;
		tc_endpoint ep;
	} bad[] = {
		{ "loopback: the peer would reach itself", ep4(127, 0, 0, 1, 41641) },
		{ "0.0.0.0/8", ep4(0, 0, 0, 0, 41641) },
		{ "0.x is this-network", ep4(0, 1, 2, 3, 41641) },
		{ "link-local, one segment only", ep4(169, 254, 1, 1, 41641) },
		{ "multicast", ep4(224, 0, 0, 1, 41641) },
		{ "reserved", ep4(240, 0, 0, 1, 41641) },
		{ "broadcast", ep4(255, 255, 255, 255, 41641) },
		{ "carrier NAT / tailnet range, low", ep4(100, 64, 0, 1, 41641) },
		{ "carrier NAT / tailnet range, high", ep4(100, 127, 255, 254, 41641) },
		{ "port 0 is not somewhere to send", ep4(203, 0, 113, 7, 0) },
		{ "::", ep6("00000000000000000000000000000000", 41641) },
		{ "::1", ep6("00000000000000000000000000000001", 41641) },
		{ "fe80::/10 link-local", ep6("fe800000000000000000000000000001", 41641) },
		{ "febf:: is still link-local",
		  ep6("febf0000000000000000000000000001", 41641) },
		{ "ff00::/8 multicast", ep6("ff020000000000000000000000000001", 41641) },
		{ "v4-mapped, a duplicate of the v4 form",
		  ep6("00000000000000000000ffffcb007107", 41641) },
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		if (tc_endpoint_is_candidate(&bad[i].ep)) {
			char s[64];
			tc_endpoint_format(s, sizeof s, &bad[i].ep);
			TCT_FAILF("offered %s (%s)", s, bad[i].why);
		}
		tct_checks++;
	}

	TCT_CASE("fec0:: is not link-local and is still offered");
	/* The boundary: fe80::/10 covers fe80 through febf. Site-local fec0::/10
	 * is deprecated but not link-local, and a filter using a byte comparison
	 * instead of a mask would wrongly drop it. */
	tc_endpoint fec0 = ep6("fec00000000000000000000000000001", 41641);
	TCT_TRUE(tc_endpoint_is_candidate(&fec0));

	TCT_CASE("malformed endpoints are refused");
	tc_endpoint junk;
	memset(&junk, 0, sizeof junk);
	junk.ip_len = 7;
	junk.port = 1;
	TCT_TRUE(!tc_endpoint_is_candidate(&junk));
	TCT_TRUE(!tc_endpoint_is_candidate(NULL));
}

static void test_sockets(void)
{
	TCT_CASE("a socket pair opens and reports its port");
	tc_udp a, b;
	TCT_EQ_INT(tc_udp_open(&a, 0), TC_OK);
	TCT_EQ_INT(tc_udp_open(&b, 0), TC_OK);
	TCT_TRUE(a.port != 0);
	TCT_TRUE(b.port != 0);
	TCT_TRUE(a.port != b.port);

	TCT_CASE("a datagram goes from one to the other over loopback");
	tc_endpoint to_b = ep4(127, 0, 0, 1, b.port);
	static const char kMsg[] = "direct path, one day";
	TCT_EQ_INT(tc_udp_send(&a, &to_b, kMsg, sizeof kMsg - 1), TC_OK);

	tc_endpoint from;
	uint8_t buf[256];
	size_t n = 0;
	TCT_EQ_INT(tc_udp_recv(&b, &from, buf, sizeof buf, &n, 2000), TC_OK);
	TCT_EQ_INT((int)n, (int)(sizeof kMsg - 1));
	TCT_EQ_MEM(buf, kMsg, sizeof kMsg - 1);

	TCT_CASE("and the sender's address and port come back with it");
	/* Which is what lets a peer learn where to answer, and what the whole
	 * direct path depends on. */
	TCT_EQ_INT(from.ip_len, 4);
	TCT_EQ_INT(from.port, a.port);

	TCT_CASE("a reply reaches the original sender");
	TCT_EQ_INT(tc_udp_send(&b, &from, "pong", 4), TC_OK);
	tc_endpoint back;
	TCT_EQ_INT(tc_udp_recv(&a, &back, buf, sizeof buf, &n, 2000), TC_OK);
	TCT_EQ_INT((int)n, 4);
	TCT_EQ_MEM(buf, "pong", 4);
	TCT_EQ_INT(back.port, b.port);

	TCT_CASE("silence is a timeout, not an error");
	/* On a direct path silence is the normal state between packets, so the
	 * caller must be able to tell it apart from a broken socket. */
	TCT_EQ_INT(tc_udp_recv(&a, &back, buf, sizeof buf, &n, 50),
	           TC_ERR_TIMEOUT);

	TCT_CASE("the descriptors are available for an event loop");
	int fds[4];
	size_t nf = tc_udp_fds(&a, fds, 4);
	TCT_TRUE(nf >= 1);
	for (size_t i = 0; i < nf; i++)
		TCT_TRUE(fds[i] >= 0);

	TCT_CASE("an endpoint with no matching socket is refused, not crashed");
	tc_endpoint nowhere;
	memset(&nowhere, 0, sizeof nowhere);
	nowhere.ip_len = 9;
	nowhere.port = 1;
	TCT_EQ_INT(tc_udp_send(&a, &nowhere, "x", 1), TC_ERR_INVAL);

	tc_udp_close(&a);
	tc_udp_close(&b);
	TCT_EQ_INT(a.fd4, -1);
	TCT_EQ_INT(a.fd6, -1);

	TCT_CASE("closing twice is harmless");
	tc_udp_close(&a);
	tc_udp_close(NULL);
}

static void test_requested_port(void)
{
	TCT_CASE("a requested port is honoured, and both families share it");
	/* A peer told "reach me on N" has to find us there whichever family it
	 * chooses, or half the candidates are wrong. */
	tc_udp probe;
	TCT_EQ_INT(tc_udp_open(&probe, 0), TC_OK);
	uint16_t want = probe.port;
	tc_udp_close(&probe);

	tc_udp u;
	if (tc_udp_open(&u, want) == TC_OK) {
		TCT_EQ_INT(u.port, want);
		tc_udp_close(&u);
	} else {
		/* Another process may have taken it in between; that is not a bug
		 * here, so the case is counted rather than asserted. */
		tct_checks++;
	}
}

static void test_local_endpoints(void)
{
	TCT_CASE("local addresses come back paired with the bound port");
	tc_udp u;
	TCT_EQ_INT(tc_udp_open(&u, 0), TC_OK);

	tc_endpoint eps[TC_UDP_MAX_LOCAL];
	size_t n = tc_udp_local_endpoints(&u, eps, TC_UDP_MAX_LOCAL);
	/* Zero is a legitimate answer on a host with only loopback, so this
	 * asserts what must be true of whatever came back rather than that
	 * something did. */
	for (size_t i = 0; i < n; i++) {
		TCT_EQ_INT(eps[i].port, u.port);
		if (!tc_endpoint_is_candidate(&eps[i]))
			TCT_FAILF("listed an address the filter rejects");
		tct_checks++;
	}

	TCT_CASE("with no duplicates");
	/* The same address can appear on several interfaces, and a duplicate
	 * candidate is a duplicate probe for the peer. */
	for (size_t i = 0; i < n; i++)
		for (size_t j = i + 1; j < n; j++)
			if (tc_endpoint_equal(&eps[i], &eps[j]))
				TCT_FAILF("address %zu and %zu are the same", i, j);
	tct_checks++;

	TCT_CASE("a short buffer truncates rather than overruns");
	tc_endpoint one;
	size_t got = tc_udp_local_endpoints(&u, &one, 1);
	TCT_TRUE(got <= 1);

	TCT_EQ_INT((int)tc_udp_local_endpoints(NULL, eps, 4), 0);
	TCT_EQ_INT((int)tc_udp_local_endpoints(&u, NULL, 4), 0);
	TCT_EQ_INT((int)tc_udp_local_endpoints(&u, eps, 0), 0);

	tc_udp_close(&u);
}

int main(void)
{
	test_candidates_accepted();
	test_candidates_rejected();
	test_sockets();
	test_requested_port();
	test_local_endpoints();
	return tct_report("udp");
}
