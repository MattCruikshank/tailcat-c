/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Addresses, and how they are written down.
 *
 * The formatter existed for a while with only one IPv6 case covering it --
 * RFC 5769's STUN vector, which happens to have no zero groups in it. Every
 * address that could be compressed came out wrong, and it took a disco
 * endpoint list to notice, because "2001:db8:1" still looks like an address.
 */

#include "tc/endpoint.h"

#include "tctest.h"

#include <arpa/inet.h>

static void v6(tc_endpoint *ep, const uint8_t b[16], uint16_t port)
{
	memset(ep, 0, sizeof *ep);
	memcpy(ep->ip, b, 16);
	ep->ip_len = 16;
	ep->port = port;
}

static void expect_v6(const uint8_t b[16], const char *want)
{
	tc_endpoint ep;
	v6(&ep, b, 443);
	char got[80];
	if (tc_endpoint_format(got, sizeof got, &ep) != TC_OK) {
		TCT_FAILF("could not format, want %s", want);
		return;
	}
	char full[80];
	snprintf(full, sizeof full, "[%s]:443", want);
	TCT_EQ_STR(got, full);
}

static void test_v4(void)
{
	TCT_CASE("IPv4 addresses");
	tc_endpoint ep;
	memset(&ep, 0, sizeof ep);
	ep.ip[0] = 203;
	ep.ip[1] = 0;
	ep.ip[2] = 113;
	ep.ip[3] = 7;
	ep.ip_len = 4;
	ep.port = 41641;
	char s[64];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);
	TCT_EQ_STR(s, "203.0.113.7:41641");

	memset(&ep, 0, sizeof ep);
	ep.ip_len = 4;
	ep.port = 0;
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);
	TCT_EQ_STR(s, "0.0.0.0:0");

	memset(ep.ip, 255, 4);
	ep.port = 65535;
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);
	TCT_EQ_STR(s, "255.255.255.255:65535");
}

static void test_v6_compression(void)
{
	TCT_CASE("RFC 5952: the longest run of zero groups is compressed");
	static const struct {
		uint8_t b[16];
		const char *want;
	} cases[] = {
		/* No zeros at all -- the case the suite used to have. */
		{ { 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22,
		    0x33, 0x44, 0x55, 0x66, 0x77 },
		  "2001:db8:1234:5678:11:2233:4455:6677" },
		/* A run in the middle, which is the common form. */
		{ { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 },
		  "2001:db8::1" },
		/* A leading run. */
		{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, "::1" },
		/* A trailing run. */
		{ { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		  "2001:db8::" },
		/* The unspecified address is nothing but a run. */
		{ { 0 }, "::" },
		/* A single zero group is written out: "::" would be no shorter, and
		 * RFC 5952 forbids it so that one address has one spelling. */
		{ { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0x00, 0x01, 0, 0x02, 0, 0x03, 0,
		    0x04, 0, 0x05 },
		  "2001:db8:0:1:2:3:4:5" },
		/* Two equal runs: the first wins. */
		{ { 0x20, 0x01, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0x02, 0, 0x03 },
		  "2001::1:0:0:2:3" },
		/* A later run that is strictly longer wins over an earlier one. */
		{ { 0x20, 0x01, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x03 },
		  "2001:0:0:1::3" },
		/* Leading zeros within a group are never printed. */
		{ { 0x00, 0x0a, 0x0b, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x0e, 0x00,
		    0x0f },
		  "a:bcd::e:f" },
		/* A v4-mapped address formats as IPv6 when it is stored as sixteen
		 * bytes; tc_endpoint_from16 is what turns it back into IPv4. */
		{ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7 },
		  "::ffff:cb00:7107" },
	};

	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
		expect_v6(cases[i].b, cases[i].want);
}

static void test_v6_reparses(void)
{
	TCT_CASE("what we print, the system's own parser reads back");
	/* An independent check that the spelling is right, rather than just
	 * self-consistent: inet_pton is the reference here. */
	static const uint8_t patterns[][16] = {
		{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 },
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 },
		{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
		{ 0 },
		{ 0x20, 0x01, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0x02, 0, 0x03 },
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7 },
	};
	for (size_t i = 0; i < sizeof patterns / sizeof patterns[0]; i++) {
		tc_endpoint ep;
		v6(&ep, patterns[i], 443);
		char s[80];
		TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);

		/* Strip the "[" and "]:443" the endpoint form adds. */
		char bare[80];
		size_t n = strlen(s);
		if (n < 7 || s[0] != '[') {
			TCT_FAILF("malformed: %s", s);
			continue;
		}
		const char *close = strchr(s, ']');
		if (close == NULL) {
			TCT_FAILF("malformed: %s", s);
			continue;
		}
		size_t bn = (size_t)(close - s - 1);
		memcpy(bare, s + 1, bn);
		bare[bn] = '\0';

		uint8_t back[16];
		if (inet_pton(AF_INET6, bare, back) != 1) {
			TCT_FAILF("inet_pton rejected our output: %s", bare);
			continue;
		}
		TCT_EQ_MEM(back, patterns[i], 16);
	}
}

static void test_errors(void)
{
	TCT_CASE("bad arguments and buffers too small");
	tc_endpoint ep;
	memset(&ep, 0, sizeof ep);
	ep.ip_len = 16;
	char s[80];
	TCT_EQ_INT(tc_endpoint_format(NULL, sizeof s, &ep), TC_ERR_INVAL);
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_endpoint_format(s, 0, &ep), TC_ERR_INVAL);

	ep.ip_len = 7;
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_ERR_INVAL);

	TCT_CASE("a truncated result is an error, never a short address");
	/* Every prefix length of a buffer, for the longest address there is.
	 * Silently returning "2001:db8:1234" would be an address too. */
	static const uint8_t longest[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34,
		                                 0x56, 0x78, 0x00, 0x11, 0x22, 0x33,
		                                 0x44, 0x55, 0x66, 0x77 };
	v6(&ep, longest, 32853);
	char want[80];
	TCT_EQ_INT(tc_endpoint_format(want, sizeof want, &ep), TC_OK);
	size_t full = strlen(want);
	for (size_t cap = 1; cap <= full + 1; cap++) {
		char buf[80];
		memset(buf, 'X', sizeof buf);
		int rc = tc_endpoint_format(buf, cap, &ep);
		if (cap <= full) {
			if (rc == TC_OK)
				TCT_FAILF("claimed success with %zu bytes for %zu", cap, full);
			tct_checks++;
		} else {
			TCT_EQ_INT(rc, TC_OK);
			TCT_EQ_STR(buf, want);
		}
	}
}

static void test_equal_and_map(void)
{
	TCT_CASE("equality, and the v4-mapped wire form");
	tc_endpoint a, b, c;
	memset(&a, 0, sizeof a);
	a.ip[0] = 203;
	a.ip[2] = 113;
	a.ip[3] = 7;
	a.ip_len = 4;
	a.port = 41641;

	uint8_t w[16];
	tc_endpoint_to16(&a, w);
	static const uint8_t kPrefix[12] = { 0, 0, 0, 0, 0, 0,
		                                 0, 0, 0, 0, 0xff, 0xff };
	TCT_EQ_MEM(w, kPrefix, 12);

	/* The round trip must land back on IPv4. An address that arrives mapped
	 * and stays mapped compares unequal to the same address learned any other
	 * way, and one path then looks like two. */
	tc_endpoint_from16(&b, w, a.port);
	TCT_EQ_INT(b.ip_len, 4);
	TCT_TRUE(tc_endpoint_equal(&a, &b));

	TCT_CASE("differing family, address or port are all unequal");
	memcpy(&c, &a, sizeof c);
	c.port = 41642;
	TCT_TRUE(!tc_endpoint_equal(&a, &c));
	memcpy(&c, &a, sizeof c);
	c.ip[3] = 8;
	TCT_TRUE(!tc_endpoint_equal(&a, &c));
	memcpy(&c, &a, sizeof c);
	c.ip_len = 16;
	TCT_TRUE(!tc_endpoint_equal(&a, &c));
	TCT_TRUE(!tc_endpoint_equal(&a, NULL));
	TCT_TRUE(!tc_endpoint_equal(NULL, &a));

	TCT_CASE("a real IPv6 address survives the wire form unchanged");
	static const uint8_t kV6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		                             0,    0,    0,    0,    0, 0, 0, 1 };
	v6(&a, kV6, 443);
	tc_endpoint_to16(&a, w);
	TCT_EQ_MEM(w, kV6, 16);
	tc_endpoint_from16(&b, w, 443);
	TCT_EQ_INT(b.ip_len, 16);
	TCT_TRUE(tc_endpoint_equal(&a, &b));

	TCT_CASE("::ffff:0:0/96 is the only prefix that unmaps");
	/* The unspecified address and ::1 share eleven of those twelve bytes, and
	 * turning either into an IPv4 address would be wrong. */
	static const uint8_t kLoop[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
		                               0, 0, 0, 0, 0, 0, 0, 1 };
	tc_endpoint_from16(&b, kLoop, 443);
	TCT_EQ_INT(b.ip_len, 16);
	static const uint8_t kNat64[16] = { 0, 0x64, 0xff, 0x9b, 0, 0,  0,   0,
		                                0, 0,    0,    0,    203, 0, 113, 7 };
	tc_endpoint_from16(&b, kNat64, 443);
	TCT_EQ_INT(b.ip_len, 16);
}

static void test_candidate(void)
{
	TCT_CASE("which of our own addresses are worth advertising");
	static const struct {
		const char *name;
		uint8_t ip[4];
		bool want;
	} v4[] = {
		{ "a public address", { 203, 0, 113, 7 }, true },
		{ "a LAN address, the best path there is", { 192, 168, 1, 10 }, true },
		{ "another RFC 1918 range", { 10, 0, 0, 1 }, true },
		{ "and the third", { 172, 16, 0, 1 }, true },
		{ "loopback, which would reach the peer itself", { 127, 0, 0, 1 },
		  false },
		{ "\"this network\"", { 0, 1, 2, 3 }, false },
		{ "link-local", { 169, 254, 1, 1 }, false },
		{ "multicast", { 224, 0, 0, 1 }, false },
		{ "the reserved top of the space", { 255, 255, 255, 255 }, false },
		{ "carrier-grade NAT / tailnet space", { 100, 64, 0, 1 }, false },
		{ "the top of that range", { 100, 127, 255, 255 }, false },
		{ "just below it, which is ordinary space", { 100, 63, 0, 1 }, true },
		{ "just above it, likewise", { 100, 128, 0, 1 }, true },
	};
	for (size_t i = 0; i < sizeof v4 / sizeof v4[0]; i++) {
		tc_endpoint ep;
		memset(&ep, 0, sizeof ep);
		memcpy(ep.ip, v4[i].ip, 4);
		ep.ip_len = 4;
		ep.port = 41641;
		if (tc_endpoint_is_candidate(&ep) != v4[i].want)
			TCT_FAILF("%s: wanted %s", v4[i].name,
			          v4[i].want ? "kept" : "dropped");
		tct_checks++;
	}

	TCT_CASE("a port of zero is never a candidate");
	/* It is the absence of a port, not a port. Advertising it sends the peer
	 * probing somewhere nothing is listening. */
	tc_endpoint ep;
	memset(&ep, 0, sizeof ep);
	ep.ip[0] = 203;
	ep.ip[2] = 113;
	ep.ip[3] = 7;
	ep.ip_len = 4;
	ep.port = 0;
	TCT_TRUE(!tc_endpoint_is_candidate(&ep));
	TCT_TRUE(!tc_endpoint_is_candidate(NULL));

	TCT_CASE("and an unset address is not one either");
	memset(&ep, 0, sizeof ep);
	ep.port = 41641;
	TCT_TRUE(!tc_endpoint_is_candidate(&ep));
}

int main(void)
{
	test_v4();
	test_v6_compression();
	test_v6_reparses();
	test_errors();
	test_equal_and_map();
	test_candidate();
	return tct_report("endpoint");
}
