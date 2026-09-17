/* SPDX-License-Identifier: BSD-3-Clause
 *
 * IPv4 destinations wrapped for an IPv6-only tunnel.
 *
 * Two anchors, neither of them ours. RFC 6052 section 2.4 publishes a worked
 * example that can be checked by eye, and the system resolver will embed a
 * dotted quad into an IPv6 address on request -- "64:ff9b::192.0.2.33" is
 * legal input to inet_pton, and it does the layout itself. Our byte copy has
 * to agree with both.
 */

#include "tc/nat64.h"

#include "tctest.h"

#include <arpa/inet.h>

static void ep4(tc_endpoint *e, uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                uint16_t port)
{
	memset(e, 0, sizeof *e);
	e->ip[0] = a;
	e->ip[1] = b;
	e->ip[2] = c;
	e->ip[3] = d;
	e->ip_len = 4;
	e->port = port;
}

static void test_rfc6052_example(void)
{
	TCT_CASE("RFC 6052 section 2.4: 192.0.2.33 becomes 64:ff9b::192.0.2.33");
	/* The published example, transcribed so it can be checked against the
	 * document by eye. Everything else here is generated; this one is the
	 * fixed point that says the generator is pointed at the right prefix. */
	tc_endpoint v4, wrapped;
	ep4(&v4, 192, 0, 2, 33, 443);
	TCT_EQ_INT(tc_nat64_wrap(&wrapped, &v4), TC_OK);
	TCT_EQ_INT(wrapped.ip_len, 16);
	TCT_EQ_INT(wrapped.port, 443);

	uint8_t want[16];
	TCT_EQ_INT(inet_pton(AF_INET6, "64:ff9b::192.0.2.33", want), 1);
	TCT_EQ_MEM(wrapped.ip, want, 16);

	/* And the hex spelling of the same thing, which is what a packet
	 * capture would show. */
	uint8_t hexform[16];
	TCT_EQ_INT(inet_pton(AF_INET6, "64:ff9b::c000:221", hexform), 1);
	TCT_EQ_MEM(wrapped.ip, hexform, 16);

	char s[64];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &wrapped), TC_OK);
	TCT_EQ_STR(s, "[64:ff9b::c000:221]:443");
}

static void test_agrees_with_the_resolver(void)
{
	TCT_CASE("every IPv4 address embeds where the system says it does");
	/* Breadth, from an implementation that is not ours. A prefix written
	 * one byte out, or four bytes copied to the wrong offset, passes a
	 * round-trip test of our own code and fails here. */
	static const uint8_t kSamples[][4] = {
		{ 0, 0, 0, 0 },
		{ 0, 0, 0, 1 },
		{ 1, 2, 3, 4 },
		{ 10, 0, 0, 1 },
		{ 100, 64, 0, 1 },
		{ 127, 0, 0, 1 },
		{ 169, 254, 1, 1 },
		{ 172, 16, 254, 3 },
		{ 192, 0, 2, 33 },
		{ 192, 168, 1, 10 },
		{ 198, 51, 100, 7 },
		{ 203, 0, 113, 255 },
		{ 224, 0, 0, 251 },
		{ 255, 255, 255, 255 },
		{ 0x64, 0xff, 0x9b, 0x00 }, /* bytes that look like the prefix */
		{ 0xff, 0x00, 0xff, 0x00 },
	};

	for (size_t i = 0; i < sizeof kSamples / sizeof kSamples[0]; i++) {
		tc_endpoint v4, wrapped, back;
		ep4(&v4, kSamples[i][0], kSamples[i][1], kSamples[i][2],
		    kSamples[i][3], 41641);

		char text[64];
		snprintf(text, sizeof text, "64:ff9b::%u.%u.%u.%u", kSamples[i][0],
		         kSamples[i][1], kSamples[i][2], kSamples[i][3]);
		uint8_t want[16];
		if (inet_pton(AF_INET6, text, want) != 1) {
			TCT_FAILF("the resolver would not parse %s", text);
			continue;
		}

		TCT_EQ_INT(tc_nat64_wrap(&wrapped, &v4), TC_OK);
		TCT_EQ_MEM(wrapped.ip, want, 16);
		TCT_TRUE(tc_nat64_is(wrapped.ip));

		TCT_CASE("and comes back unchanged");
		TCT_EQ_INT(tc_nat64_unwrap(&back, &wrapped), TC_OK);
		TCT_TRUE(tc_endpoint_equal(&v4, &back));
	}
}

static void test_not_the_v4mapped_prefix(void)
{
	TCT_CASE("the translation prefix is not the v4-mapped one");
	/* Two prefixes with two meanings, and confusing them is the obvious
	 * mistake. ::ffff:0:0/96 already means "this IPv4 address written as
	 * sixteen bytes", and tc_endpoint_from16 unmaps it on sight -- so an
	 * address translated into it would silently come back out as IPv4 at a
	 * layer that knew nothing about translation. RFC 4291 also forbids
	 * v4-mapped addresses on the wire. */
	tc_endpoint v4, wrapped;
	ep4(&v4, 203, 0, 113, 7, 443);
	TCT_EQ_INT(tc_nat64_wrap(&wrapped, &v4), TC_OK);

	uint8_t mapped[16];
	TCT_EQ_INT(inet_pton(AF_INET6, "::ffff:203.0.113.7", mapped), 1);
	TCT_TRUE(memcmp(wrapped.ip, mapped, 16) != 0);

	/* A wrapped address must survive the wire encoding as IPv6. If it were
	 * in the v4-mapped range it would not. */
	uint8_t wire[16];
	tc_endpoint_to16(&wrapped, wire);
	tc_endpoint back;
	tc_endpoint_from16(&back, wire, wrapped.port);
	TCT_EQ_INT(back.ip_len, 16);
	TCT_TRUE(tc_endpoint_equal(&back, &wrapped));

	TCT_CASE("and a v4-mapped address is not treated as translated");
	tc_endpoint m;
	memset(&m, 0, sizeof m);
	memcpy(m.ip, mapped, 16);
	m.ip_len = 16;
	m.port = 443;
	TCT_TRUE(!tc_nat64_is(m.ip));
	tc_endpoint out;
	TCT_EQ_INT(tc_nat64_unwrap(&out, &m), TC_ERR_INVAL);
}

static void test_refuses(void)
{
	TCT_CASE("an ordinary IPv6 address is not inside the prefix");
	/* Unwrapping one would invent an IPv4 destination out of the last four
	 * bytes of somebody's address. */
	static const char *kOutside[] = {
		"2001:db8::1",
		"fd7a:115c:a1e0::1",
		"::1",
		"::",
		"64:ff9c::1",       /* one bit different in the prefix */
		"64:ff9a::1",       /* and the other way */
		"0064:ff9b:0:1::1", /* prefix bytes right, byte 8 onwards wrong */
		"65:ff9b::1",
		"ff02::1",
	};
	for (size_t i = 0; i < sizeof kOutside / sizeof kOutside[0]; i++) {
		tc_endpoint ep, out;
		memset(&ep, 0, sizeof ep);
		if (inet_pton(AF_INET6, kOutside[i], ep.ip) != 1) {
			TCT_FAILF("could not parse %s", kOutside[i]);
			continue;
		}
		ep.ip_len = 16;
		ep.port = 443;
		if (tc_nat64_is(ep.ip))
			TCT_FAILF("%s was taken for a translated address", kOutside[i]);
		TCT_EQ_INT(tc_nat64_unwrap(&out, &ep), TC_ERR_INVAL);
	}

	TCT_CASE("64:ff9b::/96 with anything in the low 32 bits is inside it");
	/* Including all zeros, which is 64:ff9b:: itself and translates to
	 * 0.0.0.0. Whether that destination is worth dialling is the caller's
	 * question; whether it is in the prefix is this one. */
	tc_endpoint ep, out;
	memset(&ep, 0, sizeof ep);
	TCT_EQ_INT(inet_pton(AF_INET6, "64:ff9b::", ep.ip), 1);
	ep.ip_len = 16;
	TCT_TRUE(tc_nat64_is(ep.ip));
	TCT_EQ_INT(tc_nat64_unwrap(&out, &ep), TC_OK);
	TCT_EQ_INT(out.ip_len, 4);
	TCT_EQ_INT(out.ip[0], 0);

	TCT_CASE("wrapping something that is not IPv4 is refused");
	/* An IPv6 destination needs no translation, and wrapping one would
	 * produce a completely different address rather than an equivalent. */
	memset(&ep, 0, sizeof ep);
	TCT_EQ_INT(inet_pton(AF_INET6, "2001:db8::1", ep.ip), 1);
	ep.ip_len = 16;
	TCT_EQ_INT(tc_nat64_wrap(&out, &ep), TC_ERR_INVAL);

	memset(&ep, 0, sizeof ep);
	ep.ip_len = 0; /* unset */
	TCT_EQ_INT(tc_nat64_wrap(&out, &ep), TC_ERR_INVAL);

	TCT_CASE("unwrapping something that is not sixteen bytes is refused");
	tc_endpoint v4;
	ep4(&v4, 203, 0, 113, 7, 443);
	TCT_EQ_INT(tc_nat64_unwrap(&out, &v4), TC_ERR_INVAL);

	TCT_CASE("null arguments");
	TCT_TRUE(!tc_nat64_is(NULL));
	TCT_EQ_INT(tc_nat64_wrap(NULL, &v4), TC_ERR_INVAL);
	TCT_EQ_INT(tc_nat64_wrap(&out, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_nat64_unwrap(NULL, &ep), TC_ERR_INVAL);
	TCT_EQ_INT(tc_nat64_unwrap(&out, NULL), TC_ERR_INVAL);
}

static void test_ports_are_untouched(void)
{
	TCT_CASE("translation moves the address and leaves the port alone");
	/* A translator that helpfully rewrote ports would be a different thing
	 * entirely, and the bug would look like a service answering on the
	 * wrong one. */
	static const uint16_t kPorts[] = { 1, 53, 443, 3306, 41641, 65535 };
	for (size_t i = 0; i < sizeof kPorts / sizeof kPorts[0]; i++) {
		tc_endpoint v4, wrapped, back;
		ep4(&v4, 192, 168, 1, 10, kPorts[i]);
		TCT_EQ_INT(tc_nat64_wrap(&wrapped, &v4), TC_OK);
		TCT_EQ_INT(wrapped.port, kPorts[i]);
		TCT_EQ_INT(tc_nat64_unwrap(&back, &wrapped), TC_OK);
		TCT_EQ_INT(back.port, kPorts[i]);
	}
}

int main(void)
{
	test_rfc6052_example();
	test_agrees_with_the_resolver();
	test_not_the_v4mapped_prefix();
	test_refuses();
	test_ports_are_untouched();
	return tct_report("nat64");
}
