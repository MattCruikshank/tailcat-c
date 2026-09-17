/* SPDX-License-Identifier: BSD-3-Clause
 *
 * SOCKS5 destination classification and the UDP relay header.
 *
 * The header is the dangerous part. It carries a destination in front of the
 * payload, so a parser one byte out does not fail -- it sends the payload
 * somewhere else, and both ends look like they are working. There is no
 * checksum and no acknowledgement to notice with.
 */

#include "tc/socks.h"

#include "tctest.h"

#include <arpa/inet.h>

static void test_classify(void)
{
	tc_socks_target t;

	TCT_CASE("an IPv4 destination is somewhere beyond the server");
	static const uint8_t v4[4] = { 203, 0, 113, 7 };
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV4, v4, 4, 443), TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_ADDRESS);
	TCT_EQ_INT(t.port, 443);
	TCT_EQ_INT(t.dst.ip_len, 4);
	char s[80];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &t.dst), TC_OK);
	TCT_EQ_STR(s, "203.0.113.7:443");

	TCT_CASE("and so is an IPv6 one");
	uint8_t v6[16];
	TCT_EQ_INT(inet_pton(AF_INET6, "2001:db8::1", v6), 1);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV6, v6, 16, 443), TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_ADDRESS);
	TCT_EQ_INT(t.dst.ip_len, 16);
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &t.dst), TC_OK);
	TCT_EQ_STR(s, "[2001:db8::1]:443");

	TCT_CASE("a v4-mapped IPv6 literal is the IPv4 address it stands for");
	/* Otherwise the same destination has two spellings, and a client that
	 * happens to use the mapped form would open a second flow to the same
	 * place. */
	TCT_EQ_INT(inet_pton(AF_INET6, "::ffff:203.0.113.7", v6), 1);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV6, v6, 16, 443), TC_OK);
	TCT_EQ_INT(t.dst.ip_len, 4);
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &t.dst), TC_OK);
	TCT_EQ_STR(s, "203.0.113.7:443");

	TCT_CASE("upstream's hostname means the server itself");
	/* A SOCKS client configured for upstream should work against us, so the
	 * spelling has to be theirs rather than one of our own choosing. */
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME,
	                             (const uint8_t *)"server.tailcat", 14, 22),
	           TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_SERVER);
	TCT_EQ_INT(t.port, 22);
	TCT_EQ_INT(t.dst.ip_len, 0);

	TCT_CASE("an empty host does too");
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME, NULL, 0, 22), TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_SERVER);

	TCT_CASE("any other name is reported as needing DNS, not refused");
	/* Resolving it here resolves it on the client's machine rather than the
	 * server's, which is a decision with consequences. The caller makes it;
	 * this function will not make it silently. */
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME,
	                             (const uint8_t *)"example.com", 11, 443),
	           TC_ERR_UNSUPPORTED);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME,
	                             (const uint8_t *)"server.tailcat.", 15, 443),
	           TC_ERR_UNSUPPORTED);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME,
	                             (const uint8_t *)"server.tailca", 13, 443),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("port zero is refused, because it is not a port");
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV4, v4, 4, 0),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_NAME,
	                             (const uint8_t *)"server.tailcat", 14, 0),
	           TC_ERR_INVAL);

	TCT_CASE("a wrong address length, and an unknown address type");
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV4, v4, 3, 443),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV6, v6, 4, 443),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_classify(&t, 0x02, v4, 4, 443), TC_ERR_UNSUPPORTED);
	TCT_EQ_INT(tc_socks_classify(&t, 0xff, v4, 4, 443), TC_ERR_UNSUPPORTED);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_socks_classify(NULL, TC_SOCKS_ATYP_IPV4, v4, 4, 443),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_classify(&t, TC_SOCKS_ATYP_IPV4, NULL, 4, 443),
	           TC_ERR_INVAL);
}

/* ---- the UDP relay header ----------------------------------------------- */

static void test_udp_parse(void)
{
	tc_socks_target t;
	const uint8_t *data;
	size_t dlen;

	TCT_CASE("a datagram for an IPv4 destination");
	/* RSV RSV FRAG ATYP  addr          port     payload */
	static const uint8_t v4[] = { 0,   0,   0,    0x01, 203, 0,
		                          113, 7,   0x01, 0xbb, 'h', 'i' };
	TCT_EQ_INT(tc_socks_udp_parse(v4, sizeof v4, &t, &data, &dlen), TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_ADDRESS);
	TCT_EQ_INT(t.dst.port, 443);
	char s[80];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &t.dst), TC_OK);
	TCT_EQ_STR(s, "203.0.113.7:443");
	TCT_EQ_INT((int)dlen, 2);
	TCT_TRUE(memcmp(data, "hi", 2) == 0);

	TCT_CASE("the payload pointer is inside the packet we were given");
	/* It is documented as borrowed, so a caller copying it after the buffer
	 * is reused would be reading somebody else's datagram. */
	TCT_TRUE(data >= v4 && data < v4 + sizeof v4);

	TCT_CASE("a datagram for an IPv6 destination");
	uint8_t v6[4 + 16 + 2 + 3];
	memset(v6, 0, sizeof v6);
	v6[3] = TC_SOCKS_ATYP_IPV6;
	TCT_EQ_INT(inet_pton(AF_INET6, "2001:db8::1", v6 + 4), 1);
	v6[20] = 0x01;
	v6[21] = 0xbb;
	memcpy(v6 + 22, "abc", 3);
	TCT_EQ_INT(tc_socks_udp_parse(v6, sizeof v6, &t, &data, &dlen), TC_OK);
	TCT_EQ_INT(t.dst.ip_len, 16);
	TCT_EQ_INT((int)dlen, 3);
	TCT_TRUE(memcmp(data, "abc", 3) == 0);

	TCT_CASE("a datagram for the server itself");
	static const uint8_t srv[] = { 0,   0,   0,   0x03, 14,  's', 'e', 'r',
		                           'v', 'e', 'r', '.',  't', 'a', 'i', 'l',
		                           'c', 'a', 't', 0x00, 0x35 };
	TCT_EQ_INT(tc_socks_udp_parse(srv, sizeof srv, &t, &data, &dlen), TC_OK);
	TCT_EQ_INT((int)t.kind, TC_SOCKS_TO_SERVER);
	TCT_EQ_INT(t.port, 53);
	TCT_EQ_INT((int)dlen, 0); /* a zero-length datagram is legal */

	TCT_CASE("a fragmented datagram is dropped, not reassembled");
	/* RFC 1928 permits dropping these, and every implementation does.
	 * Reassembly would be a buffer to overflow for a feature with no
	 * users. */
	uint8_t frag[sizeof v4];
	memcpy(frag, v4, sizeof v4);
	frag[2] = 1;
	TCT_EQ_INT(tc_socks_udp_parse(frag, sizeof frag, &t, &data, &dlen),
	           TC_ERR_UNSUPPORTED);
	frag[2] = 0x80; /* the "last fragment" bit */
	TCT_EQ_INT(tc_socks_udp_parse(frag, sizeof frag, &t, &data, &dlen),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("the reserved bytes must be zero");
	uint8_t rsv[sizeof v4];
	memcpy(rsv, v4, sizeof v4);
	rsv[0] = 1;
	TCT_EQ_INT(tc_socks_udp_parse(rsv, sizeof rsv, &t, &data, &dlen),
	           TC_ERR_INVAL);
	memcpy(rsv, v4, sizeof v4);
	rsv[1] = 1;
	TCT_EQ_INT(tc_socks_udp_parse(rsv, sizeof rsv, &t, &data, &dlen),
	           TC_ERR_INVAL);

	TCT_CASE("every prefix of a real datagram is refused");
	/* The length arithmetic is where a header parser gets talked into
	 * reading past its buffer, and the name form makes the length
	 * attacker-controlled. */
	for (size_t k = 0; k < sizeof srv; k++) {
		if (tc_socks_udp_parse(srv, k, &t, &data, &dlen) == TC_OK)
			TCT_FAILF("accepted a %zu byte datagram", k);
		tct_checks++;
	}
	/* And the whole thing is accepted, so the loop above is measuring the
	 * boundary rather than a parser that refuses everything. */
	TCT_EQ_INT(tc_socks_udp_parse(srv, sizeof srv, &t, &data, &dlen), TC_OK);
	/* Only up to the end of the header: past that a short read is a short
	 * *payload*, which is legal -- a zero-length datagram is a real thing to
	 * send. Asserting otherwise would be asserting a bug. */
	const size_t v6_hdr = 4 + 16 + 2;
	for (size_t k = 0; k < v6_hdr; k++) {
		if (tc_socks_udp_parse(v6, k, &t, &data, &dlen) == TC_OK)
			TCT_FAILF("accepted a %zu byte IPv6 datagram", k);
		tct_checks++;
	}
	for (size_t k = v6_hdr; k <= sizeof v6; k++) {
		if (tc_socks_udp_parse(v6, k, &t, &data, &dlen) != TC_OK)
			TCT_FAILF("refused a %zu byte IPv6 datagram", k);
		TCT_EQ_INT((int)dlen, (int)(k - v6_hdr));
		tct_checks++;
	}

	TCT_CASE("a name length that runs past the datagram");
	/* One byte the client controls, claiming more than arrived. */
	uint8_t liar[] = { 0, 0, 0, 0x03, 200, 'a', 'b', 0x00, 0x35 };
	TCT_EQ_INT(tc_socks_udp_parse(liar, sizeof liar, &t, &data, &dlen),
	           TC_ERR_INVAL);
	liar[4] = 255;
	TCT_EQ_INT(tc_socks_udp_parse(liar, sizeof liar, &t, &data, &dlen),
	           TC_ERR_INVAL);

	TCT_CASE("an unknown address type");
	uint8_t bad[sizeof v4];
	memcpy(bad, v4, sizeof v4);
	bad[3] = 0x02;
	TCT_EQ_INT(tc_socks_udp_parse(bad, sizeof bad, &t, &data, &dlen),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_socks_udp_parse(NULL, 10, &t, &data, &dlen), TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_parse(v4, sizeof v4, NULL, &data, &dlen),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_parse(v4, sizeof v4, &t, NULL, &dlen),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_parse(v4, sizeof v4, &t, &data, NULL),
	           TC_ERR_INVAL);
}

static void test_udp_build(void)
{
	uint8_t out[512];
	size_t n = 0;
	tc_endpoint src;

	TCT_CASE("a reply names where it came from");
	/* A client that sent to several destinations on one association has no
	 * other way to tell the answers apart. */
	memset(&src, 0, sizeof src);
	src.ip[0] = 203;
	src.ip[2] = 113;
	src.ip[3] = 7;
	src.ip_len = 4;
	src.port = 443;
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, &src, "pong", 4),
	           TC_OK);
	TCT_EQ_INT((int)n, 4 + 4 + 2 + 4);
	TCT_EQ_INT(out[0], 0);
	TCT_EQ_INT(out[1], 0);
	TCT_EQ_INT(out[2], 0);
	TCT_EQ_INT(out[3], TC_SOCKS_ATYP_IPV4);
	TCT_EQ_INT(out[4], 203);
	TCT_EQ_INT(out[8], 0x01);
	TCT_EQ_INT(out[9], 0xbb);
	TCT_TRUE(memcmp(out + 10, "pong", 4) == 0);

	TCT_CASE("and it parses back as what was put in");
	/* Build and parse are the two halves a real association runs through, so
	 * a disagreement between them is a bug no single-sided test would see. */
	tc_socks_target t;
	const uint8_t *data;
	size_t dlen;
	TCT_EQ_INT(tc_socks_udp_parse(out, n, &t, &data, &dlen), TC_OK);
	TCT_TRUE(tc_endpoint_equal(&t.dst, &src));
	TCT_EQ_INT((int)dlen, 4);
	TCT_TRUE(memcmp(data, "pong", 4) == 0);

	TCT_CASE("an IPv6 source round trips too");
	memset(&src, 0, sizeof src);
	TCT_EQ_INT(inet_pton(AF_INET6, "2001:db8::1", src.ip), 1);
	src.ip_len = 16;
	src.port = 53;
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, &src, "x", 1), TC_OK);
	TCT_EQ_INT(out[3], TC_SOCKS_ATYP_IPV6);
	TCT_EQ_INT(tc_socks_udp_parse(out, n, &t, &data, &dlen), TC_OK);
	TCT_TRUE(tc_endpoint_equal(&t.dst, &src));

	TCT_CASE("a zero-length payload is legal");
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, &src, NULL, 0), TC_OK);
	TCT_EQ_INT((int)n, 4 + 16 + 2);
	TCT_EQ_INT(tc_socks_udp_parse(out, n, &t, &data, &dlen), TC_OK);
	TCT_EQ_INT((int)dlen, 0);

	TCT_CASE("a buffer too small is an error, not a truncated datagram");
	/* Truncating would send a header with someone else's payload length,
	 * and UDP gives the receiver nothing to notice with. */
	for (size_t cap = 0; cap < 4 + 16 + 2 + 1; cap++) {
		if (tc_socks_udp_build(out, cap, &n, &src, "x", 1) == TC_OK)
			TCT_FAILF("claimed success with %zu bytes", cap);
		tct_checks++;
	}

	TCT_CASE("an unset source is refused");
	/* There is no header that means "from nowhere", and inventing one would
	 * hand the client an address it would then reply to. */
	memset(&src, 0, sizeof src);
	src.port = 53;
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, &src, "x", 1),
	           TC_ERR_INVAL);

	TCT_CASE("null arguments");
	src.ip_len = 4;
	TCT_EQ_INT(tc_socks_udp_build(NULL, sizeof out, &n, &src, "x", 1),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, NULL, &src, "x", 1),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, NULL, "x", 1),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_socks_udp_build(out, sizeof out, &n, &src, NULL, 1),
	           TC_ERR_INVAL);
}

int main(void)
{
	test_classify();
	test_udp_parse();
	test_udp_build();
	return tct_report("socks");
}
