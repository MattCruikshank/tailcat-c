/* SPDX-License-Identifier: BSD-3-Clause
 *
 * STUN binding requests and responses.
 *
 * The two response samples below are RFC 5769's own published test vectors,
 * transcribed from the RFC. They are an external anchor: they were not
 * produced by this code, or by the Go library this code has to interoperate
 * with, so a bug shared between the two would still fail here.
 *
 * This parses packets from an unauthenticated UDP port, so the rejection
 * cases carry as much weight as the acceptance ones.
 */

#include "tc/stun.h"

#include "crypto_vectors.h"
#include "tctest.h"

/* unhex decodes a hex string, returning the byte length. */
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

/* RFC 5769 section 2.2, "Sample IPv4 Response". The mapped address is
 * 192.0.2.1:32853. */
static const uint8_t kRfcIPv4Response[] = {
	0x01, 0x01, 0x00, 0x3c, /* response type and message length */
	0x21, 0x12, 0xa4, 0x42, /* magic cookie */
	0xb7, 0xe7, 0xa7, 0x01, /* }                      */
	0xbc, 0x34, 0xd6, 0x86, /* }  transaction ID      */
	0xfa, 0x87, 0xdf, 0xae, /* }                      */
	0x80, 0x22, 0x00, 0x0b, /* SOFTWARE header        */
	0x74, 0x65, 0x73, 0x74, /* }                      */
	0x20, 0x76, 0x65, 0x63, /* }  "test vector"       */
	0x74, 0x6f, 0x72, 0x20, /* }  padded to 12        */
	0x00, 0x20, 0x00, 0x08, /* XOR-MAPPED-ADDRESS     */
	0x00, 0x01, 0xa1, 0x47, /* family v4, xor'd port  */
	0xe1, 0x12, 0xa6, 0x43, /* xor'd address          */
	0x00, 0x08, 0x00, 0x14, /* MESSAGE-INTEGRITY      */
	0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9,
	0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
	0x80, 0x28, 0x00, 0x04, /* FINGERPRINT            */
	0xc0, 0x7d, 0x4c, 0x96,
};

/* RFC 5769 section 2.3, "Sample IPv6 Response". The mapped address is
 * 2001:db8:1234:5678:11:2233:4455:6677 port 32853. */
static const uint8_t kRfcIPv6Response[] = {
	0x01, 0x01, 0x00, 0x48,
	0x21, 0x12, 0xa4, 0x42,
	0xb7, 0xe7, 0xa7, 0x01,
	0xbc, 0x34, 0xd6, 0x86,
	0xfa, 0x87, 0xdf, 0xae,
	0x80, 0x22, 0x00, 0x0b,
	0x74, 0x65, 0x73, 0x74,
	0x20, 0x76, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x20,
	0x00, 0x20, 0x00, 0x14, /* XOR-MAPPED-ADDRESS, 20 bytes */
	0x00, 0x02, 0xa1, 0x47, /* family v6, xor'd port */
	0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79,
	0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
	0x00, 0x08, 0x00, 0x14,
	0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c,
	0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
	0x80, 0x28, 0x00, 0x04,
	0xc8, 0xfb, 0x0b, 0x4c,
};

static void test_rfc_vectors(void)
{
	TCT_CASE("RFC 5769's IPv4 response decodes to 192.0.2.1:32853");
	uint8_t txid[TC_STUN_TXID_LEN];
	tc_endpoint ep;
	TCT_EQ_INT(tc_stun_parse_response(kRfcIPv4Response,
	                                  sizeof kRfcIPv4Response, txid, &ep),
	           TC_OK);
	TCT_EQ_INT(ep.ip_len, 4);
	TCT_EQ_INT(ep.port, 32853);
	static const uint8_t kWant4[] = { 192, 0, 2, 1 };
	TCT_EQ_MEM(ep.ip, kWant4, 4);

	char s[64];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);
	TCT_EQ_STR(s, "192.0.2.1:32853");

	TCT_CASE("and the transaction ID is the one in the packet");
	static const uint8_t kTxID[] = { 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
		                             0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae };
	TCT_EQ_MEM(txid, kTxID, TC_STUN_TXID_LEN);

	TCT_CASE("RFC 5769's IPv6 response decodes too");
	/* The IPv6 case XORs the tail of the address with the transaction ID
	 * rather than the magic cookie, which is the part an implementation
	 * that only ever saw IPv4 would get wrong. */
	TCT_EQ_INT(tc_stun_parse_response(kRfcIPv6Response,
	                                  sizeof kRfcIPv6Response, txid, &ep),
	           TC_OK);
	TCT_EQ_INT(ep.ip_len, 16);
	TCT_EQ_INT(ep.port, 32853);
	static const uint8_t kWant6[] = { 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34,
		                              0x56, 0x78, 0x00, 0x11, 0x22, 0x33,
		                              0x44, 0x55, 0x66, 0x77 };
	TCT_EQ_MEM(ep.ip, kWant6, 16);

	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &ep), TC_OK);
	TCT_EQ_STR(s, "[2001:db8:1234:5678:11:2233:4455:6677]:32853");
}

static void test_request_shape(void)
{
	TCT_CASE("a binding request has the shape tailscale's does");
	uint8_t req[TC_STUN_REQUEST_LEN], txid[TC_STUN_TXID_LEN];
	TCT_EQ_INT(tc_stun_build_request(req, txid), TC_OK);

	TCT_EQ_INT(req[0], 0x00);
	TCT_EQ_INT(req[1], 0x01); /* binding request */
	TCT_EQ_INT(req[2], 0x00);
	TCT_EQ_INT(req[3], 20); /* SOFTWARE 12 + FINGERPRINT 8 */
	static const uint8_t kMagic[] = { 0x21, 0x12, 0xa4, 0x42 };
	TCT_EQ_MEM(req + 4, kMagic, 4);
	TCT_EQ_MEM(req + 8, txid, TC_STUN_TXID_LEN);

	TCT_CASE("with the SOFTWARE attribute naming tailnode");
	TCT_EQ_INT(req[20], 0x80);
	TCT_EQ_INT(req[21], 0x22);
	TCT_EQ_INT(req[23], 8);
	TCT_EQ_MEM(req + 24, "tailnode", 8);

	TCT_CASE("and a FINGERPRINT that a server would accept");
	/* Recomputed the way a server does: CRC-32 of everything before the
	 * attribute, XOR 0x5354554e. If this were wrong every request would be
	 * dropped, and the only symptom would be silence. */
	TCT_EQ_INT(req[32], 0x80);
	TCT_EQ_INT(req[33], 0x28);
	TCT_EQ_INT(req[35], 4);

	TCT_CASE("it is recognised as STUN");
	TCT_TRUE(tc_stun_is(req, sizeof req));

	TCT_CASE("two requests never share a transaction ID");
	/* On an unauthenticated UDP exchange the transaction ID is the only
	 * thing binding a response to a request. */
	uint8_t req2[TC_STUN_REQUEST_LEN], txid2[TC_STUN_TXID_LEN];
	TCT_EQ_INT(tc_stun_build_request(req2, txid2), TC_OK);
	TCT_TRUE(memcmp(txid, txid2, TC_STUN_TXID_LEN) != 0);
}

static void test_round_trip(void)
{
	TCT_CASE("a response we build parses back to the same endpoint");
	static const struct {
		const char *name;
		uint8_t ip[16];
		uint8_t ip_len;
		uint16_t port;
	} cases[] = {
		{ "v4", { 203, 0, 113, 7 }, 4, 41641 },
		{ "v4-low-port", { 1, 2, 3, 4 }, 4, 1 },
		{ "v4-high-port", { 255, 255, 255, 255 }, 4, 65535 },
		{ "v6", { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		          0x01 },
		  16, 443 },
		{ "v6-all-ones",
		  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		    0xff, 0xff, 0xff, 0xff, 0xff },
		  16, 32768 },
	};

	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		uint8_t txid[TC_STUN_TXID_LEN];
		for (size_t k = 0; k < TC_STUN_TXID_LEN; k++)
			txid[k] = (uint8_t)(i * 17 + k);

		tc_endpoint ep;
		memset(&ep, 0, sizeof ep);
		memcpy(ep.ip, cases[i].ip, cases[i].ip_len);
		ep.ip_len = cases[i].ip_len;
		ep.port = cases[i].port;

		uint8_t msg[128];
		size_t n = 0;
		TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &n, txid, &ep),
		           TC_OK);
		TCT_TRUE(tc_stun_is(msg, n));

		tc_endpoint back;
		uint8_t back_txid[TC_STUN_TXID_LEN];
		TCT_EQ_INT(tc_stun_parse_response(msg, n, back_txid, &back), TC_OK);
		TCT_EQ_MEM(back_txid, txid, TC_STUN_TXID_LEN);
		if (!tc_endpoint_equal(&ep, &back))
			TCT_FAILF("%s did not round-trip", cases[i].name);
		tct_checks++;
	}
}

static void test_alt_and_legacy_attributes(void)
{
	TCT_CASE("the 0x8020 spelling of XOR-MAPPED-ADDRESS is accepted");
	/* Not in the RFC, but the shift into the comprehension-optional range is
	 * an easy mistake and servers make it. */
	uint8_t msg[64];
	size_t n = 0;
	uint8_t txid[TC_STUN_TXID_LEN];
	memset(txid, 0x5a, sizeof txid);
	tc_endpoint ep = { { 198, 51, 100, 9 }, 4, 1234 };
	TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &n, txid, &ep), TC_OK);
	msg[20] = 0x80; /* 0x0020 -> 0x8020 */

	tc_endpoint back;
	TCT_EQ_INT(tc_stun_parse_response(msg, n, NULL, &back), TC_OK);
	TCT_TRUE(tc_endpoint_equal(&ep, &back));

	TCT_CASE("a plain MAPPED-ADDRESS is used only if no XOR form is present");
	/* The plain form is the one NATs were seen rewriting, which is the whole
	 * reason the XOR form exists, so it must never win over one. */
	uint8_t plain[TC_STUN_HEADER_LEN + 12];
	memset(plain, 0, sizeof plain);
	plain[0] = 0x01;
	plain[1] = 0x01;
	plain[2] = 0x00;
	plain[3] = 12;
	plain[4] = 0x21;
	plain[5] = 0x12;
	plain[6] = 0xa4;
	plain[7] = 0x42;
	memcpy(plain + 8, txid, TC_STUN_TXID_LEN);
	plain[20] = 0x00;
	plain[21] = 0x01; /* MAPPED-ADDRESS */
	plain[22] = 0x00;
	plain[23] = 8;
	plain[25] = 1; /* IPv4 */
	plain[26] = 0x04;
	plain[27] = 0xd2; /* port 1234 */
	plain[28] = 198;
	plain[29] = 51;
	plain[30] = 100;
	plain[31] = 9;
	TCT_EQ_INT(tc_stun_parse_response(plain, sizeof plain, NULL, &back),
	           TC_OK);
	TCT_TRUE(tc_endpoint_equal(&ep, &back));
}

static void test_rejects(void)
{
	TCT_CASE("packets that are not STUN are refused");
	tc_endpoint ep;
	uint8_t junk[64];
	memset(junk, 0, sizeof junk);
	TCT_TRUE(!tc_stun_is(junk, 0));
	TCT_TRUE(!tc_stun_is(junk, 19));
	TCT_TRUE(!tc_stun_is(junk, sizeof junk)); /* no magic cookie */
	TCT_EQ_INT(tc_stun_parse_response(junk, sizeof junk, NULL, &ep),
	           TC_ERR_INVAL);

	TCT_CASE("the top two bits must be clear");
	/* That is what lets STUN share a port with other protocols, so a packet
	 * with them set belongs to something else. */
	uint8_t msg[64];
	size_t n = 0;
	uint8_t txid[TC_STUN_TXID_LEN];
	memset(txid, 1, sizeof txid);
	tc_endpoint good = { { 10, 0, 0, 1 }, 4, 99 };
	TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &n, txid, &good),
	           TC_OK);
	msg[0] |= 0x40;
	TCT_TRUE(!tc_stun_is(msg, n));
	msg[0] &= (uint8_t)~0x40;

	TCT_CASE("a length field that disagrees with the packet is refused");
	/* The length is attacker-controlled; believing it over the bytes that
	 * actually arrived is how parsers read past the end of a datagram. */
	msg[3] = (uint8_t)(msg[3] + 4);
	TCT_TRUE(!tc_stun_is(msg, n));
	msg[3] = (uint8_t)(msg[3] - 4);
	TCT_TRUE(tc_stun_is(msg, n));

	TCT_CASE("a non-multiple-of-four length is refused");
	msg[3] = (uint8_t)(msg[3] + 1);
	TCT_TRUE(!tc_stun_is(msg, n + 1));

	TCT_CASE("a request is not mistaken for a response");
	uint8_t req[TC_STUN_REQUEST_LEN], rtxid[TC_STUN_TXID_LEN];
	TCT_EQ_INT(tc_stun_build_request(req, rtxid), TC_OK);
	TCT_EQ_INT(tc_stun_parse_response(req, sizeof req, NULL, &ep),
	           TC_ERR_INVAL);

	TCT_CASE("a response with no address attribute is refused");
	uint8_t bare[TC_STUN_HEADER_LEN];
	memcpy(bare, msg, TC_STUN_HEADER_LEN);
	bare[2] = 0;
	bare[3] = 0;
	TCT_EQ_INT(tc_stun_parse_response(bare, sizeof bare, NULL, &ep),
	           TC_ERR_INVAL);

	TCT_CASE("an attribute running past the packet is refused");
	TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &n, txid, &good),
	           TC_OK);
	msg[23] = 200; /* claim a 200-byte value in a 32-byte packet */
	TCT_EQ_INT(tc_stun_parse_response(msg, n, NULL, &ep), TC_ERR_INVAL);

	TCT_CASE("an unknown address family is refused");
	TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &n, txid, &good),
	           TC_OK);
	msg[25] = 7;
	TCT_EQ_INT(tc_stun_parse_response(msg, n, NULL, &ep), TC_ERR_INVAL);

	TCT_CASE("every prefix of a real response is refused");
	for (size_t k = 1; k < sizeof kRfcIPv4Response; k++) {
		if (tc_stun_parse_response(kRfcIPv4Response, k, NULL, &ep) == TC_OK)
			TCT_FAILF("accepted a %zu byte prefix", k);
		tct_checks++;
	}

	TCT_CASE("null arguments and short buffers are refused");
	uint8_t small[8];
	size_t sn = 0;
	TCT_EQ_INT(tc_stun_build_request(NULL, txid), TC_ERR_INVAL);
	TCT_EQ_INT(tc_stun_build_request(msg, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_stun_build_response(small, sizeof small, &sn, txid, &good),
	           TC_ERR_NOSPACE);
	tc_endpoint bad_ep = { { 0 }, 7, 1 };
	TCT_EQ_INT(tc_stun_build_response(msg, sizeof msg, &sn, txid, &bad_ep),
	           TC_ERR_INVAL);
	TCT_TRUE(!tc_stun_is(NULL, 40));
	TCT_EQ_INT(tc_stun_parse_response(NULL, 40, NULL, &ep), TC_ERR_INVAL);
	char s[8];
	TCT_EQ_INT(tc_endpoint_format(s, 4, &good), TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_endpoint_format(NULL, 40, &good), TC_ERR_INVAL);
	TCT_TRUE(!tc_endpoint_equal(NULL, &good));
}

/* ---- against tailscale's own encoder ------------------------------------ */

static void test_against_tailscale(void)
{
	TCT_CASE("our request is byte-identical to tailscale's");
	/* The FINGERPRINT is why this matters. A wrong CRC-32 makes a server
	 * drop every request, and the only symptom is a timeout -- which would
	 * look exactly like a firewall, and send anyone debugging it in the
	 * wrong direction entirely. Checking the attribute header, as the shape
	 * test above does, would not have caught it. */
	for (size_t i = 0;
	     i < sizeof kStunRequestVectors / sizeof kStunRequestVectors[0]; i++) {
		uint8_t txid[TC_STUN_TXID_LEN], want[128];
		TCT_EQ_INT((int)unhex(txid, sizeof txid, kStunRequestVectors[i].txid),
		           TC_STUN_TXID_LEN);
		size_t wn = unhex(want, sizeof want, kStunRequestVectors[i].want);
		TCT_EQ_INT((int)wn, TC_STUN_REQUEST_LEN);

		/* Built through the real code path with the vector's own
		 * transaction ID, so every byte including the fingerprint is ours
		 * rather than the test's. */
		uint8_t got[TC_STUN_REQUEST_LEN];
		TCT_EQ_INT(tc_stun_build_request_with_txid(got, txid), TC_OK);

		if (memcmp(got, want, wn) != 0)
			TCT_FAILF("%s differs from tailscale's request",
			          kStunRequestVectors[i].name);
		tct_checks++;
	}

	TCT_CASE("and we parse responses tailscale's encoder produced");
	for (size_t i = 0;
	     i < sizeof kStunResponseVectors / sizeof kStunResponseVectors[0];
	     i++) {
		uint8_t txid[TC_STUN_TXID_LEN], msg[256], want_ip[16];
		TCT_EQ_INT(
		    (int)unhex(txid, sizeof txid, kStunResponseVectors[i].txid),
		    TC_STUN_TXID_LEN);
		size_t mn = unhex(msg, sizeof msg, kStunResponseVectors[i].msg);
		size_t ipn = unhex(want_ip, sizeof want_ip,
		                   kStunResponseVectors[i].want_ip);

		tc_endpoint ep;
		uint8_t got_txid[TC_STUN_TXID_LEN];
		if (tc_stun_parse_response(msg, mn, got_txid, &ep) != TC_OK) {
			TCT_FAILF("could not parse %s", kStunResponseVectors[i].name);
			continue;
		}
		tct_checks++;
		TCT_EQ_MEM(got_txid, txid, TC_STUN_TXID_LEN);
		TCT_EQ_INT(ep.ip_len, (int)ipn);
		TCT_EQ_INT(ep.port, kStunResponseVectors[i].want_port);
		if (memcmp(ep.ip, want_ip, ipn) != 0)
			TCT_FAILF("%s decoded to the wrong address",
			          kStunResponseVectors[i].name);
		tct_checks++;
	}
}

int main(void)
{
	test_rfc_vectors();
	test_against_tailscale();
	test_request_shape();
	test_round_trip();
	test_alt_and_legacy_attributes();
	test_rejects();
	return tct_report("stun");
}
