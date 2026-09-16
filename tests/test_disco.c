/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The disco protocol.
 *
 * The outer wrapper carries a random nonce, so a whole packet cannot be
 * compared byte for byte against another implementation's. The payload inside
 * the box can be, and that is where every field offset lives -- so the
 * vectors here are the inner messages as marshalled by tailscale.com/disco,
 * and the tests reach them by sealing through our real API and opening the
 * box again.
 *
 * These packets arrive on an open UDP port from anywhere, so the rejection
 * cases matter as much as the round trips.
 */

#include "tc/crypto.h"
#include "tc/disco.h"

#include "crypto_vectors.h"
#include "tctest.h"

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

static const char *vector(const char *name)
{
	for (size_t i = 0;
	     i < sizeof kDiscoPayloadVectors / sizeof kDiscoPayloadVectors[0];
	     i++) {
		if (strcmp(kDiscoPayloadVectors[i].name, name) == 0)
			return kDiscoPayloadVectors[i].want;
	}
	return NULL;
}

/* A fixed pair of disco identities for the whole file. */
static uint8_t g_a_priv[32], g_a_pub[32];
static uint8_t g_b_priv[32], g_b_pub[32];

/* The transaction ID the vectors were generated with. Taken from a vector
 * rather than restated, so the two cannot drift apart. */
static void vector_txid(uint8_t out[TC_DISCO_TXID_LEN])
{
	uint8_t buf[64];
	size_t n = unhex(buf, sizeof buf, vector("ping-bare"));
	TCT_EQ_INT((int)n, 2 + TC_DISCO_TXID_LEN);
	memcpy(out, buf + 2, TC_DISCO_TXID_LEN);
}

/* sealed_payload seals msg from A to B and returns the plaintext B sees, so
 * the encoding can be compared with another implementation's without the
 * random nonce getting in the way. */
static size_t sealed_payload(const tc_disco_msg *msg, uint8_t *out, size_t cap)
{
	static uint8_t pkt[2048];
	size_t pkt_len = 0;
	if (tc_disco_seal(pkt, sizeof pkt, &pkt_len, msg, g_a_pub, g_a_priv,
	                  g_b_pub) != TC_OK)
		return 0;

	size_t box_len = pkt_len - TC_DISCO_HEADER_LEN;
	if (box_len < TC_BOX_TAG_LEN || box_len - TC_BOX_TAG_LEN > cap)
		return 0;
	const uint8_t *nonce = pkt + TC_DISCO_MAGIC_LEN + 32;
	if (tc_box_open(out, nonce, pkt + TC_DISCO_HEADER_LEN, box_len, g_a_pub,
	                g_b_priv) != TC_OK)
		return 0;
	return box_len - TC_BOX_TAG_LEN;
}

static void expect_payload(const tc_disco_msg *msg, const char *name)
{
	uint8_t want[1024], got[1024];
	size_t wn = unhex(want, sizeof want, vector(name));
	size_t gn = sealed_payload(msg, got, sizeof got);
	if (gn != wn || memcmp(got, want, wn) != 0)
		TCT_FAILF("%s: our payload differs from tailscale's (%zu vs %zu "
		          "bytes)",
		          name, gn, wn);
	tct_checks++;
}

static void test_encoding_matches_tailscale(void)
{
	TCT_CASE("our messages encode exactly as tailscale's do");
	uint8_t tx[TC_DISCO_TXID_LEN];
	vector_txid(tx);

	tc_disco_msg m;

	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PING;
	memcpy(m.ping.txid, tx, sizeof tx);
	expect_payload(&m, "ping-bare");

	TCT_CASE("a ping carrying a node key");
	uint8_t want[1024];
	size_t wn = unhex(want, sizeof want, vector("ping-with-nodekey"));
	TCT_EQ_INT((int)wn, 2 + TC_DISCO_TXID_LEN + 32);
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PING;
	memcpy(m.ping.txid, tx, sizeof tx);
	memcpy(m.ping.node_key, want + 2 + TC_DISCO_TXID_LEN, 32);
	m.ping.has_node_key = true;
	expect_payload(&m, "ping-with-nodekey");

	TCT_CASE("a padded ping, which is how the path MTU gets probed");
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PING;
	memcpy(m.ping.txid, tx, sizeof tx);
	m.ping.padding = 20;
	expect_payload(&m, "ping-padded");

	TCT_CASE("a pong, for both address families");
	/* Every address goes on the wire as sixteen bytes, an IPv4 one in its
	 * v4-mapped form. Sending the four-byte form would be shorter and would
	 * not parse anywhere. */
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	memcpy(m.pong.txid, tx, sizeof tx);
	m.pong.src.ip[0] = 203;
	m.pong.src.ip[1] = 0;
	m.pong.src.ip[2] = 113;
	m.pong.src.ip[3] = 7;
	m.pong.src.ip_len = 4;
	m.pong.src.port = 41641;
	expect_payload(&m, "pong-0");

	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	memcpy(m.pong.txid, tx, sizeof tx);
	static const uint8_t kV6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		                             0,    0,    0,    0,    0, 0, 0, 1 };
	memcpy(m.pong.src.ip, kV6, 16);
	m.pong.src.ip_len = 16;
	m.pong.src.port = 443;
	expect_payload(&m, "pong-1");

	TCT_CASE("call-me-maybe, empty and with a mix of families");
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_CALL_ME_MAYBE;
	expect_payload(&m, "cmm-empty");

	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_CALL_ME_MAYBE;
	m.call_me_maybe.num = 3;
	uint8_t a[4] = { 192, 168, 1, 10 }, b[4] = { 203, 0, 113, 7 };
	memcpy(m.call_me_maybe.eps[0].ip, a, 4);
	m.call_me_maybe.eps[0].ip_len = 4;
	m.call_me_maybe.eps[0].port = 41641;
	memcpy(m.call_me_maybe.eps[1].ip, b, 4);
	m.call_me_maybe.eps[1].ip_len = 4;
	m.call_me_maybe.eps[1].port = 41641;
	memcpy(m.call_me_maybe.eps[2].ip, kV6, 16);
	m.call_me_maybe.eps[2].ip_len = 16;
	m.call_me_maybe.eps[2].port = 41641;
	expect_payload(&m, "cmm-three");
}

static void test_parses_tailscales_encoding(void)
{
	TCT_CASE("and we parse what tailscale produced");
	/* The other direction: their bytes, wrapped in a box, through our
	 * parser. Encoding and decoding both agreeing with us would prove
	 * nothing about either. */
	static const struct {
		const char *name;
		tc_disco_type type;
	} cases[] = {
		{ "ping-bare", TC_DISCO_PING },
		{ "ping-with-nodekey", TC_DISCO_PING },
		{ "ping-padded", TC_DISCO_PING },
		{ "pong-0", TC_DISCO_PONG },
		{ "pong-1", TC_DISCO_PONG },
		{ "cmm-empty", TC_DISCO_CALL_ME_MAYBE },
		{ "cmm-three", TC_DISCO_CALL_ME_MAYBE },
	};

	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		uint8_t payload[1024];
		size_t pn = unhex(payload, sizeof payload, vector(cases[i].name));

		static uint8_t pkt[2048];
		memcpy(pkt, "TS\xf0\x9f\x92\xac", TC_DISCO_MAGIC_LEN);
		memcpy(pkt + TC_DISCO_MAGIC_LEN, g_a_pub, 32);
		uint8_t *nonce = pkt + TC_DISCO_MAGIC_LEN + 32;
		TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
		TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, payload, pn,
		                       g_b_pub, g_a_priv),
		           TC_OK);
		size_t total = TC_DISCO_HEADER_LEN + pn + TC_BOX_TAG_LEN;

		tc_disco_msg m;
		if (tc_disco_open(&m, pkt, total, g_b_priv, g_a_pub) != TC_OK) {
			TCT_FAILF("could not open %s", cases[i].name);
			continue;
		}
		tct_checks++;
		TCT_EQ_INT((int)m.type, (int)cases[i].type);
	}

	TCT_CASE("a pong's source address comes back unmapped");
	/* The same IPv4 address learned this way has to compare equal to one
	 * learned any other way, or a path looks like two. */
	uint8_t payload[1024];
	size_t pn = unhex(payload, sizeof payload, vector("pong-0"));
	static uint8_t pkt[2048];
	memcpy(pkt, "TS\xf0\x9f\x92\xac", TC_DISCO_MAGIC_LEN);
	memcpy(pkt + TC_DISCO_MAGIC_LEN, g_a_pub, 32);
	uint8_t *nonce = pkt + TC_DISCO_MAGIC_LEN + 32;
	TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, payload, pn,
	                       g_b_pub, g_a_priv),
	           TC_OK);
	tc_disco_msg m;
	TCT_EQ_INT(tc_disco_open(&m, pkt, TC_DISCO_HEADER_LEN + pn + TC_BOX_TAG_LEN,
	                         g_b_priv, g_a_pub),
	           TC_OK);
	TCT_EQ_INT(m.pong.src.ip_len, 4);
	TCT_EQ_INT(m.pong.src.port, 41641);
	char s[64];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &m.pong.src), TC_OK);
	TCT_EQ_STR(s, "203.0.113.7:41641");

	TCT_CASE("and a call-me-maybe's endpoints do too");
	pn = unhex(payload, sizeof payload, vector("cmm-three"));
	TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, payload, pn,
	                       g_b_pub, g_a_priv),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt, TC_DISCO_HEADER_LEN + pn + TC_BOX_TAG_LEN,
	                         g_b_priv, g_a_pub),
	           TC_OK);
	TCT_EQ_INT((int)m.call_me_maybe.num, 3);
	TCT_EQ_INT(m.call_me_maybe.eps[0].ip_len, 4);
	TCT_EQ_INT(m.call_me_maybe.eps[1].ip_len, 4);
	TCT_EQ_INT(m.call_me_maybe.eps[2].ip_len, 16);
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &m.call_me_maybe.eps[2]),
	           TC_OK);
	TCT_EQ_STR(s, "[2001:db8::1]:41641");
}

static void test_round_trip(void)
{
	TCT_CASE("a sealed message opens with the right keys");
	tc_disco_msg out, in;
	memset(&in, 0, sizeof in);
	in.type = TC_DISCO_PING;
	TCT_EQ_INT(tc_random_bytes(in.ping.txid, TC_DISCO_TXID_LEN), TC_OK);
	TCT_EQ_INT(tc_random_bytes(in.ping.node_key, 32), TC_OK);
	in.ping.has_node_key = true;

	uint8_t pkt[2048];
	size_t n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_OK);
	TCT_TRUE(tc_disco_looks_like(pkt, n));

	uint8_t src[32];
	TCT_EQ_INT(tc_disco_source(pkt, n, src), TC_OK);
	TCT_EQ_MEM(src, g_a_pub, 32);

	TCT_EQ_INT(tc_disco_open(&out, pkt, n, g_b_priv, g_a_pub), TC_OK);
	TCT_EQ_INT((int)out.type, TC_DISCO_PING);
	TCT_EQ_MEM(out.ping.txid, in.ping.txid, TC_DISCO_TXID_LEN);
	TCT_TRUE(out.ping.has_node_key);
	TCT_EQ_MEM(out.ping.node_key, in.ping.node_key, 32);

	TCT_CASE("two seals of the same message differ");
	/* The nonce is random per message; reusing one under the same key pair
	 * would leak the XOR of two payloads. */
	uint8_t pkt2[2048];
	size_t n2 = 0;
	TCT_EQ_INT(tc_disco_seal(pkt2, sizeof pkt2, &n2, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_OK);
	TCT_EQ_INT((int)n2, (int)n);
	TCT_TRUE(memcmp(pkt, pkt2, n) != 0);

	TCT_CASE("padding survives the round trip");
	memset(&in, 0, sizeof in);
	in.type = TC_DISCO_PING;
	in.ping.padding = 100;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&out, pkt, n, g_b_priv, g_a_pub), TC_OK);
	TCT_EQ_INT((int)out.ping.padding, 100);
	TCT_TRUE(!out.ping.has_node_key);
}

static void test_rejects(void)
{
	tc_disco_msg m, in;
	memset(&in, 0, sizeof in);
	in.type = TC_DISCO_PING;
	uint8_t pkt[2048];
	size_t n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_OK);

	TCT_CASE("a message sealed to someone else does not open");
	uint8_t c_priv[32], c_pub[32];
	TCT_EQ_INT(tc_x25519_keypair(c_priv, c_pub), TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, c_priv, g_a_pub), TC_ERR_INVAL);

	TCT_CASE("a sender key other than the one expected is refused");
	/* The packet names its own sender, and believing that field would let
	 * anyone seal a valid disco message to us -- which is the one thing
	 * sealing is for. */
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, c_pub), TC_ERR_INVAL);

	TCT_CASE("a tampered box does not open");
	pkt[n - 1] ^= 1;
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, g_a_pub), TC_ERR_INVAL);
	pkt[n - 1] ^= 1;
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, g_a_pub), TC_OK);

	TCT_CASE("a tampered nonce does not open");
	pkt[TC_DISCO_MAGIC_LEN + 32] ^= 1;
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, g_a_pub), TC_ERR_INVAL);
	pkt[TC_DISCO_MAGIC_LEN + 32] ^= 1;

	TCT_CASE("a packet without the magic is not disco");
	pkt[0] ^= 1;
	TCT_TRUE(!tc_disco_looks_like(pkt, n));
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, g_a_pub), TC_ERR_INVAL);
	pkt[0] ^= 1;

	TCT_CASE("every prefix of a real packet is refused");
	for (size_t k = 1; k < n; k += 3) {
		if (tc_disco_open(&m, pkt, k, g_b_priv, g_a_pub) == TC_OK)
			TCT_FAILF("accepted a %zu byte prefix", k);
		tct_checks++;
	}

	TCT_CASE("an unknown message type is reported as unsupported, not bad");
	/* The protocol has nine types and basic traversal uses three. A peer
	 * that sends one of the others is newer, not hostile, and the caller
	 * needs to be able to tell those apart. */
	uint8_t payload[4] = { 0x07, 0x00, 0x00, 0x00 }; /* CallMeMaybeVia */
	memcpy(pkt, "TS\xf0\x9f\x92\xac", TC_DISCO_MAGIC_LEN);
	memcpy(pkt + TC_DISCO_MAGIC_LEN, g_a_pub, 32);
	uint8_t *nonce = pkt + TC_DISCO_MAGIC_LEN + 32;
	TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, payload,
	                       sizeof payload, g_b_pub, g_a_priv),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt,
	                         TC_DISCO_HEADER_LEN + sizeof payload +
	                             TC_BOX_TAG_LEN,
	                         g_b_priv, g_a_pub),
	           TC_ERR_UNSUPPORTED);

	TCT_CASE("a ragged call-me-maybe yields no endpoints, not an error");
	/* Upstream's choice, and worth matching: a peer that learns to send
	 * something new should not look broken to one that has not. */
	uint8_t ragged[2 + 17] = { 0x03, 0x00 };
	TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, ragged,
	                       sizeof ragged, g_b_pub, g_a_priv),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt,
	                         TC_DISCO_HEADER_LEN + sizeof ragged +
	                             TC_BOX_TAG_LEN,
	                         g_b_priv, g_a_pub),
	           TC_OK);
	TCT_EQ_INT((int)m.type, TC_DISCO_CALL_ME_MAYBE);
	TCT_EQ_INT((int)m.call_me_maybe.num, 0);

	TCT_CASE("more endpoints than we hold are truncated, not overflowed");
	static uint8_t many[2 + 40 * 18];
	many[0] = 0x03;
	many[1] = 0x00;
	for (size_t i = 0; i < 40; i++) {
		uint8_t *e = many + 2 + i * 18;
		memset(e, 0, 18);
		e[10] = 0xff;
		e[11] = 0xff;
		e[12] = 203;
		e[13] = 0;
		e[14] = 113;
		e[15] = (uint8_t)i;
		e[16] = 0xa2;
		e[17] = 0xa9;
	}
	TCT_EQ_INT(tc_random_bytes(nonce, TC_DISCO_NONCE_LEN), TC_OK);
	TCT_EQ_INT(tc_box_seal(pkt + TC_DISCO_HEADER_LEN, nonce, many,
	                       sizeof many, g_b_pub, g_a_priv),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt,
	                         TC_DISCO_HEADER_LEN + sizeof many + TC_BOX_TAG_LEN,
	                         g_b_priv, g_a_pub),
	           TC_OK);
	TCT_EQ_INT((int)m.call_me_maybe.num, TC_DISCO_MAX_ENDPOINTS);

	TCT_CASE("a ping padded past 32 bytes is not read as a node key");
	/* The sender omits the field when it has none, so zeros there can only
	 * be padding. Reading them would invent a peer identity out of filler. */
	memset(&in, 0, sizeof in);
	in.type = TC_DISCO_PING;
	in.ping.padding = 64;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_OK);
	TCT_EQ_INT(tc_disco_open(&m, pkt, n, g_b_priv, g_a_pub), TC_OK);
	TCT_TRUE(!m.ping.has_node_key);
	TCT_EQ_INT((int)m.ping.padding, 64);

	TCT_CASE("null arguments and short buffers are refused");
	uint8_t tiny[8];
	size_t tn = 0;
	TCT_EQ_INT(tc_disco_seal(tiny, sizeof tiny, &tn, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_disco_seal(NULL, 100, &tn, &in, g_a_pub, g_a_priv, g_b_pub),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_disco_open(NULL, pkt, n, g_b_priv, g_a_pub), TC_ERR_INVAL);
	TCT_EQ_INT(tc_disco_open(&m, NULL, n, g_b_priv, g_a_pub), TC_ERR_INVAL);
	TCT_TRUE(!tc_disco_looks_like(NULL, 100));
	TCT_EQ_INT(tc_disco_source(pkt, 3, g_a_pub), TC_ERR_INVAL);

	TCT_CASE("too many endpoints to send is refused, not truncated");
	memset(&in, 0, sizeof in);
	in.type = TC_DISCO_CALL_ME_MAYBE;
	in.call_me_maybe.num = TC_DISCO_MAX_ENDPOINTS + 1;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &in, g_a_pub, g_a_priv,
	                         g_b_pub),
	           TC_ERR_TOOMANY);
}

int main(void)
{
	if (tc_x25519_keypair(g_a_priv, g_a_pub) != TC_OK ||
	    tc_x25519_keypair(g_b_priv, g_b_pub) != TC_OK) {
		fprintf(stderr, "could not generate disco keys\n");
		return 1;
	}
	test_encoding_matches_tailscale();
	test_parses_tailscales_encoding();
	test_round_trip();
	test_rejects();
	return tct_report("disco");
}
