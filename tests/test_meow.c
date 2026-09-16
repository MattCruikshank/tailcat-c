/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The meow exchange, disco key derivation and tunnel addressing.
 *
 * The encoded packets and disco keys come from tests/meow_vectors.h, which
 * tools/genaddrs generates using upstream tailcat's own EncodeMeowPing,
 * EncodeMeowed and DiscoPublicForNode. Both are wire-visible, so pinning them
 * against upstream is what stops a plausible-but-wrong implementation from
 * passing its own tests.
 */

#include "tc/tailcat.h"

#include "tc/crypto.h"
#include "tc/noise.h"
#include "tctest.h"

#include "meow_vectors.h"

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t unhex(uint8_t *buf, size_t cap, const char *s)
{
	size_t n = strlen(s);
	if (n % 2 != 0 || n / 2 > cap)
		return (size_t)-1;
	for (size_t i = 0; i < n; i += 2) {
		int hi = hexval(s[i]), lo = hexval(s[i + 1]);
		if (hi < 0 || lo < 0)
			return (size_t)-1;
		buf[i / 2] = (uint8_t)(hi << 4 | lo);
	}
	return n / 2;
}

static void test_disco_derivation(void)
{
	for (size_t i = 0; i < sizeof kDiscoVectors / sizeof kDiscoVectors[0];
	     i++) {
		TCT_CASE("disco key derivation matches upstream");

		uint8_t priv[32], want_pub[32], want_disco[32];
		TCT_EQ_INT(unhex(priv, sizeof priv, kDiscoVectors[i].node_private), 32);
		TCT_EQ_INT(unhex(want_pub, sizeof want_pub,
		                 kDiscoVectors[i].node_public),
		           32);
		TCT_EQ_INT(unhex(want_disco, sizeof want_disco,
		                 kDiscoVectors[i].disco_public),
		           32);

		/* The node public key must come out of our own X25519 too, which
		 * confirms the vector's private key is stored clamped. */
		tc_wg_identity id;
		TCT_EQ_INT(tc_wg_identity_from_private(&id, priv), TC_OK);
		TCT_EQ_MEM(id.public_key, want_pub, 32);

		uint8_t disco_pub[32], disco_priv[32];
		TCT_EQ_INT(tc_disco_key_for_node(disco_priv, disco_pub, priv), TC_OK);
		TCT_EQ_MEM(disco_pub, want_disco, 32);

		/* And the derived private key really is the one behind it. */
		uint8_t check[32];
		TCT_EQ_INT(tc_x25519_base(check, disco_priv), TC_OK);
		TCT_EQ_MEM(check, want_disco, 32);
	}

	TCT_CASE("derivation is deterministic and clamped");
	uint8_t priv[32];
	memset(priv, 0x42, sizeof priv);
	uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
	TCT_EQ_INT(tc_disco_key_for_node(a_priv, a_pub, priv), TC_OK);
	TCT_EQ_INT(tc_disco_key_for_node(b_priv, b_pub, priv), TC_OK);
	TCT_EQ_MEM(a_pub, b_pub, 32);
	TCT_EQ_INT(a_priv[0] & 7, 0);
	TCT_EQ_INT(a_priv[31] & 0x80, 0);
	TCT_EQ_INT(a_priv[31] & 0x40, 0x40);

	TCT_CASE("the disco key differs from the node key");
	/* They are deliberately independent: disco keys travel in cleartext on
	 * direct paths, the node key does not. */
	tc_wg_identity id;
	TCT_EQ_INT(tc_wg_identity_from_private(&id, priv), TC_OK);
	TCT_TRUE(memcmp(a_pub, id.public_key, 32) != 0);
	TCT_TRUE(memcmp(a_priv, id.private_key, 32) != 0);

	TCT_CASE("either output may be NULL");
	TCT_EQ_INT(tc_disco_key_for_node(NULL, a_pub, priv), TC_OK);
	TCT_EQ_INT(tc_disco_key_for_node(a_priv, NULL, priv), TC_OK);
	TCT_EQ_INT(tc_disco_key_for_node(NULL, NULL, NULL), TC_ERR_INVAL);
}

static void test_meow_encoding(void)
{
	for (size_t i = 0;
	     i < sizeof kMeowPingVectors / sizeof kMeowPingVectors[0]; i++) {
		TCT_CASE("meow ping encoding matches upstream byte for byte");

		uint8_t node[32], disco[32], want[128];
		TCT_EQ_INT(unhex(node, sizeof node, kMeowPingVectors[i].node_public),
		           32);
		TCT_EQ_INT(unhex(disco, sizeof disco, kMeowPingVectors[i].disco_public),
		           32);
		size_t want_len = unhex(want, sizeof want, kMeowPingVectors[i].encoded);
		TCT_EQ_INT(want_len, TC_MEOW_PING_LEN);

		uint8_t got[128];
		size_t got_len = 0;
		TCT_EQ_INT(tc_meow_encode_ping(got, sizeof got, &got_len, node, disco),
		           TC_OK);
		TCT_EQ_INT(got_len, want_len);
		TCT_EQ_MEM(got, want, want_len);

		TCT_CASE("and parses back to the same keys");
		uint8_t back_node[32], back_disco[32];
		TCT_EQ_INT(tc_meow_parse_ping(want, want_len, back_node, back_disco),
		           TC_OK);
		TCT_EQ_MEM(back_node, node, 32);
		TCT_EQ_MEM(back_disco, disco, 32);

		TCT_TRUE(tc_meow_is_packet(want, want_len));
		TCT_TRUE(!tc_meow_is_meowed(want, want_len));
	}

	TCT_CASE("meowed encoding matches upstream");
	uint8_t want[16];
	size_t want_len = unhex(want, sizeof want, kMeowedEncoded);
	TCT_EQ_INT(want_len, TC_MEOW_MEOWED_LEN);

	uint8_t got[16];
	size_t got_len = 0;
	TCT_EQ_INT(tc_meow_encode_meowed(got, sizeof got, &got_len), TC_OK);
	TCT_EQ_INT(got_len, want_len);
	TCT_EQ_MEM(got, want, want_len);
	TCT_TRUE(tc_meow_is_packet(got, got_len));
	TCT_TRUE(tc_meow_is_meowed(got, got_len));
}

static void test_meow_rejections(void)
{
	uint8_t node[32], disco[32], pkt[TC_MEOW_PING_LEN];
	memset(node, 0x11, sizeof node);
	memset(disco, 0x22, sizeof disco);
	TCT_EQ_INT(tc_meow_encode_ping(pkt, sizeof pkt, NULL, node, disco), TC_OK);

	uint8_t out_node[32], out_disco[32];

	TCT_CASE("rejects an all-zero disco key");
	/* Upstream treats this as malformed rather than as "no disco key". */
	uint8_t bad[TC_MEOW_PING_LEN];
	memcpy(bad, pkt, sizeof bad);
	memset(bad + TC_MEOW_MAGIC_LEN + 1 + 32, 0, 32);
	TCT_EQ_INT(tc_meow_parse_ping(bad, sizeof bad, out_node, out_disco),
	           TC_ERR_INVAL);

	TCT_CASE("rejects a wrong magic");
	memcpy(bad, pkt, sizeof bad);
	bad[0] = 'M';
	TCT_EQ_INT(tc_meow_parse_ping(bad, sizeof bad, out_node, out_disco),
	           TC_ERR_INVAL);
	TCT_TRUE(!tc_meow_is_packet(bad, sizeof bad));

	TCT_CASE("rejects a wrong type");
	memcpy(bad, pkt, sizeof bad);
	bad[TC_MEOW_MAGIC_LEN] = 0x7f;
	TCT_EQ_INT(tc_meow_parse_ping(bad, sizeof bad, out_node, out_disco),
	           TC_ERR_INVAL);

	TCT_CASE("rejects a truncated ping");
	for (size_t n = 0; n < TC_MEOW_PING_LEN; n++)
		TCT_TRUE(tc_meow_parse_ping(pkt, n, out_node, out_disco) != TC_OK);

	TCT_CASE("a meowed packet is not a ping");
	uint8_t ack[TC_MEOW_MEOWED_LEN];
	TCT_EQ_INT(tc_meow_encode_meowed(ack, sizeof ack, NULL), TC_OK);
	TCT_TRUE(tc_meow_parse_ping(ack, sizeof ack, out_node, out_disco) !=
	         TC_OK);

	TCT_CASE("a too-small buffer is refused");
	TCT_EQ_INT(tc_meow_encode_ping(pkt, 8, NULL, node, disco), TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_meow_encode_meowed(ack, 2, NULL), TC_ERR_NOSPACE);
}

static void test_no_collision_with_wireguard(void)
{
	TCT_CASE("meow cannot be mistaken for WireGuard traffic");
	/* Both share one DERP channel. WireGuard message types are a
	 * little-endian uint32 of 1..4, so their first byte is 1..4; meow's is
	 * 'm'. This is the whole reason meow carries a magic prefix, so assert
	 * it rather than assume it. */
	const unsigned wg_types[] = { TC_WG_MSG_INITIATION, TC_WG_MSG_RESPONSE,
		                          TC_WG_MSG_COOKIE_REPLY,
		                          TC_WG_MSG_TRANSPORT };
	for (size_t i = 0; i < sizeof wg_types / sizeof wg_types[0]; i++) {
		uint8_t wg[64];
		memset(wg, 0, sizeof wg);
		wg[0] = (uint8_t)wg_types[i];
		TCT_TRUE(!tc_meow_is_packet(wg, sizeof wg));
		TCT_TRUE(!tc_meow_is_meowed(wg, sizeof wg));
	}
	TCT_TRUE((uint8_t)TC_MEOW_MAGIC[0] > 4);
}

static void test_tunnel_addr(void)
{
	TCT_CASE("the tunnel address uses Tailscale's ULA prefix");
	uint8_t pub[32];
	for (size_t i = 0; i < sizeof pub; i++)
		pub[i] = (uint8_t)(i + 1);

	uint8_t addr[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(addr, pub);

	static const uint8_t kPrefix[6] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };
	TCT_EQ_MEM(addr, kPrefix, 6);
	/* The remaining 80 bits are the first ten bytes of the node key. */
	TCT_EQ_MEM(addr + 6, pub, 10);

	TCT_CASE("different keys give different addresses");
	uint8_t other[32], other_addr[TC_TUNNEL_ADDR_LEN];
	memcpy(other, pub, sizeof other);
	other[0] ^= 0xff;
	tc_tunnel_addr_for_key(other_addr, other);
	TCT_TRUE(memcmp(addr, other_addr, TC_TUNNEL_ADDR_LEN) != 0);

	TCT_CASE("IPv6 formatting");
	static const struct {
		const char *bytes;
		const char *want;
	} kFmt[] = {
		{ "fd7a115ca1e00102030405060708090a", "fd7a:115c:a1e0:102:304:506:708:90a" },
		{ "00000000000000000000000000000000", "::" },
		{ "00000000000000000000000000000001", "::1" },
		{ "20010db8000000000000000000000001", "2001:db8::1" },
		{ "fe800000000000000202b3fffe1e8329", "fe80::202:b3ff:fe1e:8329" },
		{ "20010db8000000010000000000000001", "2001:db8:0:1::1" },
		{ "10000000000000000000000000000000", "1000::" },
	};
	for (size_t i = 0; i < sizeof kFmt / sizeof kFmt[0]; i++) {
		uint8_t raw[16];
		TCT_EQ_INT(unhex(raw, sizeof raw, kFmt[i].bytes), 16);
		char out[64];
		TCT_EQ_INT(tc_tunnel_addr_format(out, sizeof out, raw), TC_OK);
		TCT_EQ_STR(out, kFmt[i].want);
	}

	TCT_CASE("a too-small buffer is refused");
	char tiny[8];
	TCT_EQ_INT(tc_tunnel_addr_format(tiny, sizeof tiny, addr), TC_ERR_NOSPACE);
}

int main(void)
{
	test_disco_derivation();
	test_meow_encoding();
	test_meow_rejections();
	test_no_collision_with_wireguard();
	test_tunnel_addr();
	return tct_report("meow");
}
