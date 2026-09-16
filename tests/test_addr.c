/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The golden addresses and the malformed-input cases here are ported from
 * upstream tailcat's tailcat_test.go (TestAddr, TestParseAddrMalformed*,
 * TestParseAddrNullInArrays), so passing this is evidence of real wire
 * compatibility rather than self-consistency.
 */

#include "tc/addr.h"
#include "tc/base64url.h"
#include "tc/cbor.h"
#include "tctest.h"

/* The server public key used throughout upstream's TestAddr:
 * [32]byte{1: 1, 2: 2, 31: 31}. */
static void golden_key(uint8_t k[32])
{
	memset(k, 0, 32);
	k[1] = 1;
	k[2] = 2;
	k[31] = 31;
}

/* addr_from_cbor builds "tc" + base64url(raw), the way upstream's tests
 * construct deliberately malformed addresses. */
static size_t addr_from_cbor(char *out, size_t cap, const uint8_t *raw,
                             size_t n)
{
	size_t len = 0;
	memcpy(out, "tc", 2);
	int rc = tc_base64url_encode(out + 2, cap - 2, raw, n, &len);
	TCT_EQ_INT(rc, TC_OK);
	return len + 2;
}

/* ---- golden vectors -------------------------------------------------- */

static void test_golden_just_key(void)
{
	TCT_CASE("golden: just_key encodes exactly");
	static const char kWant[] =
		"tcoWFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHw";

	tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);

	char got[TC_ADDR_STR_MAX];
	size_t got_len = 0;
	TCT_EQ_INT(tc_addr_encode(got, sizeof got, &ci, &got_len), TC_OK);
	TCT_EQ_STR(got, kWant);
	TCT_EQ_INT(got_len, strlen(kWant));

	TCT_CASE("golden: just_key parses back");
	tc_conn_info back;
	TCT_EQ_INT(tc_addr_parse(&back, kWant, strlen(kWant)), TC_OK);
	TCT_EQ_MEM(back.server_public, ci.server_public, 32);
	TCT_TRUE(!back.has_disco_public);
	TCT_TRUE(!back.has_preshared_key);
	TCT_EQ_INT(back.num_regions, 0);
	TCT_EQ_INT(back.region_id, 0);
}

static void test_golden_region_id(void)
{
	TCT_CASE("golden: region_id encodes exactly");
	static const char kWant[] =
		"tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg";

	tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);
	ci.region_id = 10;

	char got[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(got, sizeof got, &ci, NULL), TC_OK);
	TCT_EQ_STR(got, kWant);

	TCT_CASE("golden: region_id parses back");
	tc_conn_info back;
	TCT_EQ_INT(tc_addr_parse(&back, kWant, strlen(kWant)), TC_OK);
	TCT_EQ_MEM(back.server_public, ci.server_public, 32);
	TCT_EQ_INT(back.region_id, 10);
	TCT_EQ_INT(back.num_regions, 0);
}

/* Upstream's cli_test.go and ssh_test.go both use this real address. */
static void test_real_world_addr(void)
{
	TCT_CASE("parses an address from upstream's tests");
	static const char kAddr[] =
		"tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";

	tc_conn_info ci;
	TCT_EQ_INT(tc_addr_parse(&ci, kAddr, strlen(kAddr)), TC_OK);
	TCT_TRUE(!tc_ct_is_zero(ci.server_public, 32));

	TCT_CASE("and re-encodes to exactly the same string");
	char back[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(back, sizeof back, &ci, NULL), TC_OK);
	TCT_EQ_STR(back, kAddr);
}

/* ---- elide/restore are exact inverses -------------------------------- */

static void test_custom_region_round_trip(void)
{
	TCT_CASE("key_with_full_custom_region");
	tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);
	ci.num_regions = 1;
	ci.regions[0].num_nodes = 2;
	snprintf(ci.regions[0].nodes[0].name, TC_DNS_NAME_MAX, "%s", "1a");
	snprintf(ci.regions[0].nodes[0].ipv4, TC_IP_STR_MAX, "%s",
	         "400.400.400.400");
	snprintf(ci.regions[0].nodes[0].hostname, TC_DNS_NAME_MAX, "%s",
	         "my-derp.custom.example");
	snprintf(ci.regions[0].nodes[1].name, TC_DNS_NAME_MAX, "%s", "1b");
	snprintf(ci.regions[0].nodes[1].ipv4, TC_IP_STR_MAX, "%s",
	         "400.400.400.400");
	snprintf(ci.regions[0].nodes[1].hostname, TC_DNS_NAME_MAX, "%s",
	         "my-derp2.custom.example");

	char addr[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(addr, sizeof addr, &ci, NULL), TC_OK);

	tc_conn_info back;
	TCT_EQ_INT(tc_addr_parse(&back, addr, strlen(addr)), TC_OK);

	/* Upstream's expected round-tripped form. */
	TCT_EQ_INT(back.num_regions, 1);
	TCT_EQ_INT(back.regions[0].region_id, 1);
	TCT_EQ_STR(back.regions[0].region_code, "1");
	TCT_EQ_STR(back.regions[0].region_name, "");
	TCT_EQ_INT(back.regions[0].num_nodes, 2);

	TCT_EQ_INT(back.regions[0].nodes[0].region_id, 1);
	TCT_EQ_STR(back.regions[0].nodes[0].name, "my-derp.custom.example");
	TCT_EQ_STR(back.regions[0].nodes[0].hostname, "my-derp.custom.example");
	TCT_EQ_STR(back.regions[0].nodes[0].ipv4, "400.400.400.400");

	TCT_EQ_INT(back.regions[0].nodes[1].region_id, 1);
	TCT_EQ_STR(back.regions[0].nodes[1].name, "my-derp2.custom.example");
	TCT_EQ_STR(back.regions[0].nodes[1].hostname, "my-derp2.custom.example");

	TCT_CASE("re-encoding the restored form is stable");
	char again[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(again, sizeof again, &back, NULL), TC_OK);
	TCT_EQ_STR(again, addr);
}

static void test_implicit_fields_removed(void)
{
	TCT_CASE("remove_implicit_fields_on_marshal");
	tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);
	ci.num_regions = 1;
	ci.regions[0].region_id = 123;
	snprintf(ci.regions[0].region_name, TC_REGION_NAME_MAX, "%s", "Seattle");
	ci.regions[0].num_nodes = 2;
	ci.regions[0].nodes[0].region_id = 123;
	snprintf(ci.regions[0].nodes[0].name, TC_DNS_NAME_MAX, "%s", "1a");
	snprintf(ci.regions[0].nodes[0].hostname, TC_DNS_NAME_MAX, "%s",
	         "tc1a.ipn.dev");
	ci.regions[0].nodes[1].region_id = 123;
	snprintf(ci.regions[0].nodes[1].name, TC_DNS_NAME_MAX, "%s", "1b");
	snprintf(ci.regions[0].nodes[1].hostname, TC_DNS_NAME_MAX, "%s",
	         "derp1b.tailscale.com");

	char addr[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(addr, sizeof addr, &ci, NULL), TC_OK);

	tc_conn_info back;
	TCT_EQ_INT(tc_addr_parse(&back, addr, strlen(addr)), TC_OK);

	/* RegionID 123 and RegionName "Seattle" are dropped on the wire, so the
	 * parsed form gets the synthesised 1-based ID and its decimal code. */
	TCT_EQ_INT(back.regions[0].region_id, 1);
	TCT_EQ_STR(back.regions[0].region_code, "1");
	TCT_EQ_STR(back.regions[0].region_name, "");
	TCT_EQ_INT(back.regions[0].nodes[0].region_id, 1);
	TCT_EQ_STR(back.regions[0].nodes[0].name, "tc1a.ipn.dev");
	TCT_EQ_STR(back.regions[0].nodes[1].name, "derp1b.tailscale.com");
}

static void test_optional_keys_round_trip(void)
{
	TCT_CASE("disco key and pre-shared key survive a round trip");
	tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);
	ci.has_disco_public = true;
	for (size_t i = 0; i < 32; i++)
		ci.server_disco_public[i] = (uint8_t)(0xa0 + i);
	ci.has_preshared_key = true;
	for (size_t i = 0; i < 32; i++)
		ci.preshared_key[i] = (uint8_t)(0x40 + i);
	ci.region_id = 10;

	char addr[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(addr, sizeof addr, &ci, NULL), TC_OK);

	tc_conn_info back;
	TCT_EQ_INT(tc_addr_parse(&back, addr, strlen(addr)), TC_OK);
	TCT_TRUE(back.has_disco_public);
	TCT_TRUE(back.has_preshared_key);
	TCT_EQ_MEM(back.server_disco_public, ci.server_disco_public, 32);
	TCT_EQ_MEM(back.preshared_key, ci.preshared_key, 32);
	TCT_EQ_INT(back.region_id, 10);

	TCT_CASE("an address without a PSK is shorter than one with");
	tc_conn_info no_psk = ci;
	no_psk.has_preshared_key = false;
	char shorter[TC_ADDR_STR_MAX];
	TCT_EQ_INT(tc_addr_encode(shorter, sizeof shorter, &no_psk, NULL), TC_OK);
	TCT_TRUE(strlen(shorter) < strlen(addr));
}

/* ---- malformed input ------------------------------------------------- */

/* Builds {"p": <n bytes>} and asserts it is rejected, mirroring upstream's
 * TestParseAddrMalformedPublicKey. */
static void expect_bad_key_len(char field, size_t n)
{
	uint8_t raw[128];
	tc_cbor_writer w;
	uint8_t filler[64];
	memset(filler, 0, sizeof filler);

	tc_cbor_writer_init(&w, raw, sizeof raw);
	if (field == 'p') {
		tc_cbor_write_map_header(&w, 1);
		tc_cbor_write_text(&w, "p", 1);
		tc_cbor_write_bytes(&w, filler, n);
	} else {
		/* A valid "p" plus a malformed optional key. */
		uint8_t pub[32];
		golden_key(pub);
		tc_cbor_write_map_header(&w, 2);
		tc_cbor_write_text(&w, "p", 1);
		tc_cbor_write_bytes(&w, pub, 32);
		tc_cbor_write_text(&w, &field, 1);
		tc_cbor_write_bytes(&w, filler, n);
	}
	size_t raw_len = 0;
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);

	char addr[TC_ADDR_STR_MAX];
	size_t addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);

	tc_conn_info ci;
	TCT_TRUE(tc_addr_parse(&ci, addr, addr_len) != TC_OK);
}

static void test_malformed_keys(void)
{
	TCT_CASE("rejects a short or long server public key");
	expect_bad_key_len('p', 31);
	expect_bad_key_len('p', 33);

	TCT_CASE("rejects a short or long disco public key");
	expect_bad_key_len('k', 31);
	expect_bad_key_len('k', 33);

	TCT_CASE("rejects a short or long pre-shared key");
	expect_bad_key_len('q', 31);
	expect_bad_key_len('q', 33);
}

static void test_null_in_arrays(void)
{
	uint8_t raw[128];
	tc_cbor_writer w;
	uint8_t pub[32];
	size_t raw_len = 0;
	char addr[TC_ADDR_STR_MAX];
	size_t addr_len;
	tc_conn_info ci;

	golden_key(pub);

	TCT_CASE("rejects a null region");
	/* {"p": pub, "r": [null]} */
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "r", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_null(&w);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_TRUE(tc_addr_parse(&ci, addr, addr_len) != TC_OK);

	TCT_CASE("rejects a null node");
	/* {"p": pub, "r": [{"i": 1, "N": [null]}]} */
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "r", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "i", 1);
	tc_cbor_write_uint(&w, 1);
	tc_cbor_write_text(&w, "N", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_null(&w);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_TRUE(tc_addr_parse(&ci, addr, addr_len) != TC_OK);
}

static void test_structural_rejections(void)
{
	tc_conn_info ci;

	TCT_CASE("rejects a missing tc prefix");
	TCT_EQ_INT(tc_addr_parse(&ci, "xx1234", 6), TC_ERR_INVAL);
	TCT_EQ_INT(tc_addr_parse(&ci, "", 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_addr_parse(&ci, "t", 1), TC_ERR_INVAL);

	TCT_CASE("rejects an address with no CBOR at all");
	TCT_TRUE(tc_addr_parse(&ci, "tc", 2) != TC_OK);

	TCT_CASE("rejects bad base64");
	TCT_EQ_INT(tc_addr_parse(&ci, "tc!!!!", 6), TC_ERR_INVAL);

	TCT_CASE("rejects a top-level item that is not a map");
	uint8_t raw[64];
	tc_cbor_writer w;
	size_t raw_len = 0;
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_uint(&w, 1);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	char addr[TC_ADDR_STR_MAX];
	size_t addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_TRUE(tc_addr_parse(&ci, addr, addr_len) != TC_OK);

	TCT_CASE("rejects a map with no server public key");
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "i", 1);
	tc_cbor_write_uint(&w, 10);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_ERR_INVAL);

	TCT_CASE("rejects trailing bytes after the map");
	uint8_t pub[32];
	golden_key(pub);
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_uint(&w, 99); /* junk after the map */
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_ERR_INVAL);
}

static void test_unknown_fields_are_skipped(void)
{
	TCT_CASE("an unknown field from a newer tailcat is ignored");
	uint8_t raw[128];
	uint8_t pub[32];
	tc_cbor_writer w;
	size_t raw_len = 0;
	golden_key(pub);

	/* {"p": pub, "z": [1, {"deep": 2}], "i": 7} */
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 3);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "z", 1);
	tc_cbor_write_array_header(&w, 2);
	tc_cbor_write_uint(&w, 1);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "deep", 4);
	tc_cbor_write_uint(&w, 2);
	tc_cbor_write_text(&w, "i", 1);
	tc_cbor_write_uint(&w, 7);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);

	char addr[TC_ADDR_STR_MAX];
	size_t addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);

	tc_conn_info ci;
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_OK);
	TCT_EQ_MEM(ci.server_public, pub, 32);
	TCT_EQ_INT(ci.region_id, 7);
}

static void test_limits(void)
{
	TCT_CASE("too many regions is an error, not a smash");
	uint8_t raw[512];
	uint8_t pub[32];
	tc_cbor_writer w;
	size_t raw_len = 0;
	golden_key(pub);

	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "r", 1);
	tc_cbor_write_array_header(&w, TC_ADDR_MAX_REGIONS + 1);
	for (int i = 0; i < TC_ADDR_MAX_REGIONS + 1; i++)
		tc_cbor_write_map_header(&w, 0);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);

	char addr[TC_ADDR_STR_MAX];
	size_t addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	tc_conn_info ci;
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_ERR_TOOMANY);

	TCT_CASE("too many nodes is an error, not a smash");
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "r", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "N", 1);
	tc_cbor_write_array_header(&w, TC_ADDR_MAX_NODES + 1);
	for (int i = 0; i < TC_ADDR_MAX_NODES + 1; i++)
		tc_cbor_write_map_header(&w, 0);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_ERR_TOOMANY);

	TCT_CASE("an over-long hostname is rejected, not truncated");
	char longhost[TC_DNS_NAME_MAX + 8];
	memset(longhost, 'a', sizeof longhost);
	tc_cbor_writer_init(&w, raw, sizeof raw);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "p", 1);
	tc_cbor_write_bytes(&w, pub, 32);
	tc_cbor_write_text(&w, "r", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "N", 1);
	tc_cbor_write_array_header(&w, 1);
	tc_cbor_write_map_header(&w, 1);
	tc_cbor_write_text(&w, "h", 1);
	tc_cbor_write_text(&w, longhost, sizeof longhost);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &raw_len), TC_OK);
	addr_len = addr_from_cbor(addr, sizeof addr, raw, raw_len);
	TCT_EQ_INT(tc_addr_parse(&ci, addr, addr_len), TC_ERR_NOSPACE);

	TCT_CASE("encode refuses a too-small output buffer");
	memset(&ci, 0, sizeof ci);
	golden_key(ci.server_public);
	char tiny[8];
	TCT_EQ_INT(tc_addr_encode(tiny, sizeof tiny, &ci, NULL), TC_ERR_NOSPACE);
}

int main(void)
{
	test_golden_just_key();
	test_golden_region_id();
	test_real_world_addr();
	test_custom_region_round_trip();
	test_implicit_fields_removed();
	test_optional_keys_round_trip();
	test_malformed_keys();
	test_null_in_arrays();
	test_structural_rejections();
	test_unknown_fields_are_skipped();
	test_limits();
	return tct_report("addr");
}
