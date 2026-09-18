/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Saved identity files.
 *
 * The two samples below were produced by the real `tailcat genkey`, copied
 * verbatim. That matters more than a round-trip test would: a format we
 * invented and then parsed back would pass its own tests while being unable
 * to read anything a user actually has.
 */

#include "tc/keyfile.h"

#include "tctest.h"

/* Written by: tailcat genkey --key test.private.json --region 301 */
static const char kServerKey[] =
	"{\n"
	"\t\"Private\": \"privkey:08f692071cc7aad5c45b1342c8f3e9da150eacd2d633152be14ca826df447059\",\n"
	"\t\"Public\": {\n"
	"\t\t\"ServerPublic\": \"nodekey:425e445df8535e98161ec38073deca582713f938682b3c13f561ce5a0c2bbe70\",\n"
	"\t\t\"ServerDiscoPublic\": \"discokey:21c5ed7addf9c22b38be2289a51e02a415dfa992665243ce56426fe721570b64\",\n"
	"\t\t\"PresharedKey\": \"psk:c157b77053ff4df6e854cd83fe7fb0f20b25136666164467e14247116ca6fab2\",\n"
	"\t\t\"RegionID\": 301\n"
	"\t}\n"
	"}";

/* Written by: tailcat genkey --key c.private.json --client */
static const char kClientKey[] =
	"{\n"
	"\t\"Private\": \"privkey:38e9dcfae92422eb9867c6bf9667b813e9bcec210ece4bc6bec9f96cef94964a\",\n"
	"\t\"Public\": {\n"
	"\t\t\"ServerPublic\": \"nodekey:6140b3ec448cf4afc7f121fd8076655eed5c4ef3e0455255f3252c3d7935fc00\",\n"
	"\t\t\"ServerDiscoPublic\": \"discokey:782fac692116bc20438239fd8cd306e8f37d066c862347156245debb61fd3539\",\n"
	"\t\t\"PresharedKey\": \"psk:872692ecbfe116d1d31686c670797a25d11184a4b91f5befe536bcb187743de3\"\n"
	"\t}\n"
	"}";

/* Written by: tailcat genkey --key h.private.json --region=derp9.example.com
 *
 * The form for a relay the published DERP map does not list. There is no
 * RegionID anywhere in it -- the hostname *is* the reference -- so a reader
 * that treated a missing ID as "none configured" would throw the relay away
 * and go and measure a different one at startup, which is bug 45's shape.
 *
 * Note the explicit zeroes and empty strings: Go's encoder writes every
 * field. Ours elides them, so this also checks that a file with them present
 * reads the same as one without. */
static const char kHostRegionKey[] =
	"{\n"
	"\t\"Private\": \"privkey:90b628c0a658dbd58133c0d1d9c927d3dc1e0788f49417d9c55de1667de3597c\",\n"
	"\t\"Public\": {\n"
	"\t\t\"ServerPublic\": \"nodekey:64435af4fe391b9d6731a9a246b197904a03c7773cdb219cbe82adfcb4fea175\",\n"
	"\t\t\"ServerDiscoPublic\": \"discokey:3ac2dc87afa3e1574a64ac3a2c72ff48ec616ad0d35399d3ad02894d9466b971\",\n"
	"\t\t\"PresharedKey\": \"psk:a0821f7c6949a715a8ab831cb7edb05b61acad36cc5a2a24aca64aca64977017\",\n"
	"\t\t\"Region\": [\n"
	"\t\t\t{\n"
	"\t\t\t\t\"RegionID\": 0,\n"
	"\t\t\t\t\"RegionCode\": \"\",\n"
	"\t\t\t\t\"RegionName\": \"\",\n"
	"\t\t\t\t\"Nodes\": [\n"
	"\t\t\t\t\t{\n"
	"\t\t\t\t\t\t\"Name\": \"\",\n"
	"\t\t\t\t\t\t\"RegionID\": 0,\n"
	"\t\t\t\t\t\t\"HostName\": \"derp9.example.com\"\n"
	"\t\t\t\t\t}\n"
	"\t\t\t\t]\n"
	"\t\t\t}\n"
	"\t\t]\n"
	"\t}\n"
	"}";

static void test_reads_a_custom_relay_key(void)
{
	TCT_CASE("a key naming relay hostnames keeps them, and has no region ID");
	static tc_keyfile k;
	TCT_EQ_INT(tc_keyfile_parse(&k, kHostRegionKey, sizeof kHostRegionKey - 1),
	           TC_OK);
	TCT_TRUE(k.has_private);
	TCT_EQ_INT((int)k.pub.num_regions, 1);
	TCT_EQ_INT((int)k.pub.regions[0].num_nodes, 1);
	TCT_EQ_STR(k.pub.regions[0].nodes[0].hostname, "derp9.example.com");

	/* The absent ID is the load-bearing part. `serve` measures a relay only
	 * when the key names none at all; if this came back as "no region" it
	 * would go and pick a different relay and publish an address for a third
	 * one. */
	TCT_EQ_INT((int)k.pub.region_id, 0);
	TCT_EQ_INT((int)k.pub.regions[0].region_id, 0);
}

static void test_reads_a_real_server_key(void)
{
	TCT_CASE("a key written by the real genkey loads");
	static tc_keyfile k;
	TCT_EQ_INT(tc_keyfile_parse(&k, kServerKey, sizeof kServerKey - 1),
	           TC_OK);
	TCT_TRUE(k.has_private);
	TCT_TRUE(k.pub.has_disco_public);
	TCT_TRUE(k.pub.has_preshared_key);
	TCT_EQ_INT((int)k.pub.region_id, 301);

	char s[128];
	TCT_EQ_INT(tc_key_format_hex(s, sizeof s, "nodekey", k.pub.server_public),
	           TC_OK);
	TCT_EQ_STR(s, "nodekey:425e445df8535e98161ec38073deca582713f938682b3c"
	              "13f561ce5a0c2bbe70");

	TCT_CASE("the disco key it names is the one the private key derives");
	/* Checked rather than trusted: it is a derived value, so a file naming a
	 * different one is corrupt or lying, and the parser says so. */
	TCT_EQ_INT(tc_key_format_hex(s, sizeof s, "discokey",
	                             k.pub.server_disco_public),
	           TC_OK);
	TCT_EQ_STR(s, "discokey:21c5ed7addf9c22b38be2289a51e02a415dfa992665243"
	              "ce56426fe721570b64");
}

static void test_reads_a_real_client_key(void)
{
	TCT_CASE("a client key has no region and still loads");
	static tc_keyfile k;
	TCT_EQ_INT(tc_keyfile_parse(&k, kClientKey, sizeof kClientKey - 1),
	           TC_OK);
	TCT_EQ_INT((int)k.pub.region_id, 0);
	TCT_TRUE(k.pub.has_preshared_key);
}

static void test_round_trips_byte_for_byte(void)
{
	TCT_CASE("re-writing a real key reproduces it exactly");
	/* The strongest check available without running Go: our output has to be
	 * what upstream would have written, tabs, order and all. A file that
	 * merely parses back into the same values would still be a file upstream
	 * users could not diff against theirs. */
	static const char *const samples[] = { kServerKey, kClientKey };
	for (size_t i = 0; i < 2; i++) {
		static tc_keyfile k;
		TCT_EQ_INT(tc_keyfile_parse(&k, samples[i], strlen(samples[i])),
		           TC_OK);

		static char out[2048];
		size_t n = 0;
		TCT_EQ_INT(tc_keyfile_format(out, sizeof out, &n, &k), TC_OK);

		/* genkey's file ends with a newline that MarshalIndent does not add;
		 * compare the JSON itself. */
		size_t want = strlen(samples[i]);
		if (n > 0 && out[n - 1] == '\n')
			n--;
		if (n != want || memcmp(out, samples[i], want) != 0)
			TCT_FAILF("sample %zu round-tripped differently:\n--- got ---\n"
			          "%.*s\n--- want ---\n%s",
			          i, (int)n, out, samples[i]);
		tct_checks++;
	}
}

static void test_generate(void)
{
	TCT_CASE("a generated key is self-consistent");
	static tc_keyfile k;
	TCT_EQ_INT(tc_keyfile_generate(&k, true, 301), TC_OK);
	TCT_TRUE(k.has_private);
	TCT_TRUE(k.pub.has_preshared_key);
	TCT_EQ_INT((int)k.pub.region_id, 301);

	static char out[2048];
	size_t n = 0;
	TCT_EQ_INT(tc_keyfile_format(out, sizeof out, &n, &k), TC_OK);

	/* Which is to say: the parser's own consistency checks pass on it. */
	static tc_keyfile back;
	TCT_EQ_INT(tc_keyfile_parse(&back, out, n), TC_OK);
	TCT_EQ_MEM(back.private_key, k.private_key, 32);
	TCT_EQ_MEM(back.pub.server_public, k.pub.server_public, 32);
	TCT_EQ_MEM(back.pub.preshared_key, k.pub.preshared_key, 32);

	TCT_CASE("two generated keys differ");
	static tc_keyfile k2;
	TCT_EQ_INT(tc_keyfile_generate(&k2, true, 301), TC_OK);
	TCT_TRUE(memcmp(k.private_key, k2.private_key, 32) != 0);
	TCT_TRUE(memcmp(k.pub.preshared_key, k2.pub.preshared_key, 32) != 0);

	TCT_CASE("without a pre-shared key, none is written");
	TCT_EQ_INT(tc_keyfile_generate(&k, false, 0), TC_OK);
	TCT_TRUE(!k.pub.has_preshared_key);
	TCT_EQ_INT(tc_keyfile_format(out, sizeof out, &n, &k), TC_OK);
	TCT_TRUE(strstr(out, "PresharedKey") == NULL);
	TCT_TRUE(strstr(out, "RegionID") == NULL);
}

static void test_rejects(void)
{
	static tc_keyfile k;

	TCT_CASE("a key whose public half does not match its private is refused");
	/* It would produce an address nobody can reach, failing much later and
	 * much less clearly than here. */
	static char bad[2048];
	(void)snprintf(bad, sizeof bad, "%s", kServerKey);
	char *pubhex = strstr(bad, "nodekey:");
	TCT_TRUE(pubhex != NULL);
	pubhex[8] ^= 1; /* flip a hex digit of ServerPublic */
	TCT_EQ_INT(tc_keyfile_parse(&k, bad, strlen(bad)), TC_ERR_INVAL);
	TCT_TRUE(strstr(tc_keyfile_error_string(), "ServerPublic") != NULL);

	TCT_CASE("a mismatched disco key is refused too");
	(void)snprintf(bad, sizeof bad, "%s", kServerKey);
	char *discohex = strstr(bad, "discokey:");
	TCT_TRUE(discohex != NULL);
	discohex[9] ^= 1;
	TCT_EQ_INT(tc_keyfile_parse(&k, bad, strlen(bad)), TC_ERR_INVAL);

	TCT_CASE("the type prefixes are required, not decoration");
	/* Without them the same 32 bytes could be read as a node key where a
	 * disco key belongs. */
	static const char *const nopfx =
		"{\"Private\":\"08f692071cc7aad5c45b1342c8f3e9da150eacd2d633152be1"
		"4ca826df447059\",\"Public\":{\"ServerPublic\":\"x\"}}";
	TCT_EQ_INT(tc_keyfile_parse(&k, nopfx, strlen(nopfx)), TC_ERR_INVAL);

	TCT_CASE("malformed files are refused");
	static const char *const bads[] = {
		"",
		"{}",
		"[]",
		"null",
		"{\"Private\":\"privkey:00\"}",
		"{\"Public\":{}}",
		"{\"Private\":\"privkey:zz96 92071cc7aad5c45b1342c8f3e9da150eacd2d6"
		"33152be14ca826df447059\",\"Public\":{}}",
		"{\"Private\":123,\"Public\":{}}",
	};
	for (size_t i = 0; i < sizeof bads / sizeof bads[0]; i++) {
		if (tc_keyfile_parse(&k, bads[i], strlen(bads[i])) == TC_OK)
			TCT_FAILF("accepted \"%.40s\"", bads[i]);
		tct_checks++;
	}

	TCT_CASE("every prefix of a real key is refused");
	for (size_t n = 1; n < sizeof kServerKey - 1; n += 11) {
		if (tc_keyfile_parse(&k, kServerKey, n) == TC_OK)
			TCT_FAILF("accepted a %zu byte prefix", n);
		tct_checks++;
	}

	TCT_CASE("unknown members are ignored, so a future field still loads");
	static char future[2048];
	(void)snprintf(future, sizeof future,
	               "{\"Something\":[1,2,{\"a\":null}],%s",
	               kServerKey + 1);
	TCT_EQ_INT(tc_keyfile_parse(&k, future, strlen(future)), TC_OK);
	TCT_EQ_INT((int)k.pub.region_id, 301);

	TCT_CASE("null arguments and short buffers are refused");
	TCT_EQ_INT(tc_keyfile_parse(NULL, kServerKey, 10), TC_ERR_INVAL);
	TCT_EQ_INT(tc_keyfile_parse(&k, NULL, 10), TC_ERR_INVAL);
	size_t n = 0;
	char tiny[16];
	TCT_EQ_INT(tc_keyfile_parse(&k, kServerKey, sizeof kServerKey - 1),
	           TC_OK);
	TCT_EQ_INT(tc_keyfile_format(tiny, sizeof tiny, &n, &k), TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_keyfile_format(NULL, 100, &n, &k), TC_ERR_INVAL);
	TCT_EQ_INT(tc_keyfile_generate(NULL, true, 0), TC_ERR_INVAL);
	char small[8];
	TCT_EQ_INT(tc_key_format_hex(small, sizeof small, "nodekey",
	                             k.pub.server_public),
	           TC_ERR_NOSPACE);
}

int main(void)
{
	test_reads_a_real_server_key();
	test_reads_a_custom_relay_key();
	test_reads_a_real_client_key();
	test_round_trips_byte_for_byte();
	test_generate();
	test_rejects();
	return tct_report("keyfile");
}
