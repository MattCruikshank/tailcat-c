/* SPDX-License-Identifier: BSD-3-Clause
 *
 * JSON reader tests.
 *
 * The acceptance and rejection cases are drawn from the shape of JSONTestSuite
 * (Seriot's "Parsing JSON is a Minefield"), which is the standard corpus for
 * the disagreements between parsers: trailing commas, leading zeros, lone
 * surrogates, control characters in strings, and depth.
 */

#include "tc/json.h"

#include "tctest.h"

/* drain reads a whole document, returning the final status. */
static int drain(const char *doc)
{
	tc_json_reader r;
	tc_json_event ev;
	tc_json_reader_init(&r, doc, strlen(doc));
	for (;;) {
		int rc = tc_json_next(&r, &ev);
		if (rc != TC_OK)
			return rc;
		if (ev.type == TC_JSON_END)
			return TC_OK;
	}
}

static void test_accepts(void)
{
	TCT_CASE("accepts well-formed documents");
	static const char *const ok[] = {
		"{}",
		"[]",
		"null",
		"true",
		"false",
		"0",
		"-0",
		"123",
		"-123",
		"1.5",
		"-1.5e10",
		"1E+2",
		"\"\"",
		"\"hello\"",
		"[1,2,3]",
		"{\"a\":1}",
		"{\"a\":1,\"b\":[true,false,null]}",
		"  {  \"a\" : [ 1 , 2 ] }  ",
		"[[[[[1]]]]]",
		"{\"a\":{\"b\":{\"c\":{}}}}",
		"[\"\\u0041\\u00e9\\u20ac\"]",
		"[\"\\ud83d\\udc08\"]", /* a surrogate pair: U+1F408 CAT */
		"[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]",
		"\"\xc3\xa9\"",         /* raw UTF-8 */
		"[1e999]",              /* valid grammar, not an integer */
		"[-9223372036854775808]",
		"[9223372036854775807]",
	};
	for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
		int rc = drain(ok[i]);
		if (rc != TC_OK)
			TCT_FAILF("rejected %s (%s)", ok[i], tc_strerror(rc));
		tct_checks++;
	}
}

static void test_rejects(void)
{
	TCT_CASE("rejects malformed documents");
	static const char *const bad[] = {
		"",
		"   ",
		"{",
		"[",
		"}",
		"]",
		"{\"a\"}",           /* key with no value */
		"{\"a\":}",
		"{a:1}",             /* unquoted key */
		"{'a':1}",           /* single quotes */
		"{\"a\":1,}",        /* trailing comma */
		"[1,]",
		"[,1]",
		"[1 2]",             /* missing comma */
		"[1,,2]",
		"{\"a\":1 \"b\":2}",
		"01",                /* leading zero */
		"-01",
		"+1",
		".5",
		"1.",
		"1e",
		"1e+",
		"--1",
		"tru",
		"nul",
		"TRUE",
		"[1] [2]",           /* two documents */
		"{} garbage",
		"\"unterminated",
		"[\"\\x\"]",         /* invalid escape */
		"[\"\\u12\"]",       /* short \\u */
		"[\"\\uZZZZ\"]",
		"[\"\x01\"]",        /* raw control character */
		"[\"\xc3\"]",        /* truncated UTF-8 */
		"[\"\xc0\xaf\"]",    /* overlong */
		"[\"\xed\xa0\x80\"]", /* surrogate encoded in UTF-8 */
		"[1,2",
		"{\"a\":[}",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		if (drain(bad[i]) == TC_OK)
			TCT_FAILF("accepted malformed input: %s", bad[i]);
		tct_checks++;
	}
}

static void test_depth_limit(void)
{
	TCT_CASE("nesting beyond the limit is refused, not a stack overflow");
	char deep[4096];
	size_t n = 0;
	for (size_t i = 0; i < TC_JSON_MAX_DEPTH + 10; i++)
		deep[n++] = '[';
	for (size_t i = 0; i < TC_JSON_MAX_DEPTH + 10; i++)
		deep[n++] = ']';
	deep[n] = '\0';
	TCT_EQ_INT(drain(deep), TC_ERR_TOOMANY);

	TCT_CASE("nesting exactly at the limit is fine");
	n = 0;
	for (size_t i = 0; i < TC_JSON_MAX_DEPTH; i++)
		deep[n++] = '[';
	for (size_t i = 0; i < TC_JSON_MAX_DEPTH; i++)
		deep[n++] = ']';
	deep[n] = '\0';
	TCT_EQ_INT(drain(deep), TC_OK);
}

static void test_events(void)
{
	TCT_CASE("events arrive in document order");
	tc_json_reader r;
	tc_json_event ev;
	tc_json_reader_init(&r, "{\"a\":1,\"b\":[true,null]}", 23);

	static const tc_json_type want[] = {
		TC_JSON_OBJECT_BEGIN, TC_JSON_KEY,   TC_JSON_NUMBER,
		TC_JSON_KEY,          TC_JSON_ARRAY_BEGIN, TC_JSON_BOOL,
		TC_JSON_NULL,         TC_JSON_ARRAY_END,   TC_JSON_OBJECT_END,
		TC_JSON_END
	};
	for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
		TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
		TCT_EQ_INT(ev.type, want[i]);
	}

	TCT_CASE("integers are reported, fractions are not");
	tc_json_reader_init(&r, "[42,-7,1.5,1e3,99999999999999999999]", 36);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK); /* [ */

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(ev.is_integer);
	TCT_EQ_INT(ev.num, 42);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(ev.is_integer);
	TCT_EQ_INT(ev.num, -7);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(!ev.is_integer);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(!ev.is_integer);

	/* Too large for an int64: reported as non-integer rather than saturated
	 * to something that looks plausible. */
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(!ev.is_integer);
}

static void test_strings(void)
{
	tc_json_reader r;
	tc_json_event ev;
	char buf[64];

	TCT_CASE("escapes are expanded");
	tc_json_reader_init(&r, "\"a\\nb\\tc\\\\d\\\"e\\/f\"", 18);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_STRING);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "a\nb\tc\\d\"e/f");

	TCT_CASE("\\u escapes become UTF-8");
	tc_json_reader_init(&r, "\"\\u0041\\u00e9\\u20ac\"", 20);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "A\xc3\xa9\xe2\x82\xac");

	TCT_CASE("surrogate pairs become one code point");
	tc_json_reader_init(&r, "\"\\ud83d\\udc08\"", 14);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "\xf0\x9f\x90\x88"); /* U+1F408 */

	TCT_CASE("a lone surrogate is refused");
	tc_json_reader_init(&r, "\"\\ud83d\"", 8);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_ERR_INVAL);
	tc_json_reader_init(&r, "\"\\udc08\"", 8);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_ERR_INVAL);

	TCT_CASE("an escaped NUL is refused, since the result is a C string");
	tc_json_reader_init(&r, "\"a\\u0000b\"", 10);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, sizeof buf), TC_ERR_INVAL);

	TCT_CASE("a too-small destination is refused, not truncated");
	tc_json_reader_init(&r, "\"abcdefghij\"", 12);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_string_copy(&ev, buf, 5), TC_ERR_NOSPACE);

	TCT_CASE("key comparison, with and without escapes");
	tc_json_reader_init(&r, "{\"RegionID\":1,\"a\\u0062c\":2}", 27);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK); /* { */
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_key_is(&ev, "RegionID"));
	TCT_TRUE(!tc_json_key_is(&ev, "regionid"));
	TCT_TRUE(!tc_json_key_is(&ev, "RegionI"));
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK); /* 1 */
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_key_is(&ev, "abc"));
}

static void test_skip(void)
{
	TCT_CASE("skipping a member leaves the cursor on the next one");
	/* This is what keeps a parser working when the document gains fields. */
	tc_json_reader r;
	tc_json_event ev;
	static const char kDoc[] =
		"{\"skip\":{\"deep\":[1,{\"x\":[[]]},3]},\"want\":7}";
	tc_json_reader_init(&r, kDoc, sizeof kDoc - 1);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_OBJECT_BEGIN);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_key_is(&ev, "skip"));
	TCT_EQ_INT(tc_json_skip_value(&r), TC_OK);

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_key_is(&ev, "want"));
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(ev.is_integer);
	TCT_EQ_INT(ev.num, 7);

	TCT_CASE("skipping a scalar works too");
	tc_json_reader_init(&r, "[1,2,3]", 7);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(tc_json_skip_value(&r), TC_OK);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(ev.is_integer);
	TCT_EQ_INT(ev.num, 2);

	TCT_CASE("skipping a truncated value reports it");
	tc_json_reader_init(&r, "[[1,2", 5);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_skip_value(&r) != TC_OK);
}

/* A DERP map in the exact shape the real one has, so the reader is exercised
 * on the document it exists for. */
static void test_derpmap_shape(void)
{
	TCT_CASE("walks a DERP map");
	static const char kMap[] =
		"{\"Regions\":{"
		"\"301\":{\"RegionID\":301,\"RegionCode\":\"nyc\","
		"\"RegionName\":\"New York City\",\"Latitude\":40.73,"
		"\"Longitude\":-73.99,\"Nodes\":["
		"{\"Name\":\"301a\",\"RegionID\":301,"
		"\"HostName\":\"tc301a.ipn.dev\","
		"\"IPv4\":\"199.38.181.166\",\"IPv6\":\"2607:f740:f::26b\","
		"\"CanPort80\":true}]},"
		"\"303\":{\"RegionID\":303,\"RegionCode\":\"fra\",\"Nodes\":["
		"{\"HostName\":\"tc303a.ipn.dev\",\"STUNPort\":3478}]}"
		"}}";

	tc_json_reader r;
	tc_json_event ev;
	tc_json_reader_init(&r, kMap, sizeof kMap - 1);

	int regions = 0, nodes = 0;
	char host[128];
	bool saw_nyc = false;

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_OBJECT_BEGIN);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_TRUE(tc_json_key_is(&ev, "Regions"));
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_OBJECT_BEGIN);

	for (;;) {
		TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
		if (ev.type == TC_JSON_OBJECT_END)
			break;
		TCT_EQ_INT(ev.type, TC_JSON_KEY); /* the region number as a string */
		regions++;

		TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
		TCT_EQ_INT(ev.type, TC_JSON_OBJECT_BEGIN);
		for (;;) {
			TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
			if (ev.type == TC_JSON_OBJECT_END)
				break;
			if (tc_json_key_is(&ev, "RegionCode")) {
				TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
				char code[32];
				TCT_EQ_INT(tc_json_string_copy(&ev, code, sizeof code), TC_OK);
				if (strcmp(code, "nyc") == 0)
					saw_nyc = true;
			} else if (tc_json_key_is(&ev, "Nodes")) {
				TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
				TCT_EQ_INT(ev.type, TC_JSON_ARRAY_BEGIN);
				for (;;) {
					TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
					if (ev.type == TC_JSON_ARRAY_END)
						break;
					TCT_EQ_INT(ev.type, TC_JSON_OBJECT_BEGIN);
					nodes++;
					for (;;) {
						TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
						if (ev.type == TC_JSON_OBJECT_END)
							break;
						if (tc_json_key_is(&ev, "HostName")) {
							TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
							TCT_EQ_INT(tc_json_string_copy(&ev, host,
							                               sizeof host),
							           TC_OK);
						} else {
							TCT_EQ_INT(tc_json_skip_value(&r), TC_OK);
						}
					}
				}
			} else {
				/* Latitude, Longitude and anything added later. */
				TCT_EQ_INT(tc_json_skip_value(&r), TC_OK);
			}
		}
	}

	TCT_EQ_INT(regions, 2);
	TCT_EQ_INT(nodes, 2);
	TCT_TRUE(saw_nyc);
	TCT_EQ_STR(host, "tc303a.ipn.dev"); /* the last one walked */

	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_OBJECT_END);
	TCT_EQ_INT(tc_json_next(&r, &ev), TC_OK);
	TCT_EQ_INT(ev.type, TC_JSON_END);
}

static void test_truncation_everywhere(void)
{
	TCT_CASE("every prefix of a valid document is refused, never accepted");
	/* A parser that accepts a prefix would accept a truncated download. */
	static const char kDoc[] =
		"{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"a.b\"}]}}}";
	for (size_t n = 1; n < sizeof kDoc - 1; n++) {
		tc_json_reader r;
		tc_json_event ev;
		tc_json_reader_init(&r, kDoc, n);
		int rc = TC_OK;
		for (;;) {
			rc = tc_json_next(&r, &ev);
			if (rc != TC_OK || ev.type == TC_JSON_END)
				break;
		}
		if (rc == TC_OK)
			TCT_FAILF("accepted a %zu byte prefix", n);
		tct_checks++;
	}
}

int main(void)
{
	test_accepts();
	test_rejects();
	test_depth_limit();
	test_events();
	test_strings();
	test_skip();
	test_derpmap_shape();
	test_truncation_everywhere();
	return tct_report("json");
}
