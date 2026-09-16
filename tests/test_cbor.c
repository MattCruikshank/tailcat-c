/* SPDX-License-Identifier: BSD-3-Clause */

#include "tc/cbor.h"
#include "tctest.h"

#define RD(r, lit)                                                            \
	tc_cbor_reader_init(&(r), (const uint8_t *)(lit), sizeof(lit) - 1)

/* ---- RFC 8949 Appendix A integer vectors ----------------------------- */

static void test_int_vectors(void)
{
	static const struct {
		const char *enc;
		size_t enc_len;
		int64_t val;
	} kVec[] = {
		{ "\x00", 1, 0 },
		{ "\x01", 1, 1 },
		{ "\x0a", 1, 10 },
		{ "\x17", 1, 23 },
		{ "\x18\x18", 2, 24 },
		{ "\x18\x64", 2, 100 },
		{ "\x19\x03\xe8", 3, 1000 },
		{ "\x1a\x00\x0f\x42\x40", 5, 1000000 },
		{ "\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00", 9, 1000000000000LL },
		{ "\x20", 1, -1 },
		{ "\x29", 1, -10 },
		{ "\x38\x63", 2, -100 },
		{ "\x39\x03\xe7", 3, -1000 },
	};

	TCT_CASE("rfc8949 integer decode");
	for (size_t i = 0; i < sizeof kVec / sizeof kVec[0]; i++) {
		tc_cbor_reader r;
		int64_t got = 0;
		tc_cbor_reader_init(&r, (const uint8_t *)kVec[i].enc, kVec[i].enc_len);
		TCT_EQ_INT(tc_cbor_read_int(&r, &got), TC_OK);
		TCT_EQ_INT(got, kVec[i].val);
		TCT_EQ_INT(tc_cbor_remaining(&r), 0);
	}

	TCT_CASE("rfc8949 integer encode is shortest form");
	for (size_t i = 0; i < sizeof kVec / sizeof kVec[0]; i++) {
		uint8_t buf[16];
		tc_cbor_writer w;
		size_t n = 0;
		tc_cbor_writer_init(&w, buf, sizeof buf);
		tc_cbor_write_int(&w, kVec[i].val);
		TCT_EQ_INT(tc_cbor_writer_finish(&w, &n), TC_OK);
		TCT_EQ_INT(n, kVec[i].enc_len);
		TCT_EQ_MEM(buf, kVec[i].enc, kVec[i].enc_len);
	}
}

static void test_int_extremes(void)
{
	TCT_CASE("int64 extremes round trip");
	const int64_t vals[] = { INT64_MAX, INT64_MIN, -1, 0 };
	for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
		uint8_t buf[16];
		tc_cbor_writer w;
		size_t n = 0;
		tc_cbor_writer_init(&w, buf, sizeof buf);
		tc_cbor_write_int(&w, vals[i]);
		TCT_EQ_INT(tc_cbor_writer_finish(&w, &n), TC_OK);

		tc_cbor_reader r;
		int64_t got = 0;
		tc_cbor_reader_init(&r, buf, n);
		TCT_EQ_INT(tc_cbor_read_int(&r, &got), TC_OK);
		TCT_EQ_INT(got, vals[i]);
	}

	TCT_CASE("uint64 above int64 max is out of range");
	tc_cbor_reader r;
	int64_t got = 0;
	/* 0x1b ffffffffffffffff */
	RD(r, "\x1b\xff\xff\xff\xff\xff\xff\xff\xff");
	TCT_EQ_INT(tc_cbor_read_int(&r, &got), TC_ERR_RANGE);
}

/* ---- Strictness: everything we deliberately refuse ------------------- */

static void test_rejects(void)
{
	tc_cbor_reader r;
	tc_cbor_item it;

	TCT_CASE("rejects indefinite-length byte string");
	RD(r, "\x5f\x41\x61\xff");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);

	TCT_CASE("rejects indefinite-length array");
	RD(r, "\x9f\x01\x02\xff");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);

	TCT_CASE("rejects tags");
	RD(r, "\xc0\x01");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);

	TCT_CASE("rejects reserved additional info 28..30");
	RD(r, "\x1c");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_INVAL);
	RD(r, "\x1d");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_INVAL);
	RD(r, "\x1e");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_INVAL);

	TCT_CASE("rejects floats");
	RD(r, "\xf9\x3c\x00"); /* half 1.0 */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);
	RD(r, "\xfa\x47\xc3\x50\x00"); /* single */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);
	RD(r, "\xfb\x40\x09\x21\xfb\x54\x44\x2d\x18"); /* double */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);

	TCT_CASE("rejects unassigned simple values");
	RD(r, "\xf0"); /* simple(16) */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_UNSUPPORTED);

	TCT_CASE("accepts false/true/null/undefined");
	RD(r, "\xf4\xf5\xf6\xf7");
	for (unsigned want = TC_CBOR_FALSE; want <= TC_CBOR_UNDEFINED; want++) {
		TCT_EQ_INT(tc_cbor_read(&r, &it), TC_OK);
		TCT_EQ_INT(it.type, TC_CBOR_SIMPLE);
		TCT_EQ_INT(it.val, want);
	}

	TCT_CASE("rejects truncated head");
	RD(r, "\x19\x03"); /* uint16 with only one byte */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("rejects truncated payload");
	RD(r, "\x43\x01\x02"); /* bytes(3) with 2 bytes */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("rejects empty input");
	tc_cbor_reader_init(&r, NULL, 0);
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);
}

/* A malicious address can claim an enormous element count. read_item must
 * reject it up front rather than let it drive later arithmetic. */
static void test_container_count_bounds(void)
{
	tc_cbor_reader r;
	tc_cbor_item it;

	TCT_CASE("rejects absurd array count");
	RD(r, "\x9b\xff\xff\xff\xff\xff\xff\xff\xff");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("rejects absurd map count");
	RD(r, "\xbb\xff\xff\xff\xff\xff\xff\xff\xff");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("rejects array longer than the buffer");
	RD(r, "\x98\x20\x01\x02"); /* array(32), only 2 elements present */
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("rejects map claiming more pairs than bytes allow");
	RD(r, "\xb8\x20\x01\x02");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_ERR_TRUNC);

	TCT_CASE("array count exactly at the limit is accepted");
	RD(r, "\x83\x01\x02\x03");
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_OK);
	TCT_EQ_INT(it.type, TC_CBOR_ARRAY);
	TCT_EQ_INT(it.val, 3);
}

/* ---- skip ------------------------------------------------------------ */

static void test_skip(void)
{
	tc_cbor_reader r;
	int64_t v = 0;

	TCT_CASE("skips a scalar");
	RD(r, "\x01\x02");
	TCT_EQ_INT(tc_cbor_skip(&r), TC_OK);
	TCT_EQ_INT(tc_cbor_read_int(&r, &v), TC_OK);
	TCT_EQ_INT(v, 2);

	TCT_CASE("skips a nested array, landing on the next item");
	/* [1, [2, 3], {4: 5}] followed by 9 */
	RD(r, "\x83\x01\x82\x02\x03\xa1\x04\x05\x09");
	TCT_EQ_INT(tc_cbor_skip(&r), TC_OK);
	TCT_EQ_INT(tc_cbor_read_int(&r, &v), TC_OK);
	TCT_EQ_INT(v, 9);

	TCT_CASE("skips a map value that is itself a map");
	/* {1: {2: 3}} then 7 */
	RD(r, "\xa1\x01\xa1\x02\x03\x07");
	TCT_EQ_INT(tc_cbor_skip(&r), TC_OK);
	TCT_EQ_INT(tc_cbor_read_int(&r, &v), TC_OK);
	TCT_EQ_INT(v, 7);

	TCT_CASE("skip reports truncation");
	RD(r, "\x83\x01\x02"); /* array(3) with 2 elements */
	TCT_TRUE(tc_cbor_skip(&r) != TC_OK);

	TCT_CASE("deep nesting does not blow the stack");
	/* 2000 nested 1-element arrays, then a 0. */
	static uint8_t deep[2001];
	for (size_t i = 0; i < 2000; i++)
		deep[i] = 0x81;
	deep[2000] = 0x00;
	tc_cbor_reader_init(&r, deep, sizeof deep);
	TCT_EQ_INT(tc_cbor_skip(&r), TC_OK);
	TCT_EQ_INT(tc_cbor_remaining(&r), 0);
}

/* ---- strings --------------------------------------------------------- */

static void test_strings(void)
{
	tc_cbor_reader r;
	char buf[32];
	uint8_t key[32];

	TCT_CASE("reads text");
	RD(r, "\x65hello");
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "hello");

	TCT_CASE("text too long for the destination");
	RD(r, "\x65hello");
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, 5), TC_ERR_NOSPACE);
	RD(r, "\x65hello");
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, 6), TC_OK);

	TCT_CASE("rejects embedded NUL in text");
	RD(r, "\x63" "a\x00" "b");
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_ERR_INVAL);

	TCT_CASE("rejects invalid UTF-8 text");
	RD(r, "\x62\xc3\x28"); /* bad continuation */
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_ERR_INVAL);
	RD(r, "\x62\xed\xa0"); /* start of a surrogate */
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_ERR_INVAL);
	RD(r, "\x62\xc0\xaf"); /* overlong slash */
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_ERR_INVAL);

	TCT_CASE("accepts valid multibyte UTF-8");
	RD(r, "\x64\xf0\x9f\x90\x88"); /* U+1F408 CAT */
	TCT_EQ_INT(tc_cbor_read_text(&r, buf, sizeof buf), TC_OK);
	TCT_EQ_INT(strlen(buf), 4);

	TCT_CASE("byte strings are not UTF-8 checked");
	RD(r, "\x42\xc3\x28");
	tc_cbor_item it;
	TCT_EQ_INT(tc_cbor_read(&r, &it), TC_OK);
	TCT_EQ_INT(it.type, TC_CBOR_BYTES);
	TCT_EQ_INT(it.data_len, 2);

	TCT_CASE("read_bytes_exact enforces the length");
	RD(r, "\x43\x01\x02\x03");
	TCT_EQ_INT(tc_cbor_read_bytes_exact(&r, key, 32), TC_ERR_INVAL);
	RD(r, "\x43\x01\x02\x03");
	TCT_EQ_INT(tc_cbor_read_bytes_exact(&r, key, 3), TC_OK);
	TCT_EQ_MEM(key, "\x01\x02\x03", 3);

	TCT_CASE("read_bytes_exact rejects a text string");
	RD(r, "\x63" "abc");
	TCT_EQ_INT(tc_cbor_read_bytes_exact(&r, key, 3), TC_ERR_INVAL);
}

static void test_utf8_validator(void)
{
	TCT_CASE("utf8 validator");
	TCT_TRUE(tc_utf8_valid((const uint8_t *)"", 0));
	TCT_TRUE(tc_utf8_valid((const uint8_t *)"ascii", 5));
	TCT_TRUE(tc_utf8_valid((const uint8_t *)"\xc2\xa9", 2));         /* © */
	TCT_TRUE(tc_utf8_valid((const uint8_t *)"\xe2\x82\xac", 3));     /* € */
	TCT_TRUE(tc_utf8_valid((const uint8_t *)"\xf0\x9f\x90\x88", 4)); /* 🐈 */

	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\x80", 1));         /* stray cont */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xc2", 1));         /* truncated */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xc0\xaf", 2));     /* overlong */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xe0\x80\xaf", 3)); /* overlong */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xed\xa0\x80", 3)); /* surrogate */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xf5\x80\x80\x80", 4)); /* >10FFFF */
	TCT_TRUE(!tc_utf8_valid((const uint8_t *)"\xfe", 1));         /* invalid */
}

/* ---- writer ---------------------------------------------------------- */

static void test_writer(void)
{
	TCT_CASE("writer builds a map");
	uint8_t buf[64];
	tc_cbor_writer w;
	size_t n = 0;
	tc_cbor_writer_init(&w, buf, sizeof buf);
	tc_cbor_write_map_header(&w, 2);
	tc_cbor_write_text(&w, "a", 1);
	tc_cbor_write_uint(&w, 1);
	tc_cbor_write_text(&w, "b", 1);
	tc_cbor_write_array_header(&w, 2);
	tc_cbor_write_uint(&w, 2);
	tc_cbor_write_uint(&w, 3);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &n), TC_OK);
	/* {"a": 1, "b": [2, 3]} from RFC 8949 Appendix A. */
	TCT_EQ_INT(n, 9);
	TCT_EQ_MEM(buf, "\xa2\x61\x61\x01\x61\x62\x82\x02\x03", 9);

	TCT_CASE("writer error is sticky and reported once");
	uint8_t tiny[3];
	tc_cbor_writer_init(&w, tiny, sizeof tiny);
	tc_cbor_write_bytes(&w, (const uint8_t *)"aaaaaaaa", 8);
	tc_cbor_write_uint(&w, 1); /* must not write past the end */
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &n), TC_ERR_NOSPACE);

	TCT_CASE("zero-capacity writer never writes");
	tc_cbor_writer_init(&w, NULL, 0);
	tc_cbor_write_uint(&w, 1);
	TCT_EQ_INT(tc_cbor_writer_finish(&w, &n), TC_ERR_NOSPACE);
}

static void test_peek(void)
{
	TCT_CASE("peek does not consume");
	tc_cbor_reader r;
	tc_cbor_item it;
	int64_t v = 0;
	RD(r, "\x09");
	TCT_EQ_INT(tc_cbor_peek(&r, &it), TC_OK);
	TCT_EQ_INT(it.type, TC_CBOR_UINT);
	TCT_EQ_INT(it.val, 9);
	TCT_EQ_INT(tc_cbor_remaining(&r), 1);
	TCT_EQ_INT(tc_cbor_read_int(&r, &v), TC_OK);
	TCT_EQ_INT(v, 9);
	TCT_EQ_INT(tc_cbor_remaining(&r), 0);
}

int main(void)
{
	test_int_vectors();
	test_int_extremes();
	test_rejects();
	test_container_count_bounds();
	test_skip();
	test_strings();
	test_utf8_validator();
	test_writer();
	test_peek();
	return tct_report("cbor");
}
