/* SPDX-License-Identifier: BSD-3-Clause */

#include "tc/base64url.h"
#include "tctest.h"

/* Vectors from RFC 4648 section 10, re-encoded in the URL alphabet with
 * padding stripped (Go's RawURLEncoding). */
static const struct {
	const char *in;
	const char *want;
} kRfc4648[] = {
	{ "",       ""         },
	{ "f",      "Zg"       },
	{ "fo",     "Zm8"      },
	{ "foo",    "Zm9v"     },
	{ "foob",   "Zm9vYg"   },
	{ "fooba",  "Zm9vYmE"  },
	{ "foobar", "Zm9vYmFy" },
};

static void test_roundtrip(void)
{
	TCT_CASE("rfc4648 round trip");
	for (size_t i = 0; i < sizeof kRfc4648 / sizeof kRfc4648[0]; i++) {
		const char *in = kRfc4648[i].in;
		size_t n = strlen(in);
		char enc[64];
		size_t enc_len = 0;

		TCT_EQ_INT(tc_base64url_encode(enc, sizeof enc, (const uint8_t *)in,
		                               n, &enc_len), TC_OK);
		TCT_EQ_STR(enc, kRfc4648[i].want);
		TCT_EQ_INT(enc_len, strlen(kRfc4648[i].want));
		TCT_EQ_INT(tc_base64url_encoded_len(n), strlen(kRfc4648[i].want));

		uint8_t dec[64];
		size_t dec_len = 0;
		TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, enc, enc_len,
		                               &dec_len), TC_OK);
		TCT_EQ_INT(dec_len, n);
		if (n != 0)
			TCT_EQ_MEM(dec, in, n);
	}
}

static void test_url_alphabet(void)
{
	TCT_CASE("url alphabet uses - and _");
	/* 0xfb 0xff encodes to "-_" in the URL alphabet and "+/" in standard. */
	const uint8_t in[] = { 0xfb, 0xff };
	char enc[16];
	TCT_EQ_INT(tc_base64url_encode(enc, sizeof enc, in, sizeof in, NULL), TC_OK);
	TCT_EQ_STR(enc, "-_8");

	uint8_t dec[16];
	size_t dec_len = 0;
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "-_8", 3, &dec_len), TC_OK);
	TCT_EQ_INT(dec_len, 2);
	TCT_EQ_MEM(dec, in, 2);
}

static void test_decode_rejects(void)
{
	uint8_t dec[64];
	size_t dec_len = 0;

	TCT_CASE("rejects padding");
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Zg==", 4, &dec_len),
	           TC_ERR_INVAL);

	TCT_CASE("rejects standard-alphabet chars");
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "+/8", 3, &dec_len),
	           TC_ERR_INVAL);

	TCT_CASE("rejects dangling single char");
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Z", 1, &dec_len),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Zm9vZ", 5, &dec_len),
	           TC_ERR_INVAL);

	TCT_CASE("rejects other junk");
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Zm9v!", 5, &dec_len),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Zm 9v", 5, &dec_len),
	           TC_ERR_INVAL);
}

static void test_decode_skips_newlines(void)
{
	TCT_CASE("skips CR and LF like Go");
	uint8_t dec[64];
	size_t dec_len = 0;
	TCT_EQ_INT(tc_base64url_decode(dec, sizeof dec, "Zm9v\r\nYmFy", 10,
	                               &dec_len), TC_OK);
	TCT_EQ_INT(dec_len, 6);
	TCT_EQ_MEM(dec, "foobar", 6);
}

static void test_bounds(void)
{
	TCT_CASE("encode respects capacity");
	char small[4];
	/* "foobar" needs 8 chars + NUL; 4 is not enough. */
	TCT_EQ_INT(tc_base64url_encode(small, sizeof small,
	                               (const uint8_t *)"foobar", 6, NULL),
	           TC_ERR_NOSPACE);

	TCT_CASE("encode needs room for the NUL");
	char exact[3];
	/* "fo" -> "Zm8" is 3 chars, so 3 bytes is one short. */
	TCT_EQ_INT(tc_base64url_encode(exact, sizeof exact,
	                               (const uint8_t *)"fo", 2, NULL),
	           TC_ERR_NOSPACE);
	char fits[4];
	TCT_EQ_INT(tc_base64url_encode(fits, sizeof fits,
	                               (const uint8_t *)"fo", 2, NULL), TC_OK);
	TCT_EQ_STR(fits, "Zm8");

	TCT_CASE("decode respects capacity");
	uint8_t tiny[2];
	size_t dec_len = 0;
	TCT_EQ_INT(tc_base64url_decode(tiny, sizeof tiny, "Zm9vYmFy", 8, &dec_len),
	           TC_ERR_NOSPACE);

	TCT_CASE("decoded_max is an upper bound");
	for (size_t n = 0; n < 64; n++) {
		uint8_t buf[64];
		char enc[128];
		size_t enc_len = 0, dec_len2 = 0;
		memset(buf, (int)n, n);
		TCT_EQ_INT(tc_base64url_encode(enc, sizeof enc, buf, n, &enc_len),
		           TC_OK);
		TCT_TRUE(tc_base64url_decoded_max(enc_len) >= n);
		uint8_t back[64];
		TCT_EQ_INT(tc_base64url_decode(back, sizeof back, enc, enc_len,
		                               &dec_len2), TC_OK);
		TCT_EQ_INT(dec_len2, n);
		if (n != 0)
			TCT_EQ_MEM(back, buf, n);
	}
}

int main(void)
{
	test_roundtrip();
	test_url_alphabet();
	test_decode_rejects();
	test_decode_skips_newlines();
	test_bounds();
	return tct_report("base64url");
}
