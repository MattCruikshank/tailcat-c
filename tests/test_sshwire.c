/* SPDX-License-Identifier: BSD-3-Clause
 *
 * RFC 4251 section 5 data types.
 *
 * Two things are being checked here and they are worth separating.
 *
 * The first is that our encoder agrees with golang.org/x/crypto/ssh, byte for
 * byte, on every type the subset uses. That is what tests/ssh_vectors.h is
 * for: the values in it are that library's output, not a transcription of the
 * RFC, because these encodings are what the exchange hash is computed over
 * and a disagreement in any of them surfaces only as "hash mismatch".
 *
 * The second is that the *decoder* refuses what it should. That half has no
 * vectors, because a library that only ever emits well-formed input cannot
 * demonstrate what happens to malformed input -- and malformed input is the
 * entire threat model for this file. Every field an attacker sends is read
 * through this reader. So the refusals are enumerated by hand, and the sticky
 * error flag is checked to actually be sticky, since the whole safety
 * argument rests on one check at the end being enough.
 */

#include "tc/sshwire.h"

#include "tc/ed25519.h"

#include "ssh_vectors.h"
#include "tctest.h"

#include <string.h>

/* ---- hex helpers ------------------------------------------------------ */

static int unhex1(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* unhex decodes into out, returning the length, or SIZE_MAX on bad input. */
static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = strlen(s);
	if ((n & 1) != 0 || n / 2 > cap)
		return SIZE_MAX;
	for (size_t i = 0; i < n; i += 2) {
		int hi = unhex1(s[i]), lo = unhex1(s[i + 1]);
		if (hi < 0 || lo < 0)
			return SIZE_MAX;
		out[i / 2] = (uint8_t)(hi << 4 | lo);
	}
	return n / 2;
}

#define BUFSZ 2048

/* check_encoding compares a writer's output against a hex vector. */
static void check_encoding(const char *name, const tc_ssh_wbuf *w,
                           const char *want_hex)
{
	uint8_t want[BUFSZ];
	size_t want_len = unhex(want_hex, want, sizeof want);
	if (want_len == SIZE_MAX) {
		TCT_FAILF("%s: unusable vector", name);
		return;
	}
	if (!tc_ssh_wbuf_ok(w)) {
		TCT_FAILF("%s: the writer overflowed", name);
		return;
	}
	size_t got_len = tc_ssh_wbuf_len(w);
	if (got_len != want_len) {
		TCT_FAILF("%s: encoded %zu bytes, want %zu", name, got_len, want_len);
		return;
	}
	tct_checks++;
	if (memcmp(w->buf, want, want_len) != 0) {
		TCT_FAILF("%s: bytes differ", name);
		tct_hexdump("  got ", w->buf, got_len);
		tct_hexdump("  want", want, want_len);
	}
}

/* ---- encoding, against x/crypto/ssh ----------------------------------- */

static void test_strings(void)
{
	TCT_CASE("strings encode as Go encodes them");
	for (size_t i = 0; i < sizeof kSshStringVectors / sizeof *kSshStringVectors;
	     i++) {
		const tc_ssh_vector *v = &kSshStringVectors[i];
		uint8_t in[BUFSZ];
		size_t in_len = unhex(v->in, in, sizeof in);
		if (in_len == SIZE_MAX) {
			TCT_FAILF("%s: unusable input", v->name);
			continue;
		}
		uint8_t out[BUFSZ];
		tc_ssh_wbuf w;
		tc_ssh_wbuf_init(&w, out, sizeof out);
		tc_ssh_put_string(&w, in, in_len);
		check_encoding(v->name, &w, v->want);
	}

	TCT_CASE("and decode back to what went in");
	for (size_t i = 0; i < sizeof kSshStringVectors / sizeof *kSshStringVectors;
	     i++) {
		const tc_ssh_vector *v = &kSshStringVectors[i];
		uint8_t enc[BUFSZ];
		size_t enc_len = unhex(v->want, enc, sizeof enc);
		uint8_t in[BUFSZ];
		size_t in_len = unhex(v->in, in, sizeof in);
		if (enc_len == SIZE_MAX || in_len == SIZE_MAX)
			continue;

		tc_ssh_rbuf r;
		tc_ssh_rbuf_init(&r, enc, enc_len);
		size_t got_len = 0;
		const uint8_t *got = tc_ssh_get_string(&r, SIZE_MAX, &got_len);
		if (got == NULL || !tc_ssh_rbuf_ok(&r)) {
			TCT_FAILF("%s: would not decode", v->name);
			continue;
		}
		tct_checks++;
		if (got_len != in_len || (in_len > 0 && memcmp(got, in, in_len) != 0))
			TCT_FAILF("%s: round trip changed the bytes", v->name);
		TCT_EQ_INT((int)tc_ssh_rbuf_remaining(&r), 0);
	}
}

static void test_mpints(void)
{
	TCT_CASE("mpints encode in minimal two's-complement form");
	for (size_t i = 0; i < sizeof kSshMpintVectors / sizeof *kSshMpintVectors;
	     i++) {
		const tc_ssh_vector *v = &kSshMpintVectors[i];
		uint8_t in[BUFSZ];
		size_t in_len = unhex(v->in, in, sizeof in);
		if (in_len == SIZE_MAX) {
			TCT_FAILF("%s: unusable input", v->name);
			continue;
		}
		uint8_t out[BUFSZ];
		tc_ssh_wbuf w;
		tc_ssh_wbuf_init(&w, out, sizeof out);
		tc_ssh_put_mpint(&w, in, in_len);
		check_encoding(v->name, &w, v->want);
	}

	TCT_CASE("and decode to the same fixed-width value");
	for (size_t i = 0; i < sizeof kSshMpintVectors / sizeof *kSshMpintVectors;
	     i++) {
		const tc_ssh_vector *v = &kSshMpintVectors[i];
		uint8_t enc[BUFSZ], in[BUFSZ];
		size_t enc_len = unhex(v->want, enc, sizeof enc);
		size_t in_len = unhex(v->in, in, sizeof in);
		if (enc_len == SIZE_MAX || in_len == SIZE_MAX || in_len > 32)
			continue;

		/* Left-pad the input to 32 bytes, which is what the decoder
		 * produces: every mpint in this subset becomes a 32-byte scalar. */
		uint8_t want[32];
		memset(want, 0, sizeof want);
		memcpy(want + (sizeof want - in_len), in, in_len);

		tc_ssh_rbuf r;
		tc_ssh_rbuf_init(&r, enc, enc_len);
		uint8_t got[32];
		bool okgot = tc_ssh_get_mpint(&r, got, sizeof got);
		tct_checks++;
		if (!okgot || !tc_ssh_rbuf_ok(&r)) {
			TCT_FAILF("%s: would not decode", v->name);
			continue;
		}
		TCT_EQ_MEM(got, want, sizeof want);
	}
}

static void test_namelists(void)
{
	TCT_CASE("name-lists encode as Go encodes them");
	for (size_t i = 0;
	     i < sizeof kSshNamelistVectors / sizeof *kSshNamelistVectors; i++) {
		const tc_ssh_vector *v = &kSshNamelistVectors[i];

		/* The vector's "in" is the comma-joined form; split it back into the
		 * array the writer takes. */
		char joined[512];
		if (strlen(v->in) >= sizeof joined) {
			TCT_FAILF("%s: unusable input", v->name);
			continue;
		}
		snprintf(joined, sizeof joined, "%s", v->in);

		const char *names[16];
		size_t count = 0;
		if (joined[0] != '\0') {
			char *p = joined;
			names[count++] = p;
			for (; *p != '\0'; p++) {
				if (*p != ',')
					continue;
				*p = '\0';
				if (count >= sizeof names / sizeof *names) {
					TCT_FAILF("%s: too many names", v->name);
					break;
				}
				names[count++] = p + 1;
			}
		}

		uint8_t out[BUFSZ];
		tc_ssh_wbuf w;
		tc_ssh_wbuf_init(&w, out, sizeof out);
		tc_ssh_put_namelist(&w, names, count);
		check_encoding(v->name, &w, v->want);

		TCT_CASE("and every name in one is found in it");
		for (size_t j = 0; j < count; j++) {
			tct_checks++;
			if (!tc_ssh_namelist_has(out + 4, tc_ssh_wbuf_len(&w) - 4,
			                         names[j]))
				TCT_FAILF("%s: lost the name %s", v->name, names[j]);
		}
	}
}

static void test_ed25519_blobs(void)
{
	TCT_CASE("the ssh-ed25519 public key blob matches Go's");
	for (size_t i = 0;
	     i < sizeof kSshEd25519Vectors / sizeof *kSshEd25519Vectors; i++) {
		uint8_t seed[32];
		if (unhex(kSshEd25519Vectors[i].seed, seed, sizeof seed) != 32) {
			TCT_FAILF("vector %zu: unusable seed", i);
			continue;
		}
		uint8_t pub[32];
		if (tc_ed25519_public_from_seed(pub, seed) != TC_OK) {
			TCT_FAILF("vector %zu: could not derive the key", i);
			continue;
		}

		/* RFC 8709: string "ssh-ed25519", string key. */
		uint8_t out[BUFSZ];
		tc_ssh_wbuf w;
		tc_ssh_wbuf_init(&w, out, sizeof out);
		tc_ssh_put_cstring(&w, "ssh-ed25519");
		tc_ssh_put_string(&w, pub, sizeof pub);
		check_encoding("ssh-ed25519 pub blob", &w,
		               kSshEd25519Vectors[i].pub_blob);

		TCT_CASE("and so does the signature blob");
		uint8_t msg[BUFSZ];
		size_t msg_len = unhex(kSshEd25519Vectors[i].msg, msg, sizeof msg);
		uint8_t sig[64];
		if (msg_len == SIZE_MAX ||
		    tc_ed25519_sign(sig, seed, pub, msg, msg_len) != TC_OK) {
			TCT_FAILF("vector %zu: could not sign", i);
			continue;
		}
		tc_ssh_wbuf_init(&w, out, sizeof out);
		tc_ssh_put_cstring(&w, "ssh-ed25519");
		tc_ssh_put_string(&w, sig, sizeof sig);
		check_encoding("ssh-ed25519 sig blob", &w,
		               kSshEd25519Vectors[i].sig_blob);
	}
}

/* ---- the decoder's refusals ------------------------------------------- */

static void test_truncation_is_refused(void)
{
	TCT_CASE("a string longer than the packet is refused");
	/* A length field of 0xffffffff on a four-byte packet. This is the shape
	 * that becomes a wild read if the length is trusted before it is
	 * compared against what is actually left. */
	static const uint8_t wild[] = { 0xff, 0xff, 0xff, 0xff };
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, wild, sizeof wild);
	TCT_TRUE(tc_ssh_get_string(&r, SIZE_MAX, NULL) == NULL);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("and so is one that is merely one byte short");
	static const uint8_t short1[] = { 0, 0, 0, 4, 1, 2, 3 };
	tc_ssh_rbuf_init(&r, short1, sizeof short1);
	TCT_TRUE(tc_ssh_get_string(&r, SIZE_MAX, NULL) == NULL);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("a string over the caller's limit is refused, not truncated");
	static const uint8_t four[] = { 0, 0, 0, 4, 1, 2, 3, 4 };
	tc_ssh_rbuf_init(&r, four, sizeof four);
	TCT_TRUE(tc_ssh_get_string(&r, 3, NULL) == NULL);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("but exactly at the limit is fine");
	tc_ssh_rbuf_init(&r, four, sizeof four);
	size_t n = 0;
	TCT_TRUE(tc_ssh_get_string(&r, 4, &n) != NULL);
	TCT_EQ_INT((int)n, 4);
	TCT_TRUE(tc_ssh_rbuf_ok(&r));

	TCT_CASE("every fixed-width read checks its own space");
	static const uint8_t three[] = { 1, 2, 3 };
	tc_ssh_rbuf_init(&r, three, sizeof three);
	(void)tc_ssh_get_u32(&r);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));
	tc_ssh_rbuf_init(&r, three, sizeof three);
	(void)tc_ssh_get_u64(&r);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));
}

static void test_the_error_is_sticky(void)
{
	/* The safety argument for this file is that a caller may do a run of
	 * reads and check once at the end. That is only true if a failure
	 * anywhere poisons everything after it -- including reads that would
	 * otherwise have succeeded. */
	TCT_CASE("a failed read poisons the reads after it");
	static const uint8_t buf[] = { 0xff, 0xff, 0xff, 0xff, 7, 7, 7, 7 };
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, buf, sizeof buf);

	TCT_TRUE(tc_ssh_get_string(&r, SIZE_MAX, NULL) == NULL);
	/* There are four readable bytes left, so without stickiness this would
	 * succeed and the caller's final check would pass on a packet that was
	 * never valid. */
	TCT_EQ_INT((int)tc_ssh_get_u32(&r), 0);
	TCT_EQ_INT((int)tc_ssh_get_byte(&r), 0);
	TCT_TRUE(tc_ssh_get_raw(&r, 1) == NULL);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));
	TCT_EQ_INT((int)tc_ssh_rbuf_remaining(&r), 0);

	TCT_CASE("and an overflowing write poisons the writes after it");
	uint8_t small[4];
	tc_ssh_wbuf w;
	tc_ssh_wbuf_init(&w, small, sizeof small);
	tc_ssh_put_u32(&w, 1);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	tc_ssh_put_byte(&w, 2); /* one too many */
	TCT_TRUE(!tc_ssh_wbuf_ok(&w));
	TCT_EQ_INT((int)tc_ssh_wbuf_len(&w), 0);

	TCT_CASE("a caller-declared failure is indistinguishable from a real one");
	tc_ssh_rbuf_init(&r, buf, sizeof buf);
	tc_ssh_rbuf_fail(&r);
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));
	TCT_EQ_INT((int)tc_ssh_get_byte(&r), 0);
}

static void test_mpint_refusals(void)
{
	uint8_t out[32];
	tc_ssh_rbuf r;

	TCT_CASE("a negative mpint is refused");
	static const uint8_t neg[] = { 0, 0, 0, 1, 0x80 };
	tc_ssh_rbuf_init(&r, neg, sizeof neg);
	TCT_TRUE(!tc_ssh_get_mpint(&r, out, sizeof out));
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("a non-minimal mpint is refused, not normalised");
	/* 0x0001 encodes the same value as 0x01, and one value with two
	 * encodings is one key with two fingerprints. */
	static const uint8_t nonmin[] = { 0, 0, 0, 2, 0x00, 0x01 };
	tc_ssh_rbuf_init(&r, nonmin, sizeof nonmin);
	TCT_TRUE(!tc_ssh_get_mpint(&r, out, sizeof out));
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("but a leading zero that clears a high bit is legal");
	static const uint8_t legal[] = { 0, 0, 0, 2, 0x00, 0x80 };
	tc_ssh_rbuf_init(&r, legal, sizeof legal);
	TCT_TRUE(tc_ssh_get_mpint(&r, out, sizeof out));
	TCT_TRUE(tc_ssh_rbuf_ok(&r));
	TCT_EQ_INT(out[31], 0x80);

	TCT_CASE("an mpint too wide for the caller's buffer is refused");
	uint8_t wide[4 + 33];
	memset(wide, 0, sizeof wide);
	wide[3] = 33;
	wide[4] = 0x01;
	tc_ssh_rbuf_init(&r, wide, sizeof wide);
	TCT_TRUE(!tc_ssh_get_mpint(&r, out, sizeof out));
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("zero decodes to zero");
	static const uint8_t zero[] = { 0, 0, 0, 0 };
	tc_ssh_rbuf_init(&r, zero, sizeof zero);
	TCT_TRUE(tc_ssh_get_mpint(&r, out, sizeof out));
	TCT_TRUE(tc_ssh_rbuf_ok(&r));
	uint8_t want_zero[32];
	memset(want_zero, 0, sizeof want_zero);
	TCT_EQ_MEM(out, want_zero, sizeof want_zero);
}

static void test_cstring_refusals(void)
{
	char buf[8];
	tc_ssh_rbuf r;

	TCT_CASE("an embedded NUL in a C string is refused");
	/* "sf\0tp" is one name to this reader and another to anything that
	 * later treats it as a path. */
	static const uint8_t embedded[] = { 0, 0, 0, 5, 's', 'f', 0, 't', 'p' };
	tc_ssh_rbuf_init(&r, embedded, sizeof embedded);
	TCT_TRUE(!tc_ssh_get_cstring(&r, buf, sizeof buf));
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("a name too long for the buffer is refused, not truncated");
	static const uint8_t longname[] = { 0,   0,   0,   8,   'a', 'b',
		                                'c', 'd', 'e', 'f', 'g', 'h' };
	tc_ssh_rbuf_init(&r, longname, sizeof longname);
	TCT_TRUE(!tc_ssh_get_cstring(&r, buf, sizeof buf));
	TCT_TRUE(!tc_ssh_rbuf_ok(&r));

	TCT_CASE("and one that just fits is kept whole");
	static const uint8_t fits[] = { 0, 0, 0, 7, 'a', 'b', 'c', 'd', 'e', 'f',
		                            'g' };
	tc_ssh_rbuf_init(&r, fits, sizeof fits);
	TCT_TRUE(tc_ssh_get_cstring(&r, buf, sizeof buf));
	TCT_EQ_STR(buf, "abcdefg");
}

static void test_namelist_matching(void)
{
	static const uint8_t list[] = "curve25519-sha256,ssh-ed25519,none";
	const size_t len = sizeof list - 1;

	TCT_CASE("a name-list finds its own members and nothing else");
	TCT_TRUE(tc_ssh_namelist_has(list, len, "curve25519-sha256"));
	TCT_TRUE(tc_ssh_namelist_has(list, len, "ssh-ed25519"));
	TCT_TRUE(tc_ssh_namelist_has(list, len, "none"));
	TCT_TRUE(!tc_ssh_namelist_has(list, len, "ssh-rsa"));

	TCT_CASE("a prefix of a member is not a member");
	/* Matching on prefix would let "curve25519-sha256" satisfy a peer that
	 * only offered "curve25519-sha256@libssh.org", which is a different
	 * algorithm identifier even though it names the same maths. */
	TCT_TRUE(!tc_ssh_namelist_has(list, len, "curve"));
	TCT_TRUE(!tc_ssh_namelist_has(list, len, "non"));
	TCT_TRUE(!tc_ssh_namelist_has(list, len, "curve25519-sha256@libssh.org"));

	TCT_CASE("an empty list contains nothing");
	TCT_TRUE(!tc_ssh_namelist_has((const uint8_t *)"", 0, "none"));

	TCT_CASE("our preference decides, not the peer's");
	/* RFC 4253 7.1: the client's order wins. A server that took its own
	 * favourite from the intersection would hash a different algorithm name
	 * than the client did. */
	static const char *const ours[] = { "ssh-ed25519", "none" };
	TCT_EQ_INT(tc_ssh_namelist_first_supported(list, len, ours, 2), 0);

	static const char *const ours2[] = { "ssh-rsa", "none" };
	TCT_EQ_INT(tc_ssh_namelist_first_supported(list, len, ours2, 2), 1);

	static const char *const ours3[] = { "ssh-rsa", "ssh-dss" };
	TCT_EQ_INT(tc_ssh_namelist_first_supported(list, len, ours3, 2), -1);

	TCT_CASE("an empty name in a list is handled rather than skipped");
	/* A peer may send ",,none". The empty entries are names of length zero,
	 * not separators to collapse. */
	static const uint8_t odd[] = ",,none";
	TCT_TRUE(tc_ssh_namelist_has(odd, sizeof odd - 1, "none"));
	TCT_TRUE(tc_ssh_namelist_has(odd, sizeof odd - 1, ""));
}

static void test_writer_edges(void)
{
	uint8_t out[64];
	tc_ssh_wbuf w;

	TCT_CASE("a name-list containing a comma is refused");
	/* Every name-list we emit is a compile-time constant, so this is a bug
	 * in us rather than input -- but emitting it would silently turn one
	 * name into two. */
	static const char *const bad[] = { "a,b" };
	tc_ssh_wbuf_init(&w, out, sizeof out);
	tc_ssh_put_namelist(&w, bad, 1);
	TCT_TRUE(!tc_ssh_wbuf_ok(&w));

	TCT_CASE("and so is one containing a space");
	static const char *const spaced[] = { "a b" };
	tc_ssh_wbuf_init(&w, out, sizeof out);
	tc_ssh_put_namelist(&w, spaced, 1);
	TCT_TRUE(!tc_ssh_wbuf_ok(&w));

	TCT_CASE("a zero-capacity writer fails rather than writing");
	tc_ssh_wbuf_init(&w, out, 0);
	tc_ssh_put_byte(&w, 1);
	TCT_TRUE(!tc_ssh_wbuf_ok(&w));

	TCT_CASE("u64 is written as two big-endian halves");
	tc_ssh_wbuf_init(&w, out, sizeof out);
	tc_ssh_put_u64(&w, 0x0123456789abcdefull);
	TCT_TRUE(tc_ssh_wbuf_ok(&w));
	static const uint8_t want[] = { 0x01, 0x23, 0x45, 0x67,
		                            0x89, 0xab, 0xcd, 0xef };
	TCT_EQ_MEM(out, want, sizeof want);

	TCT_CASE("and read back identically");
	tc_ssh_rbuf r;
	tc_ssh_rbuf_init(&r, out, 8);
	TCT_TRUE(tc_ssh_get_u64(&r) == 0x0123456789abcdefull);
	TCT_TRUE(tc_ssh_rbuf_ok(&r));

	TCT_CASE("booleans follow RFC 4251: emit 1, accept any non-zero");
	tc_ssh_wbuf_init(&w, out, sizeof out);
	tc_ssh_put_bool(&w, true);
	TCT_EQ_INT(out[0], 1);
	static const uint8_t truthy[] = { 0x42 };
	tc_ssh_rbuf_init(&r, truthy, sizeof truthy);
	TCT_TRUE(tc_ssh_get_bool(&r));
}

int main(void)
{
	test_strings();
	test_mpints();
	test_namelists();
	test_ed25519_blobs();
	test_truncation_is_refused();
	test_the_error_is_sticky();
	test_mpint_refusals();
	test_cstring_refusals();
	test_namelist_matching();
	test_writer_edges();
	return tct_report("sshwire");
}
