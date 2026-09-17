/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Ed25519.
 *
 * The field arithmetic underneath this is ours, written from scratch because
 * Mbed TLS has no Edwards curve at all -- which makes it the most dangerous
 * code in the project. A field bug does not produce garbage; it produces
 * signatures that verify perfectly against our own verifier and against
 * nothing else in the world. A round-trip test would pass completely.
 *
 * So the vectors come from Go's crypto/ed25519, fed RFC 8032's own seeds and
 * messages, and one of the RFC's published signatures is hard-coded here as a
 * fixed point -- so a generator aimed at the wrong thing cannot quietly agree
 * with itself.
 */

#include "tc/ed25519.h"

#include "tc/crypto.h"

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

static void test_rfc8032_fixed_point(void)
{
	TCT_CASE("RFC 8032 section 7.1, TEST 2, transcribed from the document");
	/* Everything else here is generated. This one is copied by hand from the
	 * RFC so it can be checked against the document by eye, which is what
	 * says the generator is pointed at Ed25519 and not at something else
	 * that also produces 64 bytes. */
	uint8_t seed[32], pub[32], msg[1], want[64], got[64];
	unhex(seed, sizeof seed,
	      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
	unhex(pub, sizeof pub,
	      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
	unhex(msg, sizeof msg, "72");
	unhex(want, sizeof want,
	      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
	      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

	uint8_t derived[32];
	TCT_EQ_INT(tc_ed25519_public_from_seed(derived, seed), TC_OK);
	TCT_EQ_MEM(derived, pub, 32);

	TCT_EQ_INT(tc_ed25519_sign(got, seed, pub, msg, 1), TC_OK);
	TCT_EQ_MEM(got, want, 64);
	TCT_EQ_INT(tc_ed25519_verify(want, pub, msg, 1), TC_OK);
}

static void test_vectors(void)
{
	TCT_CASE("every vector: the public key, the signature, and the check");
	for (size_t i = 0;
	     i < sizeof kEd25519Vectors / sizeof kEd25519Vectors[0]; i++) {
		uint8_t seed[32], pub[32], sig[64];
		static uint8_t msg[4096];
		unhex(seed, sizeof seed, kEd25519Vectors[i].seed);
		unhex(pub, sizeof pub, kEd25519Vectors[i].pub);
		unhex(sig, sizeof sig, kEd25519Vectors[i].sig);
		size_t mlen = unhex(msg, sizeof msg, kEd25519Vectors[i].msg);

		uint8_t derived[32];
		if (tc_ed25519_public_from_seed(derived, seed) != TC_OK ||
		    memcmp(derived, pub, 32) != 0) {
			TCT_FAILF("%s: derived the wrong public key",
			          kEd25519Vectors[i].name);
			continue;
		}
		tct_checks++;

		/* Deterministic, so ours must be byte-identical to Go's rather than
		 * merely valid. A signature that verifies but differs would mean the
		 * nonce derivation is wrong, which is the failure that leaks keys. */
		uint8_t got[64];
		if (tc_ed25519_sign(got, seed, pub, msg, mlen) != TC_OK ||
		    memcmp(got, sig, 64) != 0) {
			TCT_FAILF("%s: signature differs from Go's",
			          kEd25519Vectors[i].name);
			continue;
		}
		tct_checks++;

		if (tc_ed25519_verify(sig, pub, msg, mlen) != TC_OK)
			TCT_FAILF("%s: refused Go's signature", kEd25519Vectors[i].name);
		tct_checks++;
	}
}

static void test_round_trip(void)
{
	TCT_CASE("generated keys sign and verify");
	for (int i = 0; i < 16; i++) {
		uint8_t seed[32], pub[32], sig[64];
		TCT_EQ_INT(tc_ed25519_keypair(seed, pub), TC_OK);
		uint8_t msg[64];
		TCT_EQ_INT(tc_random_bytes(msg, sizeof msg), TC_OK);
		TCT_EQ_INT(tc_ed25519_sign(sig, seed, pub, msg, sizeof msg), TC_OK);
		TCT_EQ_INT(tc_ed25519_verify(sig, pub, msg, sizeof msg), TC_OK);
	}

	TCT_CASE("two keypairs are not the same keypair");
	uint8_t s1[32], p1[32], s2[32], p2[32];
	TCT_EQ_INT(tc_ed25519_keypair(s1, p1), TC_OK);
	TCT_EQ_INT(tc_ed25519_keypair(s2, p2), TC_OK);
	TCT_TRUE(memcmp(s1, s2, 32) != 0);
	TCT_TRUE(memcmp(p1, p2, 32) != 0);

	TCT_CASE("an empty message signs and verifies");
	uint8_t sig[64];
	TCT_EQ_INT(tc_ed25519_sign(sig, s1, p1, NULL, 0), TC_OK);
	TCT_EQ_INT(tc_ed25519_verify(sig, p1, NULL, 0), TC_OK);

	TCT_CASE("signing is deterministic");
	/* Two signatures over the same message must be identical. If they are
	 * not, a nonce is coming from somewhere it should not. */
	uint8_t a[64], b[64];
	static const uint8_t kMsg[5] = "hello";
	TCT_EQ_INT(tc_ed25519_sign(a, s1, p1, kMsg, sizeof kMsg), TC_OK);
	TCT_EQ_INT(tc_ed25519_sign(b, s1, p1, kMsg, sizeof kMsg), TC_OK);
	TCT_EQ_MEM(a, b, 64);
}

static void test_rejects(void)
{
	uint8_t seed[32], pub[32], sig[64];
	static const uint8_t kMsg[11] = "hello there";
	TCT_EQ_INT(tc_ed25519_keypair(seed, pub), TC_OK);
	TCT_EQ_INT(tc_ed25519_sign(sig, seed, pub, kMsg, sizeof kMsg), TC_OK);
	TCT_EQ_INT(tc_ed25519_verify(sig, pub, kMsg, sizeof kMsg), TC_OK);

	TCT_CASE("every single-bit change to the signature is caught");
	for (size_t byte = 0; byte < 64; byte++) {
		for (int bit = 0; bit < 8; bit++) {
			uint8_t bad[64];
			memcpy(bad, sig, 64);
			bad[byte] ^= (uint8_t)(1u << bit);
			if (tc_ed25519_verify(bad, pub, kMsg, sizeof kMsg) == TC_OK)
				TCT_FAILF("accepted a flip of bit %d in byte %zu", bit, byte);
			tct_checks++;
		}
	}

	TCT_CASE("every single-bit change to the message is caught");
	for (size_t byte = 0; byte < sizeof kMsg; byte++) {
		for (int bit = 0; bit < 8; bit++) {
			uint8_t bad[sizeof kMsg];
			memcpy(bad, kMsg, sizeof kMsg);
			bad[byte] ^= (uint8_t)(1u << bit);
			if (tc_ed25519_verify(sig, pub, bad, sizeof bad) == TC_OK)
				TCT_FAILF("accepted a flip of bit %d in message byte %zu",
				          bit, byte);
			tct_checks++;
		}
	}

	TCT_CASE("every single-bit change to the public key is caught");
	/* Some of these are not points at all and some are other people's keys.
	 * Both have to be refused, and the first must not crash. */
	for (size_t byte = 0; byte < 32; byte++) {
		for (int bit = 0; bit < 8; bit++) {
			uint8_t bad[32];
			memcpy(bad, pub, 32);
			bad[byte] ^= (uint8_t)(1u << bit);
			if (tc_ed25519_verify(sig, bad, kMsg, sizeof kMsg) == TC_OK)
				TCT_FAILF("accepted a flip of bit %d in key byte %zu", bit,
				          byte);
			tct_checks++;
		}
	}

	TCT_CASE("a truncated or extended message is caught");
	TCT_EQ_INT(tc_ed25519_verify(sig, pub, kMsg, sizeof kMsg - 1),
	           TC_ERR_INVAL);
	uint8_t longer[sizeof kMsg + 1];
	memcpy(longer, kMsg, sizeof kMsg);
	longer[sizeof kMsg] = 0;
	TCT_EQ_INT(tc_ed25519_verify(sig, pub, longer, sizeof longer),
	           TC_ERR_INVAL);

	TCT_CASE("an unreduced S is refused, so signatures cannot be mauled");
	/* S + L verifies under a cofactorless check that does not test the
	 * range, which turns one signature into many distinct byte strings that
	 * all pass -- and breaks anything using the signature as an identifier.
	 * L = 2^252 + 27742317777372353535851937790883648493. */
	static const uint8_t kL[32] = {
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
		0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	};
	uint8_t mauled[64];
	memcpy(mauled, sig, 64);
	unsigned carry = 0;
	for (size_t i = 0; i < 32; i++) {
		unsigned t = (unsigned)mauled[32 + i] + kL[i] + carry;
		mauled[32 + i] = (uint8_t)t;
		carry = t >> 8;
	}
	/* Only meaningful if it did not overflow out of 32 bytes. */
	if (carry == 0) {
		TCT_TRUE(memcmp(mauled + 32, sig + 32, 32) != 0);
		TCT_EQ_INT(tc_ed25519_verify(mauled, pub, kMsg, sizeof kMsg),
		           TC_ERR_INVAL);
	}
	tct_checks++;

	TCT_CASE("S equal to L exactly is refused");
	memcpy(mauled, sig, 64);
	memcpy(mauled + 32, kL, 32);
	TCT_EQ_INT(tc_ed25519_verify(mauled, pub, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("an all-ones S is refused rather than wrapped");
	memcpy(mauled, sig, 64);
	memset(mauled + 32, 0xff, 32);
	TCT_EQ_INT(tc_ed25519_verify(mauled, pub, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("a public key that is not a point is refused, not guessed at");
	/* y = 1 is a point; y = 2 is not on the curve. A decoder that invented
	 * an x for it would be accepting attacker-chosen garbage as a key. */
	uint8_t notpoint[32];
	memset(notpoint, 0, sizeof notpoint);
	notpoint[0] = 2;
	TCT_EQ_INT(tc_ed25519_verify(sig, notpoint, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("y = p - 1 and above are refused");
	/* Values at or past the modulus are non-canonical encodings. */
	uint8_t big[32];
	memset(big, 0xff, sizeof big);
	big[31] = 0x7f;
	TCT_EQ_INT(tc_ed25519_verify(sig, big, kMsg, sizeof kMsg), TC_ERR_INVAL);

	TCT_CASE("signing with a mismatched public key does not verify");
	/* The key is hashed into the challenge, so a mismatched pair produces a
	 * signature valid under neither -- silently, which is why it is worth a
	 * test rather than a comment. */
	uint8_t seed2[32], pub2[32], crossed[64];
	TCT_EQ_INT(tc_ed25519_keypair(seed2, pub2), TC_OK);
	TCT_EQ_INT(tc_ed25519_sign(crossed, seed, pub2, kMsg, sizeof kMsg),
	           TC_OK);
	TCT_EQ_INT(tc_ed25519_verify(crossed, pub, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_verify(crossed, pub2, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_ed25519_verify(NULL, pub, kMsg, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_verify(sig, NULL, kMsg, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_verify(sig, pub, NULL, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_sign(NULL, seed, pub, kMsg, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_sign(sig, NULL, pub, kMsg, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_sign(sig, seed, NULL, kMsg, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_sign(sig, seed, pub, NULL, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_public_from_seed(NULL, seed), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_public_from_seed(pub, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_keypair(NULL, pub), TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_keypair(seed, NULL), TC_ERR_INVAL);
}

static void test_identity_and_small_order(void)
{
	TCT_CASE("the identity element as a public key");
	/* y = 1, x = 0: a real point, and one whose secret key is zero. Every
	 * signature under it is forgeable, so what matters is that we neither
	 * crash nor accept a signature that was not made for it. */
	uint8_t ident[32];
	memset(ident, 0, sizeof ident);
	ident[0] = 1;

	uint8_t seed[32], pub[32], sig[64];
	TCT_EQ_INT(tc_ed25519_keypair(seed, pub), TC_OK);
	static const uint8_t kMsg[2] = "hi";
	TCT_EQ_INT(tc_ed25519_sign(sig, seed, pub, kMsg, sizeof kMsg), TC_OK);
	TCT_EQ_INT(tc_ed25519_verify(sig, ident, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("the identity key forges everything, which is not our bug");
	/* With A = identity the check becomes [S]B = R + [k]*identity = R, so
	 * S = 0 with R = identity satisfies it for *any* message. That is a
	 * property of a degenerate key rather than a flaw in the check, and
	 * every implementation behaves this way -- but it is worth pinning,
	 * because it is the only input that makes the next test possible. */
	uint8_t forged[64];
	memset(forged, 0, sizeof forged);
	forged[0] = 1; /* R = the identity point */
	TCT_EQ_INT(tc_ed25519_verify(forged, ident, kMsg, sizeof kMsg), TC_OK);
	TCT_EQ_INT(tc_ed25519_verify(forged, ident, NULL, 0), TC_OK);

	TCT_CASE("and the non-canonical spelling of that key is refused");
	/* x = 0 has one root, so the sign bit must be clear; setting it is a
	 * second byte string for the same point, and two spellings of one key
	 * make a fingerprint ambiguous.
	 *
	 * This is the one place the rule is observable. Everywhere else a
	 * non-canonical key is refused anyway, because the signature was not
	 * made for it -- here the signature *is* valid for the point, so the
	 * only thing that can reject it is the encoding rule itself. */
	uint8_t identneg[32];
	memcpy(identneg, ident, 32);
	identneg[31] |= 0x80;
	TCT_EQ_INT(tc_ed25519_verify(forged, identneg, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_ed25519_verify(sig, identneg, kMsg, sizeof kMsg),
	           TC_ERR_INVAL);

	TCT_CASE("random 32-byte strings are never accepted as public keys");
	/* Most are not points at all, which exercises the non-square branch of
	 * the decoder many times over. None may be accepted and none may
	 * crash -- this is the input an attacker actually controls. */
	for (int i = 0; i < 256; i++) {
		uint8_t junk[32];
		TCT_EQ_INT(tc_random_bytes(junk, sizeof junk), TC_OK);
		if (tc_ed25519_verify(sig, junk, kMsg, sizeof kMsg) == TC_OK)
			TCT_FAILF("accepted a random public key");
		tct_checks++;
	}

	TCT_CASE("a signature whose R is not a point is refused");
	uint8_t badR[64];
	memcpy(badR, sig, 64);
	memset(badR, 0, 32);
	badR[0] = 2; /* y = 2 is not on the curve */
	TCT_EQ_INT(tc_ed25519_verify(badR, pub, kMsg, sizeof kMsg), TC_ERR_INVAL);
}

int main(void)
{
	test_rfc8032_fixed_point();
	test_vectors();
	test_round_trip();
	test_rejects();
	test_identity_and_small_order();
	return tct_report("ed25519");
}
