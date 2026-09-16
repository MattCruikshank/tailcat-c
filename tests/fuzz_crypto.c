/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Property fuzzing for the crypto layer.
 *
 * Unlike the address parser, these functions mostly take fixed-size inputs,
 * so the interesting bugs are not "does it crash on garbage" but "do the
 * invariants hold for every shape of input". The properties checked are:
 *
 *   1. tc_aead_open on arbitrary bytes never crashes and never authenticates.
 *   2. seal then open recovers the plaintext exactly.
 *   3. flipping any single bit of ciphertext, tag, AD or counter makes open
 *      fail -- this is the property that actually protects the tunnel.
 *   4. BLAKE2s fed in arbitrary chunk sizes equals the one-shot digest, which
 *      is where the final-block flag goes wrong.
 *   5. X25519 is commutative, and small-order points are refused.
 */

#include "tc/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rng_next(void)
{
	uint64_t x = rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static size_t rng_below(size_t n) { return n ? (size_t)(rng_next() % n) : 0; }

static void rng_fill(uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (uint8_t)rng_next();
}

#define MAXPT 1024

static void fail(const char *what)
{
	fprintf(stderr, "FUZZ: %s\n", what);
	abort();
}

/* Property 1: open must reject arbitrary bytes without misbehaving. */
static void prop_open_garbage(void)
{
	uint8_t key[32], ct[MAXPT + TC_AEAD_TAG_LEN], out[MAXPT], ad[64];
	size_t ct_len = rng_below(sizeof ct);
	size_t ad_len = rng_below(sizeof ad);

	rng_fill(key, sizeof key);
	rng_fill(ct, ct_len);
	rng_fill(ad, ad_len);

	int rc = tc_aead_open(out, key, rng_next(), ad_len ? ad : NULL, ad_len,
	                      ct, ct_len);
	/* Forging a tag by chance is a 2^-128 event; treat it as a failure. */
	if (rc == TC_OK)
		fail("random ciphertext authenticated");
}

/* Properties 2 and 3. */
static void prop_aead_roundtrip(void)
{
	uint8_t key[32], pt[MAXPT], ad[64];
	uint8_t ct[MAXPT + TC_AEAD_TAG_LEN], out[MAXPT];
	size_t pt_len = rng_below(MAXPT);
	size_t ad_len = rng_below(sizeof ad);
	uint64_t ctr = rng_next();

	rng_fill(key, sizeof key);
	rng_fill(pt, pt_len);
	rng_fill(ad, ad_len);

	if (tc_aead_seal(ct, key, ctr, ad_len ? ad : NULL, ad_len,
	                 pt_len ? pt : NULL, pt_len) != TC_OK)
		fail("seal failed");

	size_t ct_len = pt_len + TC_AEAD_TAG_LEN;

	if (tc_aead_open(out, key, ctr, ad_len ? ad : NULL, ad_len, ct, ct_len) !=
	    TC_OK)
		fail("open of our own ciphertext failed");
	if (pt_len && memcmp(out, pt, pt_len) != 0)
		fail("round trip changed the plaintext");

	/* Flip one random bit of the ciphertext-or-tag. */
	size_t bit = rng_below(ct_len * 8);
	ct[bit / 8] ^= (uint8_t)(1u << (bit % 8));
	if (tc_aead_open(out, key, ctr, ad_len ? ad : NULL, ad_len, ct, ct_len) ==
	    TC_OK)
		fail("tampered ciphertext authenticated");
	ct[bit / 8] ^= (uint8_t)(1u << (bit % 8));

	/* A different counter must not authenticate. */
	if (tc_aead_open(out, key, ctr ^ (1ULL << rng_below(64)),
	                 ad_len ? ad : NULL, ad_len, ct, ct_len) == TC_OK)
		fail("wrong counter authenticated");

	/* A flipped AD bit must not authenticate. */
	if (ad_len) {
		size_t abit = rng_below(ad_len * 8);
		ad[abit / 8] ^= (uint8_t)(1u << (abit % 8));
		if (tc_aead_open(out, key, ctr, ad, ad_len, ct, ct_len) == TC_OK)
			fail("tampered associated data authenticated");
	}
}

/* Property 4: chunked BLAKE2s equals one-shot BLAKE2s. */
static void prop_blake2s_chunking(void)
{
	uint8_t msg[MAXPT], key[32];
	size_t msg_len = rng_below(MAXPT);
	size_t key_len = (rng_next() & 1u) ? 32u : 0u;
	size_t outlen = (rng_next() & 1u) ? 32u : 16u;

	rng_fill(msg, msg_len);
	rng_fill(key, sizeof key);

	uint8_t oneshot[32], chunked[32];
	tc_blake2s(oneshot, outlen, msg, msg_len, key_len ? key : NULL, key_len);

	tc_blake2s_ctx ctx;
	tc_blake2s_init_key(&ctx, outlen, key_len ? key : NULL, key_len);
	size_t off = 0;
	while (off < msg_len) {
		/* Deliberately include zero-length updates. */
		size_t take = rng_below(70);
		if (take > msg_len - off)
			take = msg_len - off;
		tc_blake2s_update(&ctx, msg + off, take);
		off += take;
	}
	tc_blake2s_final(&ctx, chunked);

	if (memcmp(oneshot, chunked, outlen) != 0)
		fail("chunked BLAKE2s differs from one-shot");
}

/* Property 5. */
static void prop_x25519(void)
{
	uint8_t ska[32], pka[32], skb[32], pkb[32], ss1[32], ss2[32];

	if (tc_x25519_keypair(ska, pka) != TC_OK ||
	    tc_x25519_keypair(skb, pkb) != TC_OK)
		fail("keypair generation failed");

	if (tc_x25519(ss1, ska, pkb) != TC_OK || tc_x25519(ss2, skb, pka) != TC_OK)
		fail("x25519 failed on a valid keypair");
	if (memcmp(ss1, ss2, 32) != 0)
		fail("x25519 is not commutative");

	/* An all-zero public key is small-order and must be refused. */
	uint8_t zero[32] = { 0 }, out[32];
	if (tc_x25519(out, ska, zero) != TC_ERR_INVAL)
		fail("small-order public key accepted");
}

int main(int argc, char **argv)
{
	unsigned long iters = 20000;
	if (argc > 1)
		iters = strtoul(argv[1], NULL, 10);
	if (argc > 2)
		rng_state = strtoull(argv[2], NULL, 10) | 1u;

	/* X25519 is orders of magnitude slower than the rest, so run it less
	 * often; the cheap properties get the bulk of the iterations. */
	for (unsigned long i = 0; i < iters; i++) {
		prop_open_garbage();
		prop_aead_roundtrip();
		prop_blake2s_chunking();
		if (i % 200 == 0)
			prop_x25519();
	}

	printf("ok   fuzz_crypto              %lu iterations, all properties held\n",
	       iters);
	return 0;
}
