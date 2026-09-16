/* SPDX-License-Identifier: BSD-3-Clause
 *
 * BLAKE2s, per RFC 7693.
 *
 * Mbed TLS does not implement BLAKE2s, and WireGuard's
 * Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s needs it three ways: as the Noise
 * hash, as the keyed MAC behind mac1/mac2 (with a 16-byte digest), and as
 * the hash underneath the HMAC its KDF uses.
 *
 * The compression function is straight-line and data-independent -- no
 * lookups indexed by secret data, no branches on secret data -- so it runs
 * in constant time with respect to both the message and the key.
 */

#include "tc/crypto.h"

#include <string.h>

/* Same initialisation vector as SHA-256. */
static const uint32_t kIV[8] = {
	0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
	0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
};

static const uint8_t kSigma[10][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static uint32_t load32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static void store32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)(v >> 8 & 0xffu);
	p[2] = (uint8_t)(v >> 16 & 0xffu);
	p[3] = (uint8_t)(v >> 24 & 0xffu);
}

static uint32_t rotr32(uint32_t x, unsigned n)
{
	return x >> n | x << (32u - n);
}

#define G(a, b, c, d, x, y)                                                   \
	do {                                                                      \
		a = a + b + (x);                                                      \
		d = rotr32(d ^ a, 16);                                                \
		c = c + d;                                                            \
		b = rotr32(b ^ c, 12);                                                \
		a = a + b + (y);                                                      \
		d = rotr32(d ^ a, 8);                                                 \
		c = c + d;                                                            \
		b = rotr32(b ^ c, 7);                                                 \
	} while (0)

/* compress absorbs one 64-byte block. `last` sets the finalisation flag,
 * which must be set for the final block and only the final block. */
static void compress(tc_blake2s_ctx *ctx, const uint8_t block[64], bool last)
{
	uint32_t m[16];
	uint32_t v[16];

	for (size_t i = 0; i < 16; i++)
		m[i] = load32(block + i * 4);

	for (size_t i = 0; i < 8; i++)
		v[i] = ctx->h[i];
	v[8] = kIV[0];
	v[9] = kIV[1];
	v[10] = kIV[2];
	v[11] = kIV[3];
	v[12] = kIV[4] ^ (uint32_t)(ctx->t & 0xffffffffu);
	v[13] = kIV[5] ^ (uint32_t)(ctx->t >> 32);
	v[14] = last ? ~kIV[6] : kIV[6];
	v[15] = kIV[7];

	for (size_t r = 0; r < 10; r++) {
		const uint8_t *s = kSigma[r];
		G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
		G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
		G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
		G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
		G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
		G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
		G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
		G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
	}

	for (size_t i = 0; i < 8; i++)
		ctx->h[i] ^= v[i] ^ v[i + 8];

	tc_memzero_explicit(v, sizeof v);
	tc_memzero_explicit(m, sizeof m);
}

void tc_blake2s_init_key(tc_blake2s_ctx *ctx, size_t outlen,
                         const uint8_t *key, size_t keylen)
{
	/* Callers inside tailcat-c pass compile-time-constant sizes, so clamping
	 * here rather than returning an error keeps every call site free of a
	 * check that can never fire. */
	if (outlen == 0 || outlen > TC_BLAKE2S_HASH_LEN)
		outlen = TC_BLAKE2S_HASH_LEN;
	if (key == NULL)
		keylen = 0;
	if (keylen > TC_BLAKE2S_KEY_MAX)
		keylen = TC_BLAKE2S_KEY_MAX;

	memset(ctx, 0, sizeof *ctx);
	for (size_t i = 0; i < 8; i++)
		ctx->h[i] = kIV[i];

	/* Parameter block word 0: digest length, key length, fanout 1, depth 1.
	 * The remaining parameter words are zero for our use, so they do not
	 * change h. */
	ctx->h[0] ^= 0x01010000ul ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
	ctx->outlen = outlen;

	if (keylen > 0) {
		/* The key is absorbed as a full zero-padded block. */
		uint8_t kblock[TC_BLAKE2S_BLOCK_LEN];
		memset(kblock, 0, sizeof kblock);
		memcpy(kblock, key, keylen);
		tc_blake2s_update(ctx, kblock, sizeof kblock);
		tc_memzero_explicit(kblock, sizeof kblock);
	}
}

void tc_blake2s_init(tc_blake2s_ctx *ctx, size_t outlen)
{
	tc_blake2s_init_key(ctx, outlen, NULL, 0);
}

void tc_blake2s_update(tc_blake2s_ctx *ctx, const void *in, size_t inlen)
{
	const uint8_t *p = (const uint8_t *)in;

	if (inlen == 0)
		return;

	size_t left = ctx->buflen;
	size_t fill = TC_BLAKE2S_BLOCK_LEN - left;

	/* Note the strict comparisons below. A block is only compressed once we
	 * know more data follows it, because the final block must be compressed
	 * with the `last` flag set -- and we cannot know a block is final until
	 * tc_blake2s_final is called. */
	if (inlen > fill) {
		memcpy(ctx->buf + left, p, fill);
		ctx->t += TC_BLAKE2S_BLOCK_LEN;
		compress(ctx, ctx->buf, false);
		ctx->buflen = 0;
		p += fill;
		inlen -= fill;

		while (inlen > TC_BLAKE2S_BLOCK_LEN) {
			ctx->t += TC_BLAKE2S_BLOCK_LEN;
			compress(ctx, p, false);
			p += TC_BLAKE2S_BLOCK_LEN;
			inlen -= TC_BLAKE2S_BLOCK_LEN;
		}
	}

	memcpy(ctx->buf + ctx->buflen, p, inlen);
	ctx->buflen += inlen;
}

void tc_blake2s_final(tc_blake2s_ctx *ctx, uint8_t *out)
{
	uint8_t full[TC_BLAKE2S_HASH_LEN];

	ctx->t += ctx->buflen;
	memset(ctx->buf + ctx->buflen, 0, TC_BLAKE2S_BLOCK_LEN - ctx->buflen);
	compress(ctx, ctx->buf, true);

	for (size_t i = 0; i < 8; i++)
		store32(full + i * 4, ctx->h[i]);

	memcpy(out, full, ctx->outlen);

	tc_memzero_explicit(full, sizeof full);
	tc_memzero_explicit(ctx, sizeof *ctx);
}

void tc_blake2s(uint8_t *out, size_t outlen, const void *in, size_t inlen,
                const uint8_t *key, size_t keylen)
{
	tc_blake2s_ctx ctx;
	tc_blake2s_init_key(&ctx, outlen, key, keylen);
	tc_blake2s_update(&ctx, in, inlen);
	tc_blake2s_final(&ctx, out);
}
