/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Salsa20, HSalsa20 and XSalsa20, and the NaCl secretbox and box built on
 * them.
 *
 * DERP's handshake frames are NaCl boxes, so this is not optional: no Salsa,
 * no DERP connection. Mbed TLS implements none of the Salsa family, though
 * its Poly1305 is reused here for the authenticator.
 *
 * Salsa20 looks almost like ChaCha20 -- same 16-word state, same ARX shape --
 * but the word layout, the rotation constants (7/9/13/18 rather than
 * 16/12/8/7) and the round pattern all differ. They are not interchangeable,
 * and the vectors in tests/test_crypto.c are generated from Go's
 * implementation precisely so a slip here cannot go unnoticed.
 *
 * Everything is straight-line and data-independent, so it runs in constant
 * time with respect to keys and plaintext.
 */

#include "tc/crypto.h"

#include "mbedtls/poly1305.h"

#include <string.h>

/* "expand 32-byte k" */
static const uint32_t kSigma[4] = { 0x61707865ul, 0x3320646eul, 0x79622d32ul,
	                                0x6b206574ul };

static uint32_t load32le(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static void store32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)(v >> 8 & 0xffu);
	p[2] = (uint8_t)(v >> 16 & 0xffu);
	p[3] = (uint8_t)(v >> 24 & 0xffu);
}

static uint32_t rotl32(uint32_t x, unsigned n)
{
	return x << n | x >> (32u - n);
}

/* salsa20_rounds applies the 20 rounds (10 column/row double rounds) to x
 * in place. It does NOT do the feed-forward addition, because HSalsa20 needs
 * the state without it. */
static void salsa20_rounds(uint32_t x[16])
{
	for (unsigned i = 0; i < 10; i++) {
		/* Column round. */
		x[4] ^= rotl32(x[0] + x[12], 7);
		x[8] ^= rotl32(x[4] + x[0], 9);
		x[12] ^= rotl32(x[8] + x[4], 13);
		x[0] ^= rotl32(x[12] + x[8], 18);

		x[9] ^= rotl32(x[5] + x[1], 7);
		x[13] ^= rotl32(x[9] + x[5], 9);
		x[1] ^= rotl32(x[13] + x[9], 13);
		x[5] ^= rotl32(x[1] + x[13], 18);

		x[14] ^= rotl32(x[10] + x[6], 7);
		x[2] ^= rotl32(x[14] + x[10], 9);
		x[6] ^= rotl32(x[2] + x[14], 13);
		x[10] ^= rotl32(x[6] + x[2], 18);

		x[3] ^= rotl32(x[15] + x[11], 7);
		x[7] ^= rotl32(x[3] + x[15], 9);
		x[11] ^= rotl32(x[7] + x[3], 13);
		x[15] ^= rotl32(x[11] + x[7], 18);

		/* Row round. */
		x[1] ^= rotl32(x[0] + x[3], 7);
		x[2] ^= rotl32(x[1] + x[0], 9);
		x[3] ^= rotl32(x[2] + x[1], 13);
		x[0] ^= rotl32(x[3] + x[2], 18);

		x[6] ^= rotl32(x[5] + x[4], 7);
		x[7] ^= rotl32(x[6] + x[5], 9);
		x[4] ^= rotl32(x[7] + x[6], 13);
		x[5] ^= rotl32(x[4] + x[7], 18);

		x[11] ^= rotl32(x[10] + x[9], 7);
		x[8] ^= rotl32(x[11] + x[10], 9);
		x[9] ^= rotl32(x[8] + x[11], 13);
		x[10] ^= rotl32(x[9] + x[8], 18);

		x[12] ^= rotl32(x[15] + x[14], 7);
		x[13] ^= rotl32(x[12] + x[15], 9);
		x[14] ^= rotl32(x[13] + x[12], 13);
		x[15] ^= rotl32(x[14] + x[13], 18);
	}
}

/* State layout, shared by Salsa20 and HSalsa20:
 *   0:sigma0  1..4:key[0..15]   5:sigma1  6..9:input  10:sigma2
 *   11..14:key[16..31]  15:sigma3 */
static void salsa20_state(uint32_t x[16], const uint8_t key[32],
                          const uint8_t in[16])
{
	x[0] = kSigma[0];
	x[5] = kSigma[1];
	x[10] = kSigma[2];
	x[15] = kSigma[3];
	for (size_t i = 0; i < 4; i++) {
		x[1 + i] = load32le(key + 4 * i);
		x[11 + i] = load32le(key + 16 + 4 * i);
		x[6 + i] = load32le(in + 4 * i);
	}
}

void tc_hsalsa20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16])
{
	uint32_t x[16];
	salsa20_state(x, key, in);
	salsa20_rounds(x);

	/* No feed-forward: HSalsa20 takes the raw post-round words, and only the
	 * eight that were not key material to begin with. */
	store32le(out + 0, x[0]);
	store32le(out + 4, x[5]);
	store32le(out + 8, x[10]);
	store32le(out + 12, x[15]);
	store32le(out + 16, x[6]);
	store32le(out + 20, x[7]);
	store32le(out + 24, x[8]);
	store32le(out + 28, x[9]);

	tc_memzero_explicit(x, sizeof x);
}

/* salsa20_block produces one 64-byte keystream block for the 8-byte nonce
 * and 64-bit counter. */
static void salsa20_block(uint8_t out[64], const uint8_t key[32],
                          const uint8_t nonce8[8], uint64_t counter)
{
	uint8_t in[16];
	uint32_t x[16], orig[16];

	memcpy(in, nonce8, 8);
	for (size_t i = 0; i < 8; i++)
		in[8 + i] = (uint8_t)(counter >> (8u * i));

	salsa20_state(x, key, in);
	memcpy(orig, x, sizeof orig);
	salsa20_rounds(x);

	for (size_t i = 0; i < 16; i++)
		store32le(out + 4 * i, x[i] + orig[i]);

	tc_memzero_explicit(x, sizeof x);
	tc_memzero_explicit(orig, sizeof orig);
	tc_memzero_explicit(in, sizeof in);
}

void tc_xsalsa20_xor(uint8_t *out, const void *in, size_t n,
                     const uint8_t nonce[TC_BOX_NONCE_LEN],
                     const uint8_t key[32], uint64_t keystream_offset)
{
	const uint8_t *ip = (const uint8_t *)in;
	uint8_t subkey[32];
	uint8_t block[64];

	/* XSalsa20: the first 16 nonce bytes go through HSalsa20 to make a
	 * subkey, and the remaining 8 become Salsa20's nonce. This is what lets
	 * the nonce be 24 bytes and therefore safe to choose at random. */
	tc_hsalsa20(subkey, key, nonce);

	/* The offset need not be block-aligned -- secretbox starts at byte 32 --
	 * so the first block may be entered partway in. */
	uint64_t ctr = keystream_offset / sizeof block;
	size_t skip = (size_t)(keystream_offset % sizeof block);

	size_t off = 0;
	while (off < n) {
		salsa20_block(block, subkey, nonce + 16, ctr);

		size_t avail = sizeof block - skip;
		size_t take = n - off;
		if (take > avail)
			take = avail;

		for (size_t i = 0; i < take; i++)
			out[off + i] = (uint8_t)(ip[off + i] ^ block[skip + i]);

		off += take;
		skip = 0;
		ctr++;
	}

	tc_memzero_explicit(subkey, sizeof subkey);
	tc_memzero_explicit(block, sizeof block);
}

/* poly_key derives the one-time Poly1305 key: the first 32 bytes of the
 * keystream. The message then continues from keystream byte 32, in the same
 * block -- see the note on tc_xsalsa20_xor. */
static void poly_key(uint8_t out[32], const uint8_t key[32],
                     const uint8_t nonce[TC_BOX_NONCE_LEN])
{
	uint8_t subkey[32];
	uint8_t block[64];

	tc_hsalsa20(subkey, key, nonce);
	salsa20_block(block, subkey, nonce + 16, 0);
	memcpy(out, block, 32);

	tc_memzero_explicit(subkey, sizeof subkey);
	tc_memzero_explicit(block, sizeof block);
}

int tc_secretbox_seal(uint8_t *out, const uint8_t key[TC_BOX_KEY_LEN],
                      const uint8_t nonce[TC_BOX_NONCE_LEN], const void *pt,
                      size_t pt_len)
{
	uint8_t pk[32];

	if (out == NULL || key == NULL || nonce == NULL)
		return TC_ERR_INVAL;
	if (pt_len > SIZE_MAX - TC_BOX_TAG_LEN)
		return TC_ERR_RANGE;
	if (pt == NULL && pt_len != 0)
		return TC_ERR_INVAL;

	poly_key(pk, key, nonce);

	/* Ciphertext goes after the tag. The message keystream starts at byte
	 * 32, immediately after the 32 bytes that became the Poly1305 key --
	 * NOT at block 1. */
	if (pt_len != 0)
		tc_xsalsa20_xor(out + TC_BOX_TAG_LEN, pt, pt_len, nonce, key, 32);

	int ret = mbedtls_poly1305_mac(pk, out + TC_BOX_TAG_LEN, pt_len, out);

	tc_memzero_explicit(pk, sizeof pk);
	return (ret == 0) ? TC_OK : TC_ERR_INVAL;
}

int tc_secretbox_open(uint8_t *out, const uint8_t key[TC_BOX_KEY_LEN],
                      const uint8_t nonce[TC_BOX_NONCE_LEN], const void *ct,
                      size_t ct_len)
{
	uint8_t pk[32];
	uint8_t tag[TC_BOX_TAG_LEN];

	if (key == NULL || nonce == NULL || ct == NULL)
		return TC_ERR_INVAL;
	if (ct_len < TC_BOX_TAG_LEN)
		return TC_ERR_INVAL;

	size_t pt_len = ct_len - TC_BOX_TAG_LEN;
	if (out == NULL && pt_len != 0)
		return TC_ERR_INVAL;

	const uint8_t *cb = (const uint8_t *)ct;

	poly_key(pk, key, nonce);

	int ret = mbedtls_poly1305_mac(pk, cb + TC_BOX_TAG_LEN, pt_len, tag);
	if (ret != 0) {
		tc_memzero_explicit(pk, sizeof pk);
		return TC_ERR_INVAL;
	}

	/* Verify before decrypting, in constant time, so a forged frame never
	 * produces plaintext an attacker chose. */
	if (!tc_ct_equal(tag, cb, TC_BOX_TAG_LEN)) {
		tc_memzero_explicit(pk, sizeof pk);
		tc_memzero_explicit(tag, sizeof tag);
		return TC_ERR_INVAL;
	}

	if (pt_len != 0)
		tc_xsalsa20_xor(out, cb + TC_BOX_TAG_LEN, pt_len, nonce, key, 32);

	tc_memzero_explicit(pk, sizeof pk);
	tc_memzero_explicit(tag, sizeof tag);
	return TC_OK;
}

int tc_box_beforenm(uint8_t shared[TC_BOX_KEY_LEN],
                    const uint8_t sk[TC_X25519_KEY_LEN],
                    const uint8_t pk[TC_X25519_KEY_LEN])
{
	uint8_t dh[TC_X25519_KEY_LEN];
	static const uint8_t kZero16[16] = { 0 };

	int rc = tc_x25519(dh, sk, pk);
	if (rc != TC_OK) {
		tc_memzero_explicit(shared, TC_BOX_KEY_LEN);
		return rc;
	}

	/* NaCl's box_beforenm: HSalsa20 of the raw DH output under a zero nonce.
	 * The DH result is not used as a key directly. */
	tc_hsalsa20(shared, dh, kZero16);

	tc_memzero_explicit(dh, sizeof dh);
	return TC_OK;
}

int tc_box_seal(uint8_t *out, const uint8_t nonce[TC_BOX_NONCE_LEN],
                const void *pt, size_t pt_len,
                const uint8_t peer_pk[TC_X25519_KEY_LEN],
                const uint8_t sk[TC_X25519_KEY_LEN])
{
	uint8_t shared[TC_BOX_KEY_LEN];
	int rc = tc_box_beforenm(shared, sk, peer_pk);
	if (rc != TC_OK)
		return rc;
	rc = tc_secretbox_seal(out, shared, nonce, pt, pt_len);
	tc_memzero_explicit(shared, sizeof shared);
	return rc;
}

int tc_box_open(uint8_t *out, const uint8_t nonce[TC_BOX_NONCE_LEN],
                const void *ct, size_t ct_len,
                const uint8_t peer_pk[TC_X25519_KEY_LEN],
                const uint8_t sk[TC_X25519_KEY_LEN])
{
	uint8_t shared[TC_BOX_KEY_LEN];
	int rc = tc_box_beforenm(shared, sk, peer_pk);
	if (rc != TC_OK)
		return rc;
	rc = tc_secretbox_open(out, shared, nonce, ct, ct_len);
	tc_memzero_explicit(shared, sizeof shared);
	return rc;
}
