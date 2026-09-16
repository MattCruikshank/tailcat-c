/* SPDX-License-Identifier: BSD-3-Clause
 *
 * HMAC-BLAKE2s-256 and the HKDF WireGuard builds on it.
 *
 * This deliberately uses HMAC (RFC 2104) around plain BLAKE2s rather than
 * BLAKE2s's own keyed mode. They are different constructions and are not
 * interchangeable: WireGuard's KDF is HMAC, so keyed BLAKE2s here would
 * produce different keys and fail to interoperate. Keyed BLAKE2s is used
 * elsewhere, for mac1/mac2.
 *
 * Mirrors device/noise-helpers.go in wireguard-go.
 */

#include "tc/crypto.h"

#include <string.h>

#define IPAD 0x36u
#define OPAD 0x5cu

void tc_hmac_blake2s(uint8_t out[TC_BLAKE2S_HASH_LEN], const uint8_t *key,
                     size_t keylen, const void *in0, size_t in0_len,
                     const void *in1, size_t in1_len)
{
	uint8_t k[TC_BLAKE2S_BLOCK_LEN];
	uint8_t pad[TC_BLAKE2S_BLOCK_LEN];
	uint8_t inner[TC_BLAKE2S_HASH_LEN];
	tc_blake2s_ctx ctx;

	/* RFC 2104: a key longer than the block size is replaced by its hash,
	 * and a shorter one is zero-padded. WireGuard only ever passes 32-byte
	 * keys, but handling the general case costs nothing and stops this being
	 * a trap if it is reused. */
	memset(k, 0, sizeof k);
	if (keylen > TC_BLAKE2S_BLOCK_LEN) {
		tc_blake2s(k, TC_BLAKE2S_HASH_LEN, key, keylen, NULL, 0);
	} else if (keylen > 0) {
		memcpy(k, key, keylen);
	}

	/* inner = BLAKE2s((k ^ ipad) || in0 || in1) */
	for (size_t i = 0; i < TC_BLAKE2S_BLOCK_LEN; i++)
		pad[i] = k[i] ^ IPAD;
	tc_blake2s_init(&ctx, TC_BLAKE2S_HASH_LEN);
	tc_blake2s_update(&ctx, pad, sizeof pad);
	if (in0_len > 0)
		tc_blake2s_update(&ctx, in0, in0_len);
	if (in1_len > 0)
		tc_blake2s_update(&ctx, in1, in1_len);
	tc_blake2s_final(&ctx, inner);

	/* out = BLAKE2s((k ^ opad) || inner) */
	for (size_t i = 0; i < TC_BLAKE2S_BLOCK_LEN; i++)
		pad[i] = k[i] ^ OPAD;
	tc_blake2s_init(&ctx, TC_BLAKE2S_HASH_LEN);
	tc_blake2s_update(&ctx, pad, sizeof pad);
	tc_blake2s_update(&ctx, inner, sizeof inner);
	tc_blake2s_final(&ctx, out);

	tc_memzero_explicit(k, sizeof k);
	tc_memzero_explicit(pad, sizeof pad);
	tc_memzero_explicit(inner, sizeof inner);
}

/* hmac1 is HMAC over a single input. */
static void hmac1(uint8_t out[TC_BLAKE2S_HASH_LEN], const uint8_t *key,
                  size_t keylen, const void *in, size_t in_len)
{
	tc_hmac_blake2s(out, key, keylen, in, in_len, NULL, 0);
}

void tc_kdf1(uint8_t t0[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len)
{
	uint8_t prk[TC_BLAKE2S_HASH_LEN];
	static const uint8_t one = 0x01;

	hmac1(prk, key, TC_BLAKE2S_HASH_LEN, input, input_len);
	hmac1(t0, prk, sizeof prk, &one, 1);

	tc_memzero_explicit(prk, sizeof prk);
}

void tc_kdf2(uint8_t t0[TC_BLAKE2S_HASH_LEN], uint8_t t1[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len)
{
	uint8_t prk[TC_BLAKE2S_HASH_LEN];
	static const uint8_t one = 0x01, two = 0x02;

	hmac1(prk, key, TC_BLAKE2S_HASH_LEN, input, input_len);
	hmac1(t0, prk, sizeof prk, &one, 1);
	tc_hmac_blake2s(t1, prk, sizeof prk, t0, TC_BLAKE2S_HASH_LEN, &two, 1);

	tc_memzero_explicit(prk, sizeof prk);
}

void tc_kdf3(uint8_t t0[TC_BLAKE2S_HASH_LEN], uint8_t t1[TC_BLAKE2S_HASH_LEN],
             uint8_t t2[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len)
{
	uint8_t prk[TC_BLAKE2S_HASH_LEN];
	static const uint8_t one = 0x01, two = 0x02, three = 0x03;

	hmac1(prk, key, TC_BLAKE2S_HASH_LEN, input, input_len);
	hmac1(t0, prk, sizeof prk, &one, 1);
	tc_hmac_blake2s(t1, prk, sizeof prk, t0, TC_BLAKE2S_HASH_LEN, &two, 1);
	tc_hmac_blake2s(t2, prk, sizeof prk, t1, TC_BLAKE2S_HASH_LEN, &three, 1);

	tc_memzero_explicit(prk, sizeof prk);
}
