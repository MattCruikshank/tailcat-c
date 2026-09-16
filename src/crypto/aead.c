/* SPDX-License-Identifier: BSD-3-Clause
 *
 * ChaCha20-Poly1305 (RFC 8439), over Mbed TLS.
 */

#include "tc/crypto.h"

#include "mbedtls/chachapoly.h"

#include <string.h>

/* WireGuard's nonce is four zero bytes followed by the 64-bit counter,
 * little-endian. */
static void nonce_from_counter(uint8_t nonce[TC_AEAD_NONCE_LEN],
                               uint64_t counter)
{
	memset(nonce, 0, 4);
	for (size_t i = 0; i < 8; i++)
		nonce[4 + i] = (uint8_t)(counter >> (8u * i));
}

int tc_aead_seal_nonce(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                       const uint8_t nonce[TC_AEAD_NONCE_LEN], const void *ad,
                       size_t ad_len, const void *pt, size_t pt_len)
{
	mbedtls_chachapoly_context ctx;
	int rc = TC_ERR_INVAL;

	if (out == NULL || key == NULL || nonce == NULL)
		return TC_ERR_INVAL;
	if (pt_len > SIZE_MAX - TC_AEAD_TAG_LEN)
		return TC_ERR_RANGE;

	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key) != 0)
		goto out;

	/* The tag is written directly after the ciphertext, which is the layout
	 * every caller wants and matches what WireGuard puts on the wire. */
	if (mbedtls_chachapoly_encrypt_and_tag(
	        &ctx, pt_len, nonce, (const unsigned char *)ad, ad_len,
	        (const unsigned char *)pt, out, out + pt_len) != 0)
		goto out;

	rc = TC_OK;
out:
	mbedtls_chachapoly_free(&ctx);
	return rc;
}

int tc_aead_open_nonce(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                       const uint8_t nonce[TC_AEAD_NONCE_LEN], const void *ad,
                       size_t ad_len, const void *ct, size_t ct_len)
{
	mbedtls_chachapoly_context ctx;
	int rc = TC_ERR_INVAL;

	if (key == NULL || nonce == NULL || ct == NULL)
		return TC_ERR_INVAL;
	if (ct_len < TC_AEAD_TAG_LEN)
		return TC_ERR_INVAL;

	size_t pt_len = ct_len - TC_AEAD_TAG_LEN;
	if (out == NULL && pt_len != 0)
		return TC_ERR_INVAL;

	const uint8_t *ctb = (const uint8_t *)ct;

	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key) != 0)
		goto out;

	/* mbedtls_chachapoly_auth_decrypt verifies the tag before releasing any
	 * plaintext, so a forged packet never yields attacker-chosen bytes. */
	if (mbedtls_chachapoly_auth_decrypt(&ctx, pt_len, nonce,
	                                    (const unsigned char *)ad, ad_len,
	                                    ctb + pt_len, ctb, out) != 0) {
		/* Do not leave a partial decryption behind for a caller that
		 * forgets to check the return value. */
		if (out != NULL && pt_len != 0)
			tc_memzero_explicit(out, pt_len);
		rc = TC_ERR_INVAL;
		goto out;
	}

	rc = TC_OK;
out:
	mbedtls_chachapoly_free(&ctx);
	return rc;
}

int tc_aead_seal(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                 uint64_t counter, const void *ad, size_t ad_len,
                 const void *pt, size_t pt_len)
{
	uint8_t nonce[TC_AEAD_NONCE_LEN];
	nonce_from_counter(nonce, counter);
	int rc = tc_aead_seal_nonce(out, key, nonce, ad, ad_len, pt, pt_len);
	tc_memzero_explicit(nonce, sizeof nonce);
	return rc;
}

int tc_aead_open(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                 uint64_t counter, const void *ad, size_t ad_len,
                 const void *ct, size_t ct_len)
{
	uint8_t nonce[TC_AEAD_NONCE_LEN];
	nonce_from_counter(nonce, counter);
	int rc = tc_aead_open_nonce(out, key, nonce, ad, ad_len, ct, ct_len);
	tc_memzero_explicit(nonce, sizeof nonce);
	return rc;
}

/* ---- XChaCha20-Poly1305 ----------------------------------------------- */

static uint32_t rd32le_c(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static void wr32le_c(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint32_t rotl32(uint32_t v, unsigned n)
{
	return (uint32_t)((v << n) | (v >> (32u - n)));
}

#define QR(a, b, c, d)                                                        \
	do {                                                                      \
		a += b; d ^= a; d = rotl32(d, 16);                                    \
		c += d; b ^= c; b = rotl32(b, 12);                                    \
		a += b; d ^= a; d = rotl32(d, 8);                                     \
		c += d; b ^= c; b = rotl32(b, 7);                                     \
	} while (0)

void tc_hchacha20(uint8_t out[TC_AEAD_KEY_LEN],
                  const uint8_t key[TC_AEAD_KEY_LEN], const uint8_t nonce[16])
{
	/* "expand 32-byte k" */
	uint32_t st[16] = { 0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u };

	for (int i = 0; i < 8; i++)
		st[4 + i] = rd32le_c(key + 4 * i);
	for (int i = 0; i < 4; i++)
		st[12 + i] = rd32le_c(nonce + 4 * i);

	for (int i = 0; i < 10; i++) {
		QR(st[0], st[4], st[8], st[12]);
		QR(st[1], st[5], st[9], st[13]);
		QR(st[2], st[6], st[10], st[14]);
		QR(st[3], st[7], st[11], st[15]);
		QR(st[0], st[5], st[10], st[15]);
		QR(st[1], st[6], st[11], st[12]);
		QR(st[2], st[7], st[8], st[13]);
		QR(st[3], st[4], st[9], st[14]);
	}

	/* No feed-forward addition here, unlike ChaCha20 proper. Adding the
	 * original state back would make the output invertible given the key,
	 * which is exactly what a key-derivation step must not be. */
	for (int i = 0; i < 4; i++)
		wr32le_c(out + 4 * i, st[i]);
	for (int i = 0; i < 4; i++)
		wr32le_c(out + 16 + 4 * i, st[12 + i]);

	tc_memzero_explicit(st, sizeof st);
}

#undef QR

/* xsplit derives the subkey and the 96-bit nonce XChaCha hands to ChaCha. */
static void xsplit(uint8_t subkey[TC_AEAD_KEY_LEN],
                   uint8_t nonce12[TC_AEAD_NONCE_LEN],
                   const uint8_t key[TC_AEAD_KEY_LEN],
                   const uint8_t nonce[TC_XAEAD_NONCE_LEN])
{
	tc_hchacha20(subkey, key, nonce);
	memset(nonce12, 0, 4);
	memcpy(nonce12 + 4, nonce + 16, 8);
}

int tc_xaead_seal(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                  const uint8_t nonce[TC_XAEAD_NONCE_LEN], const void *ad,
                  size_t ad_len, const void *pt, size_t pt_len)
{
	if (key == NULL || nonce == NULL)
		return TC_ERR_INVAL;
	uint8_t subkey[TC_AEAD_KEY_LEN], n12[TC_AEAD_NONCE_LEN];
	xsplit(subkey, n12, key, nonce);
	int rc = tc_aead_seal_nonce(out, subkey, n12, ad, ad_len, pt, pt_len);
	tc_memzero_explicit(subkey, sizeof subkey);
	return rc;
}

int tc_xaead_open(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                  const uint8_t nonce[TC_XAEAD_NONCE_LEN], const void *ad,
                  size_t ad_len, const void *ct, size_t ct_len)
{
	if (key == NULL || nonce == NULL)
		return TC_ERR_INVAL;
	uint8_t subkey[TC_AEAD_KEY_LEN], n12[TC_AEAD_NONCE_LEN];
	xsplit(subkey, n12, key, nonce);
	int rc = tc_aead_open_nonce(out, subkey, n12, ad, ad_len, ct, ct_len);
	tc_memzero_explicit(subkey, sizeof subkey);
	return rc;
}
