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
