/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The cryptography tailcat-c needs, which is exactly the primitive set of
 * WireGuard's Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s:
 *
 *   - X25519            Diffie-Hellman
 *   - ChaCha20-Poly1305 AEAD, for the handshake and the transport
 *   - BLAKE2s           the hash, and the keyed MAC behind mac1/mac2
 *   - HMAC-BLAKE2s      which the KDF is built on
 *
 * X25519, ChaCha20-Poly1305 and the CSPRNG come from Mbed TLS rather than
 * being hand-written. For a security-critical rewrite that is the right
 * trade: constant-time field arithmetic is exactly where hand-rolled
 * implementations go wrong, and Mbed TLS is maintained and gets CVE fixes.
 *
 * BLAKE2s is implemented here because Mbed TLS does not provide it and
 * WireGuard cannot be done without it.
 */
#ifndef TC_CRYPTO_H_
#define TC_CRYPTO_H_

#include "tc/tc.h"

/* ---- BLAKE2s (RFC 7693) ---------------------------------------------- */

#define TC_BLAKE2S_BLOCK_LEN 64
#define TC_BLAKE2S_HASH_LEN 32 /* WireGuard's HASH and HMAC output */
#define TC_BLAKE2S_MAC_LEN 16  /* WireGuard's mac1/mac2 output */
#define TC_BLAKE2S_KEY_MAX 32

typedef struct {
	uint32_t h[8];
	uint64_t t;    /* bytes absorbed so far */
	uint8_t buf[TC_BLAKE2S_BLOCK_LEN];
	size_t buflen; /* bytes pending in buf */
	size_t outlen;
} tc_blake2s_ctx;

/* tc_blake2s_init starts an unkeyed hash with an outlen-byte digest.
 * outlen must be in 1..32. */
void tc_blake2s_init(tc_blake2s_ctx *ctx, size_t outlen);

/* tc_blake2s_init_key starts a keyed hash (a MAC). keylen must be 0..32;
 * a zero-length key is the same as tc_blake2s_init. */
void tc_blake2s_init_key(tc_blake2s_ctx *ctx, size_t outlen,
                         const uint8_t *key, size_t keylen);

void tc_blake2s_update(tc_blake2s_ctx *ctx, const void *in, size_t inlen);

/* tc_blake2s_final writes ctx->outlen bytes to out and wipes the context. */
void tc_blake2s_final(tc_blake2s_ctx *ctx, uint8_t *out);

/* tc_blake2s is the one-shot form. Pass key=NULL, keylen=0 to hash. */
void tc_blake2s(uint8_t *out, size_t outlen, const void *in, size_t inlen,
                const uint8_t *key, size_t keylen);

/* ---- HMAC-BLAKE2s-256 and WireGuard's KDF ---------------------------- */

/* tc_hmac_blake2s computes HMAC-BLAKE2s-256 over in0 followed by in1.
 * in1 may be NULL with in1_len 0; the two-input form exists because
 * WireGuard's KDF always feeds either one or two pieces and this avoids a
 * scratch buffer. */
void tc_hmac_blake2s(uint8_t out[TC_BLAKE2S_HASH_LEN], const uint8_t *key,
                     size_t keylen, const void *in0, size_t in0_len,
                     const void *in1, size_t in1_len);

/* The HKDF WireGuard uses: prk = HMAC(key, input), then successive
 * HMAC(prk, prev || counter) for counter = 1, 2, 3.
 *
 * `key` here is the Noise chaining key and is always 32 bytes; `input` is
 * the DH output or the pre-shared key. Outputs are independent buffers. */
void tc_kdf1(uint8_t t0[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len);
void tc_kdf2(uint8_t t0[TC_BLAKE2S_HASH_LEN], uint8_t t1[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len);
void tc_kdf3(uint8_t t0[TC_BLAKE2S_HASH_LEN], uint8_t t1[TC_BLAKE2S_HASH_LEN],
             uint8_t t2[TC_BLAKE2S_HASH_LEN],
             const uint8_t key[TC_BLAKE2S_HASH_LEN], const void *input,
             size_t input_len);

/* ---- X25519 (RFC 7748) ----------------------------------------------- */

#define TC_X25519_KEY_LEN 32

/* tc_x25519_clamp applies WireGuard's private-key clamping in place. */
void tc_x25519_clamp(uint8_t sk[TC_X25519_KEY_LEN]);

/* tc_x25519_keypair generates a clamped private key and its public key. */
int tc_x25519_keypair(uint8_t sk[TC_X25519_KEY_LEN],
                      uint8_t pk[TC_X25519_KEY_LEN]);

/* tc_x25519_base computes the public key for sk. */
int tc_x25519_base(uint8_t pk[TC_X25519_KEY_LEN],
                   const uint8_t sk[TC_X25519_KEY_LEN]);

/* tc_x25519 computes the shared secret.
 *
 * It returns TC_ERR_INVAL when the result is all zeroes, which happens for
 * small-order peer public keys. WireGuard treats that as an invalid public
 * key and so do we -- accepting it would mean agreeing a shared secret an
 * attacker also knows. */
int tc_x25519(uint8_t out[TC_X25519_KEY_LEN],
              const uint8_t sk[TC_X25519_KEY_LEN],
              const uint8_t pk[TC_X25519_KEY_LEN]);

/* ---- ChaCha20-Poly1305 (RFC 8439) ------------------------------------ */

#define TC_AEAD_KEY_LEN 32
#define TC_AEAD_TAG_LEN 16
#define TC_AEAD_NONCE_LEN 12

/* WireGuard forms the 12-byte nonce as four zero bytes followed by the
 * 64-bit counter, little-endian. These take the counter directly so no
 * caller has to remember that. */

/* tc_aead_seal writes ptlen + TC_AEAD_TAG_LEN bytes to out. out may equal pt
 * for in-place encryption, provided the buffer has room for the tag. */
int tc_aead_seal(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                 uint64_t counter, const void *ad, size_t ad_len,
                 const void *pt, size_t pt_len);

/* tc_aead_open verifies and decrypts, writing ct_len - TC_AEAD_TAG_LEN bytes
 * to out. It returns TC_ERR_INVAL if authentication fails, in which case out
 * holds nothing an attacker chose. ct_len must be at least TC_AEAD_TAG_LEN. */
int tc_aead_open(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                 uint64_t counter, const void *ad, size_t ad_len,
                 const void *ct, size_t ct_len);

/* Raw-nonce forms, for anything that does not use WireGuard's counter
 * convention. */
int tc_aead_seal_nonce(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                       const uint8_t nonce[TC_AEAD_NONCE_LEN], const void *ad,
                       size_t ad_len, const void *pt, size_t pt_len);
int tc_aead_open_nonce(uint8_t *out, const uint8_t key[TC_AEAD_KEY_LEN],
                       const uint8_t nonce[TC_AEAD_NONCE_LEN], const void *ad,
                       size_t ad_len, const void *ct, size_t ct_len);

/* ---- CSPRNG ---------------------------------------------------------- */

/* tc_random_init seeds the generator from the operating system. It is safe
 * to call more than once and is called automatically by tc_random_bytes, so
 * most callers can ignore it; it exists so a program can fail loudly at
 * startup rather than at first key generation. */
int tc_random_init(void);

/* tc_random_bytes fills buf with cryptographically secure random bytes.
 * It is thread-safe. On failure it returns non-TC_OK and zeroes buf, so a
 * caller that ignores the result never gets predictable bytes. */
int tc_random_bytes(void *buf, size_t n);

#endif /* TC_CRYPTO_H_ */
