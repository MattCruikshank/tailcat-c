/* SPDX-License-Identifier: Apache-2.0
 *
 * Minimal Mbed TLS configuration for tailcat-c.
 *
 * tailcat-c needs exactly four things from Mbed TLS:
 *
 *   - X25519, for the Noise handshake's Diffie-Hellman;
 *   - ChaCha20-Poly1305, for both the handshake and transport AEAD;
 *   - a seeded CSPRNG, for keys and nonces;
 *   - (from M3 on) a TLS 1.2/1.3 client, because DERP speaks HTTPS.
 *
 * Everything else is switched off, which keeps the fat binary small and,
 * more usefully, keeps code we never call out of the attack surface.
 *
 * BLAKE2s is deliberately absent: Mbed TLS does not implement it, and
 * WireGuard's Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s needs it for the hash,
 * the mac1/mac2 keyed MAC and the HMAC the KDF is built on. That is
 * src/crypto/blake2s.c.
 */
#ifndef TC_MBEDTLS_CONFIG_H_
#define TC_MBEDTLS_CONFIG_H_

/* ---- platform -------------------------------------------------------- */

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_HAVE_TIME
/* No MBEDTLS_FS_IO: we never read keys or certificates off disk, and it is
 * one less thing reachable from parsed input. */

/* ---- symmetric ------------------------------------------------------- */

#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* AES and GCM are needed by CTR_DRBG and, later, by the TLS cipher suites
 * every real server offers. */
#define MBEDTLS_AES_C

/* ---- hashing --------------------------------------------------------- */

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA224_C

/* ---- randomness ------------------------------------------------------ */

#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* ---- public key / X25519 --------------------------------------------- */

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C

#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
/* Curves real DERP servers' certificates and key exchanges use. */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

#define MBEDTLS_ECP_NIST_OPTIM

/* ---- TLS client ------------------------------------------------------
 *
 * Deliberately not enabled yet. DERP speaks HTTPS, so M3 turns on
 * MBEDTLS_SSL_CLI_C / MBEDTLS_SSL_TLS_C / MBEDTLS_X509_CRT_PARSE_C and the
 * ECDHE key exchanges. Note that TLS 1.3 in Mbed TLS 3.6 additionally
 * requires the PSA crypto layer (MBEDTLS_PSA_CRYPTO_C and its HKDF), which
 * pulls in a substantial amount of code; enabling TLS 1.3 without it fails
 * check_config.h's prerequisite test. Left for M3 so that M2 builds the
 * smallest thing that can be verified against RFC vectors.
 */

#endif /* TC_MBEDTLS_CONFIG_H_ */
