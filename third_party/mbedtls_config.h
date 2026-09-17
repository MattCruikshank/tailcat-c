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

/* mbedtls_strerror. A TLS handshake fails for many distinguishable reasons
 * and "TC_ERR_INVAL" is useless when diagnosing a relay that will not talk to
 * us, so the few KB of message tables earn their place. */
#define MBEDTLS_ERROR_C
/* No MBEDTLS_FS_IO: we never read keys or certificates off disk, and it is
 * one less thing reachable from parsed input. */

/* ---- symmetric ------------------------------------------------------- */

#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* AES and GCM are needed by CTR_DRBG and by the TLS cipher suites every real
 * server offers. */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C

/* ---- hashing --------------------------------------------------------- */

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA224_C
/* SHA-384 suites and SHA-384 certificate signatures are both common. */
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA384_C

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
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

#define MBEDTLS_ECP_NIST_OPTIM

/* ---- TLS client ------------------------------------------------------
 *
 * DERP speaks HTTPS, so the relay transport needs a TLS client.
 *
 * TLS 1.2 only, and the reason is interoperability rather than code size.
 *
 * Phase 5.3 enabled 1.3 and reverted it. Enabling it is genuinely easy: add
 * MBEDTLS_SSL_PROTO_TLS1_3, the PSA crypto layer it requires
 * (MBEDTLS_PSA_CRYPTO_C plus HKDF, and *not* MBEDTLS_PSA_CRYPTO_CONFIG,
 * whose defaults drag in ARIA, Camellia, CCM and DES), about twenty extra
 * Mbed TLS source files, and a psa_crypto_init() before the first context.
 * That builds, links, and costs 232 KB -- about 11%.
 *
 * It also cannot connect to a single Tailscale relay.
 *
 * DERP servers append a self-signed *meta certificate* to the chain, which
 * encodes the server's public key in its CommonName so a client can skip a
 * round trip. They send it only on TLS 1.3, because 1.3 encrypts the
 * certificate chain and 1.2 does not -- see initMetacert in
 * tailscale.com/derp/derpserver. That certificate is Ed25519, and Mbed TLS
 * 3.6 cannot parse an Ed25519 certificate at all: the chain is rejected
 * whole, with "X509 - Signature algorithm (oid) is unsupported", before any
 * verification happens. Every relay becomes unreachable.
 *
 * Making it work would mean teaching a vendored TLS library to skip
 * certificates it cannot parse, in the middle of chain validation. That is
 * not a change to make for an optimisation we do not implement.
 *
 * So the gain was never "1.3 is better than 1.2" -- 1.2 with ECDHE and AEAD
 * suites is not a weak configuration. The gain would have been upstream's
 * "fast start", which reads the DERP key out of that same meta certificate;
 * and the thing that blocks 1.3 is the thing fast start is made of.
 */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* Certificate handling, and the public-key algorithms real certificate
 * chains are signed with. */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

#endif /* TC_MBEDTLS_CONFIG_H_ */
