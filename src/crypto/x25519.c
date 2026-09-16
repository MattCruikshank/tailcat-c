/* SPDX-License-Identifier: BSD-3-Clause
 *
 * X25519, over Mbed TLS's Curve25519.
 *
 * Mbed TLS speaks big-endian MPIs while X25519 is defined on little-endian
 * 32-byte strings, so the conversions here are not incidental -- getting
 * them wrong yields a working-looking implementation that cannot
 * interoperate. RFC 7748's test vectors in tests/test_crypto.c pin it.
 */

#include "tc/crypto.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

#include <string.h>

/* Curve25519's base point, x = 9. */
static const uint8_t kBasePoint[TC_X25519_KEY_LEN] = { 9 };

void tc_x25519_clamp(uint8_t sk[TC_X25519_KEY_LEN])
{
	sk[0] = (uint8_t)(sk[0] & 248u);
	sk[31] = (uint8_t)((sk[31] & 127u) | 64u);
}

static void reverse32(uint8_t dst[32], const uint8_t src[32])
{
	for (size_t i = 0; i < 32; i++)
		dst[i] = src[31 - i];
}

/* rng_adapter exposes our CSPRNG in the shape Mbed TLS wants. */
static int rng_adapter(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return (tc_random_bytes(out, len) == TC_OK) ? 0 : -1;
}

/* scalarmult computes out = sk * point using mbedtls_ecp_mul on Curve25519.
 *
 * Two things here are easy to get wrong and are load-bearing:
 *
 *  - The scalar is clamped locally. X25519's decodeScalar25519 clamps, so
 *    RFC 7748's own test vectors supply unclamped scalars and expect the
 *    implementation to do it. Mbed TLS also rejects an unclamped scalar via
 *    mbedtls_ecp_check_privkey, so skipping this fails outright rather than
 *    quietly producing the wrong answer.
 *
 *  - f_rng must not be NULL. mbedtls_ecp_mul_restartable returns
 *    MBEDTLS_ERR_ECP_BAD_INPUT_DATA for a NULL RNG; it uses it to randomise
 *    the projective coordinates, which is a side-channel countermeasure we
 *    want anyway. */
static int scalarmult(uint8_t out[TC_X25519_KEY_LEN],
                      const uint8_t sk[TC_X25519_KEY_LEN],
                      const uint8_t point[TC_X25519_KEY_LEN])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point P, R;
	mbedtls_mpi d;
	uint8_t be[TC_X25519_KEY_LEN];
	uint8_t clamped[TC_X25519_KEY_LEN];
	int rc = TC_ERR_INVAL;
	int ret;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&P);
	mbedtls_ecp_point_init(&R);
	mbedtls_mpi_init(&d);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0)
		goto out;

	/* Scalar: clamp, then little-endian on the wire to big-endian MPI. */
	memcpy(clamped, sk, sizeof clamped);
	tc_x25519_clamp(clamped);
	reverse32(be, clamped);
	if (mbedtls_mpi_read_binary(&d, be, sizeof be) != 0)
		goto out;

	/* Point: only the u-coordinate travels. RFC 7748 says to ignore the
	 * most significant bit of the final byte on input. */
	reverse32(be, point);
	be[0] = (uint8_t)(be[0] & 0x7fu);
	if (mbedtls_mpi_read_binary(&P.MBEDTLS_PRIVATE(X), be, sizeof be) != 0)
		goto out;
	/* Montgomery representation: Z = 1, and Y is unused. */
	if (mbedtls_mpi_lset(&P.MBEDTLS_PRIVATE(Z), 1) != 0)
		goto out;

	ret = mbedtls_ecp_mul(&grp, &R, &d, &P, rng_adapter, NULL);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_write_binary(&R.MBEDTLS_PRIVATE(X), be, sizeof be) != 0)
		goto out;
	reverse32(out, be);
	rc = TC_OK;

out:
	tc_memzero_explicit(be, sizeof be);
	tc_memzero_explicit(clamped, sizeof clamped);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&R);
	mbedtls_ecp_point_free(&P);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int tc_x25519_base(uint8_t pk[TC_X25519_KEY_LEN],
                   const uint8_t sk[TC_X25519_KEY_LEN])
{
	return scalarmult(pk, sk, kBasePoint);
}

int tc_x25519(uint8_t out[TC_X25519_KEY_LEN],
              const uint8_t sk[TC_X25519_KEY_LEN],
              const uint8_t pk[TC_X25519_KEY_LEN])
{
	int rc = scalarmult(out, sk, pk);
	if (rc != TC_OK) {
		tc_memzero_explicit(out, TC_X25519_KEY_LEN);
		return rc;
	}

	/* A small-order peer public key drives the shared secret to zero, which
	 * an attacker can therefore predict. WireGuard rejects this and so must
	 * we. The check is constant time so it leaks nothing about out. */
	if (tc_ct_is_zero(out, TC_X25519_KEY_LEN)) {
		tc_memzero_explicit(out, TC_X25519_KEY_LEN);
		return TC_ERR_INVAL;
	}
	return TC_OK;
}

int tc_x25519_keypair(uint8_t sk[TC_X25519_KEY_LEN],
                      uint8_t pk[TC_X25519_KEY_LEN])
{
	int rc = tc_random_bytes(sk, TC_X25519_KEY_LEN);
	if (rc != TC_OK)
		return rc;
	tc_x25519_clamp(sk);

	rc = tc_x25519_base(pk, sk);
	if (rc != TC_OK)
		tc_memzero_explicit(sk, TC_X25519_KEY_LEN);
	return rc;
}
