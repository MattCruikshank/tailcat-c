/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The CSPRNG: Mbed TLS's CTR_DRBG seeded from operating-system entropy.
 *
 * Failure here is never silent. Every path that cannot produce real random
 * bytes zeroes the caller's buffer and returns an error, so a caller that
 * ignores the return value gets zeroes -- which will fail loudly downstream
 * -- rather than something predictable that still looks like a key.
 */

#include "tc/crypto.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <pthread.h>
#include <string.h>

/* Cosmopolitan's PTHREAD_MUTEX_INITIALIZER does not name every member of its
 * pthread_mutex_t, so -Wmissing-field-initializers fires on a perfectly
 * correct use of the standard macro. Unnamed members are zero-initialised,
 * which is what the macro intends; suppress it here rather than weakening the
 * warning set for the whole project. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#pragma GCC diagnostic pop
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static bool g_ready;

/* A personalisation string, per NIST SP 800-90A. It need not be secret; it
 * just separates our DRBG instance from any other on the machine seeded from
 * the same entropy at the same moment. */
static const char kPersonalization[] = "tailcat-c ctr_drbg v1";

static int init_locked(void)
{
	if (g_ready)
		return TC_OK;

	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_drbg);

	if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
	                          (const unsigned char *)kPersonalization,
	                          sizeof kPersonalization - 1) != 0) {
		mbedtls_ctr_drbg_free(&g_drbg);
		mbedtls_entropy_free(&g_entropy);
		return TC_ERR_INVAL;
	}

	/* Reseed periodically rather than relying on a single boot-time seed. */
	mbedtls_ctr_drbg_set_reseed_interval(&g_drbg, 16384);

	g_ready = true;
	return TC_OK;
}

int tc_random_init(void)
{
	pthread_mutex_lock(&g_lock);
	int rc = init_locked();
	pthread_mutex_unlock(&g_lock);
	return rc;
}

int tc_random_bytes(void *buf, size_t n)
{
	if (buf == NULL)
		return TC_ERR_INVAL;
	if (n == 0)
		return TC_OK;

	pthread_mutex_lock(&g_lock);
	int rc = init_locked();
	if (rc == TC_OK) {
		/* ctr_drbg caps a single request; loop so callers never have to. */
		uint8_t *p = (uint8_t *)buf;
		size_t left = n;
		while (left > 0) {
			size_t chunk = left;
			if (chunk > MBEDTLS_CTR_DRBG_MAX_REQUEST)
				chunk = MBEDTLS_CTR_DRBG_MAX_REQUEST;
			if (mbedtls_ctr_drbg_random(&g_drbg, p, chunk) != 0) {
				rc = TC_ERR_INVAL;
				break;
			}
			p += chunk;
			left -= chunk;
		}
	}
	pthread_mutex_unlock(&g_lock);

	if (rc != TC_OK)
		tc_memzero_explicit(buf, n);
	return rc;
}
