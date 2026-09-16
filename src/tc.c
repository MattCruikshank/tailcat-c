/* SPDX-License-Identifier: BSD-3-Clause */

#include "tc/tc.h"

#include <string.h>

const char *tc_strerror(int err)
{
	switch (err) {
	case TC_OK:              return "ok";
	case TC_ERR_INVAL:       return "malformed input";
	case TC_ERR_NOSPACE:     return "output buffer too small";
	case TC_ERR_TRUNC:       return "input truncated";
	case TC_ERR_RANGE:       return "value out of range";
	case TC_ERR_UNSUPPORTED: return "unsupported encoding";
	case TC_ERR_TOOMANY:     return "too many elements";
	case TC_ERR_TIMEOUT:     return "timed out";
	case TC_ERR_EXIST:       return "already exists";
	default:                 return "unknown error";
	}
}

/* A volatile function pointer to memset, which the compiler is not permitted
 * to reason through and therefore cannot optimise away. This is the portable
 * trick; cosmocc has no explicit_bzero guarantee we want to rely on. */
static void *(*const volatile tc_memset_ptr)(void *, int, size_t) = memset;

void tc_memzero_explicit(void *p, size_t n)
{
	if (p != NULL && n != 0)
		tc_memset_ptr(p, 0, n);
}

bool tc_ct_is_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= b[i];
	return acc == 0;
}

bool tc_ct_equal(const void *a, const void *b, size_t n)
{
	const uint8_t *x = (const uint8_t *)a;
	const uint8_t *y = (const uint8_t *)b;
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= (uint8_t)(x[i] ^ y[i]);
	return acc == 0;
}
