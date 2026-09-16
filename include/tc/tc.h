/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Tailscale Inc & contributors
 * Copyright (c) tailcat-c contributors
 *
 * Common definitions for tailcat-c.
 */
#ifndef TC_TC_H_
#define TC_TC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Error codes. All tailcat-c functions that can fail return one of these:
 * TC_OK on success, or a negative value. Never errno. */
enum {
	TC_OK = 0,
	TC_ERR_INVAL = -1,       /* malformed or unacceptable input */
	TC_ERR_NOSPACE = -2,     /* caller's output buffer is too small */
	TC_ERR_TRUNC = -3,       /* input ended in the middle of an item */
	TC_ERR_RANGE = -4,       /* value does not fit the destination type */
	TC_ERR_UNSUPPORTED = -5, /* well-formed but not a feature we implement */
	TC_ERR_TOOMANY = -6,     /* more elements than a fixed-size limit allows */
	TC_ERR_TIMEOUT = -7,     /* the deadline passed with nothing to read */
	TC_ERR_EXIST = -8,       /* the thing being created is already there */
	TC_ERR_AGAIN = -9,       /* not ready yet; the caller should retry */
	TC_ERR_CLOSED = -10      /* the peer hung up; reconnecting may help */
};

/* tc_strerror returns a short static description of a TC_ERR_* code.
 * The returned pointer is never NULL and never needs freeing. */
const char *tc_strerror(int err);

/* Key sizes, matching tailscale.com/types/key and wireguard-go. */
#define TC_NODE_KEY_LEN 32
#define TC_DISCO_KEY_LEN 32
#define TC_PSK_LEN 32

/* tc_memzero_explicit clears n bytes at p in a way the compiler may not
 * elide, for wiping key material. */
void tc_memzero_explicit(void *p, size_t n);

/* tc_ct_is_zero reports whether the n bytes at p are all zero, in constant
 * time with respect to the contents. */
bool tc_ct_is_zero(const void *p, size_t n);

/* tc_ct_equal reports whether the n bytes at a and b are equal, in constant
 * time with respect to the contents. */
bool tc_ct_equal(const void *a, const void *b, size_t n);

#endif /* TC_TC_H_ */
