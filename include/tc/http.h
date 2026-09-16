/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A minimal HTTPS GET, enough to fetch a DERP map.
 *
 * Not a general HTTP client. It does one GET, follows at most a couple of
 * redirects, and reads a body delimited either by Content-Length or by
 * chunked transfer encoding. No keep-alive, no cookies, no compression, no
 * request bodies.
 *
 * The response comes from a host we do not control, so every length in it is
 * treated as hostile: the body is bounded by the caller's buffer, the header
 * block is bounded, and a chunk size that does not fit is an error rather
 * than something to allocate for.
 */
#ifndef TC_HTTP_H_
#define TC_HTTP_H_

#include "tc/tc.h"

/* Bounds on what we will read before giving up. */
#define TC_HTTP_MAX_HEADERS 16384
#define TC_HTTP_MAX_REDIRECTS 2

typedef struct {
	/* Skip TLS certificate verification. For testing only. */
	bool insecure_skip_verify;
	/* 0 means a default. Bounds both the connect and each read. */
	int timeout_ms;
} tc_http_options;

/* tc_http_get fetches https://host[:port]/path into out.
 *
 * On success *out_len holds the body length and *status the HTTP status
 * code; a non-2xx status is still reported as TC_OK with the status set, so
 * the caller can distinguish "the server said 404" from "the transport
 * failed".
 *
 * A body larger than cap gives TC_ERR_TOOMANY rather than a truncated
 * document, because a half-parsed DERP map is worse than none. */
int tc_http_get(const char *url, uint8_t *out, size_t cap, size_t *out_len,
                int *status, const tc_http_options *opts);

/* tc_http_error_string describes the last failure on this thread, or "". */
const char *tc_http_error_string(void);

/* tc_http_parse_url splits an https URL into its parts. Exposed for tests.
 * scheme must be https; anything else is refused, since this only ever
 * fetches a control document and doing so in the clear would let a relay be
 * substituted. */
int tc_http_parse_url(const char *url, char *host, size_t host_cap,
                      uint16_t *port, char *path, size_t path_cap);

#endif /* TC_HTTP_H_ */
