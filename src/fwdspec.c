/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See fwdspec.h. Parsing one port-forwarding mapping.
 */

#include "tc/fwdspec.h"

#include <stdio.h>
#include <string.h>

static _Thread_local char g_err[160];

const char *tc_fwd_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

/* parse_port reads a decimal port from [s, end). allow_zero is only true for
 * the local side, where 0 means "let the operating system choose". */
static int parse_port(const char *s, const char *end, bool allow_zero,
                      uint16_t *out)
{
	if (s >= end) {
		FAILF("expected a port number");
		return TC_ERR_INVAL;
	}
	uint32_t v = 0;
	for (const char *p = s; p < end; p++) {
		if (*p < '0' || *p > '9') {
			FAILF("\"%.*s\" is not a port number", (int)(end - s), s);
			return TC_ERR_INVAL;
		}
		v = v * 10u + (uint32_t)(*p - '0');
		if (v > 65535u) {
			FAILF("\"%.*s\" is above 65535", (int)(end - s), s);
			return TC_ERR_RANGE;
		}
	}
	if (v == 0 && !allow_zero) {
		FAILF("port 0 is not a port");
		return TC_ERR_INVAL;
	}
	*out = (uint16_t)v;
	return TC_OK;
}

int tc_fwd_parse(tc_fwd_spec *out, const char *spec)
{
	if (out == NULL || spec == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';
	memset(out, 0, sizeof *out);

	const char *end = spec + strlen(spec);
	if (spec == end) {
		FAILF("empty mapping");
		return TC_ERR_INVAL;
	}

	const char *colon = memchr(spec, ':', (size_t)(end - spec));
	if (colon == NULL) {
		/* One port: the same on both sides. Zero is not allowed here,
		 * because an OS-chosen local port would leave no remote port to
		 * pair it with. */
		int rc = parse_port(spec, end, false, &out->remote_port);
		if (rc != TC_OK)
			return rc;
		out->local_port = out->remote_port;
		return TC_OK;
	}

	int rc = parse_port(spec, colon, true, &out->local_port);
	if (rc != TC_OK) {
		/* Via a copy: snprintf'ing g_err into itself is undefined, and the
		 * compiler says so. */
		char why[sizeof g_err];
		(void)snprintf(why, sizeof why, "%s", g_err);
		FAILF("local port: %.120s", why);
		return rc;
	}

	/* A second colon means the remote side is an address rather than a port,
	 * which only an exit node can serve. Saying so beats "not a port
	 * number": the syntax is right, the feature is missing. */
	if (memchr(colon + 1, ':', (size_t)(end - colon - 1)) != NULL) {
		FAILF("forwarding to \"%s\" needs the server to be an exit node, "
		      "which is not implemented here",
		      colon + 1);
		return TC_ERR_UNSUPPORTED;
	}

	rc = parse_port(colon + 1, end, false, &out->remote_port);
	if (rc != TC_OK) {
		/* An IPv6 literal has no second colon only if it is malformed, so
		 * this is the ordinary bad-port case. */
		return rc;
	}
	return TC_OK;
}
