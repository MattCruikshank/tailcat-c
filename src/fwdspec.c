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

/* parse_dest reads the `host:port` tail of a mapping that names a destination
 * beyond the server.
 *
 * host may be an IPv4 literal or a bracketed IPv6 one. Unbracketed IPv6 is
 * refused rather than guessed at: "::1:80" has no unambiguous reading, and
 * RFC 3986 settled this argument for URLs long ago in favour of brackets. */
static int parse_dest(const char *host, const char *last_colon, const char *end,
                      tc_fwd_spec *out)
{
	size_t hlen = (size_t)(last_colon - host);
	if (hlen == 0) {
		FAILF("no host before the port");
		return TC_ERR_INVAL;
	}

	char buf[64];
	bool bracketed = (host[0] == '[');
	if (bracketed) {
		if (host[hlen - 1] != ']') {
			FAILF("an IPv6 destination must be written in brackets, as "
			      "[2001:db8::1]:443");
			return TC_ERR_INVAL;
		}
		host++;
		hlen -= 2;
	} else if (memchr(host, ':', hlen) != NULL) {
		FAILF("an IPv6 destination must be written in brackets, as "
		      "[2001:db8::1]:443");
		return TC_ERR_INVAL;
	}
	if (hlen == 0 || hlen >= sizeof buf) {
		FAILF("the destination address is not usable");
		return TC_ERR_INVAL;
	}
	memcpy(buf, host, hlen);
	buf[hlen] = '\0';

	uint16_t port = 0;
	int rc = parse_port(last_colon + 1, end, false, &port);
	if (rc != TC_OK)
		return rc;

	if (tc_endpoint_parse(&out->dst, buf, port) != TC_OK) {
		/* No DNS on purpose: a name resolved here would be resolved on the
		 * wrong machine. */
		FAILF("\"%.60s\" is not a literal IP address", buf);
		return TC_ERR_INVAL;
	}
	if (bracketed && out->dst.ip_len != 16) {
		FAILF("\"%.60s\" is in brackets but is not an IPv6 address", buf);
		return TC_ERR_INVAL;
	}
	out->remote_port = port;
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

	/* A second colon means the remote side names an address as well as a
	 * port, which only an exit node can serve. */
	const char *last = NULL;
	for (const char *q = colon + 1; q < end; q++) {
		if (*q == ':')
			last = q;
	}
	if (last != NULL) {
		int rc2 = parse_dest(colon + 1, last, end, out);
		if (rc2 != TC_OK)
			return rc2;
		return TC_OK;
	}

	rc = parse_port(colon + 1, end, false, &out->remote_port);
	if (rc != TC_OK) {
		/* An IPv6 literal has no second colon only if it is malformed, so
		 * this is the ordinary bad-port case. */
		return rc;
	}
	return TC_OK;
}
