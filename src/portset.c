/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See portset.h. Parsing a served-port spec.
 *
 * This runs on an argv string rather than on the network, so it is not
 * attacker-controlled in the way the CBOR and JSON readers are. It still
 * refuses rather than guesses: a typo in a port list silently becoming a
 * different set of open ports is exactly the kind of quiet wrong answer that
 * a server should not give.
 */

#include "tc/portset.h"

#include <stdio.h>
#include <string.h>

static _Thread_local char g_err[160];

const char *tc_portset_error_string(void)
{
	return g_err;
}

#define FAILF(...)                                                            \
	do {                                                                      \
		(void)snprintf(g_err, sizeof g_err, __VA_ARGS__);                     \
	} while (0)

void tc_portset_clear(tc_portset *ps)
{
	if (ps != NULL)
		memset(ps, 0, sizeof *ps);
}

void tc_portset_add(tc_portset *ps, uint16_t port)
{
	if (ps == NULL || port == 0)
		return;
	uint8_t mask = (uint8_t)(1u << (port & 7u));
	if ((ps->bits[port >> 3] & mask) == 0) {
		ps->bits[port >> 3] |= mask;
		ps->count++;
	}
}

bool tc_portset_has(const tc_portset *ps, uint16_t port)
{
	if (ps == NULL || port == 0)
		return false;
	return (ps->bits[port >> 3] & (uint8_t)(1u << (port & 7u))) != 0;
}

void tc_portset_add_range(tc_portset *ps, uint16_t lo, uint16_t hi)
{
	if (ps == NULL)
		return;
	if (lo > hi) {
		uint16_t t = lo;
		lo = hi;
		hi = t;
	}
	/* Counting up to hi inclusive with a uint16_t would never terminate at
	 * 65535, so the loop counter is wider than the values it holds. */
	for (uint32_t p = lo; p <= hi; p++)
		tc_portset_add(ps, (uint16_t)p);
}

static const struct {
	const char *word;
	tc_portset_service svc;
} kServices[] = {
	{ "ssh", TC_PORTSET_SVC_SSH },
	{ "no-auth-ssh", TC_PORTSET_SVC_NO_AUTH_SSH },
	{ "files", TC_PORTSET_SVC_FILES },
	{ "exec", TC_PORTSET_SVC_EXEC },
	{ "exit-node", TC_PORTSET_SVC_EXIT_NODE },
};

const char *tc_portset_service_name(tc_portset_service svc)
{
	for (size_t i = 0; i < sizeof kServices / sizeof kServices[0]; i++) {
		if (kServices[i].svc == svc)
			return kServices[i].word;
	}
	return "";
}

/* parse_num reads a decimal port number from [s, end). */
static int parse_num(const char *s, const char *end, uint16_t *out)
{
	if (s == end) {
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
	if (v == 0) {
		FAILF("port 0 is not a port");
		return TC_ERR_INVAL;
	}
	*out = (uint16_t)v;
	return TC_OK;
}

static const char *skip_spaces(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

static const char *trim_end(const char *start, const char *end)
{
	while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	return end;
}

int tc_portset_parse(tc_portset *ps, const char *spec,
                     tc_portset_service *service)
{
	if (ps == NULL || spec == NULL)
		return TC_ERR_INVAL;
	g_err[0] = '\0';
	if (service != NULL)
		*service = TC_PORTSET_SVC_NONE;

	const char *p = spec;
	const char *spec_end = spec + strlen(spec);

	if (skip_spaces(p, spec_end) == spec_end) {
		FAILF("empty port list");
		return TC_ERR_INVAL;
	}

	/* The loop is driven by commas rather than by remaining length, so that a
	 * trailing one still produces an (empty, rejected) item. Stopping at the
	 * end of the string instead would quietly accept "80," as "80". */
	bool more = true;
	while (more) {
		const char *comma = memchr(p, ',', (size_t)(spec_end - p));
		const char *item_end = (comma != NULL) ? comma : spec_end;
		const char *a = skip_spaces(p, item_end);
		const char *b = trim_end(a, item_end);
		more = (comma != NULL);
		p = (comma != NULL) ? comma + 1 : spec_end;

		size_t len = (size_t)(b - a);
		if (len == 0) {
			FAILF("empty entry in the port list");
			return TC_ERR_INVAL;
		}

		if (len == 3 && memcmp(a, "all", 3) == 0) {
			tc_portset_add_range(ps, 1, 65535);
			continue;
		}

		bool named = false;
		for (size_t i = 0; i < sizeof kServices / sizeof kServices[0]; i++) {
			size_t wl = strlen(kServices[i].word);
			if (len != wl || memcmp(a, kServices[i].word, wl) != 0)
				continue;
			/* A service is not a syntax error; it is a feature we do not
			 * have. Say which, so the caller can say so too. */
			if (service != NULL)
				*service = kServices[i].svc;
			FAILF("the \"%s\" service is not implemented here", kServices[i].word);
			named = true;
			break;
		}
		if (named)
			return TC_ERR_UNSUPPORTED;

		/* A range, but only a dash that separates two numbers: a leading one
		 * would mean a negative port, which is not a thing. */
		const char *dash = NULL;
		for (const char *q = a + 1; q < b; q++) {
			if (*q == '-') {
				dash = q;
				break;
			}
		}

		uint16_t lo = 0, hi = 0;
		int rc;
		if (dash != NULL) {
			rc = parse_num(a, dash, &lo);
			if (rc != TC_OK)
				return rc;
			rc = parse_num(dash + 1, b, &hi);
			if (rc != TC_OK)
				return rc;
			tc_portset_add_range(ps, lo, hi);
		} else {
			rc = parse_num(a, b, &lo);
			if (rc != TC_OK)
				return rc;
			tc_portset_add(ps, lo);
		}
	}
	return TC_OK;
}

int tc_portset_describe(const tc_portset *ps, char *out, size_t cap)
{
	if (ps == NULL || out == NULL || cap == 0)
		return TC_ERR_INVAL;
	out[0] = '\0';
	if (ps->count == 0) {
		(void)snprintf(out, cap, "no ports");
		return TC_OK;
	}
	if (ps->count == 65535) {
		(void)snprintf(out, cap, "1-65535 (all)");
		return TC_OK;
	}

	/* Coalesce back into ranges for display. A user who typed 8000-8999
	 * should not be shown a thousand numbers. */
	size_t off = 0;
	unsigned shown = 0;
	for (uint32_t port = 1; port <= 65535; port++) {
		if (!tc_portset_has(ps, (uint16_t)port))
			continue;
		uint32_t first = port;
		while (port < 65535 && tc_portset_has(ps, (uint16_t)(port + 1)))
			port++;

		if (shown == 8) {
			(void)snprintf(out + off, cap - off, ", ...");
			return TC_OK;
		}
		int n;
		if (first == port)
			n = snprintf(out + off, cap - off, "%s%u", off ? ", " : "",
			             (unsigned)first);
		else
			n = snprintf(out + off, cap - off, "%s%u-%u", off ? ", " : "",
			             (unsigned)first, (unsigned)port);
		if (n < 0 || (size_t)n >= cap - off)
			return TC_ERR_NOSPACE;
		off += (size_t)n;
		shown++;
	}
	return TC_OK;
}
