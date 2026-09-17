/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/dnsaddr.h.
 */
#include "tc/dnsaddr.h"

#include "tc/addr.h"

#include <netdb.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define TXT_PREFIX "tailcat="

static char g_err[160];

const char *tc_dns_error_string(void)
{
	return g_err[0] != '\0' ? g_err : "invalid destination";
}

static int fail(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void)vsnprintf(g_err, sizeof g_err, fmt, ap);
	va_end(ap);
	return TC_ERR_INVAL;
}

/* parses_as_address is the whole reason this file is careful. A label that is
 * a real tailcat address must never reach a resolver. */
static bool parses_as_address(const char *s, size_t len)
{
	static tc_conn_info ci;
	return tc_addr_parse(&ci, s, len) == TC_OK;
}

/* One label of a DNS name, by RFC 1035's letters-digits-hyphen rule. The
 * character set is deliberately narrow: this is a name that came off a
 * command line and is about to be sent to a resolver. */
static int check_label(const char *p, size_t len)
{
	if (len == 0)
		return fail("name contains an empty label");
	if (len > 63)
		return fail("name contains a label longer than 63 bytes");
	if (p[0] == '-' || p[len - 1] == '-')
		return fail("name contains a label beginning or ending with a hyphen");
	for (size_t i = 0; i < len; i++) {
		char c = p[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-')
			continue;
		return fail("name contains an invalid character '%c'", c);
	}
	return TC_OK;
}

int tc_dns_classify(tc_dnsarg_kind *kind, char *out, size_t cap,
                    const char *arg)
{
	g_err[0] = '\0';
	if (kind == NULL || out == NULL || cap == 0 || arg == NULL)
		return fail("missing destination");
	out[0] = '\0';

	size_t len = strlen(arg);
	if (len == 0)
		return fail("empty destination");

	/* An address is an address, whatever else it might also look like. */
	if (parses_as_address(arg, len)) {
		*kind = TC_DNSARG_ADDRESS;
		return TC_OK;
	}
	if (memchr(arg, '.', len) == NULL)
		return fail("\"%s\" is neither a tailcat address nor a DNS name", arg);

	/* A trailing dot is a fully qualified name and not an empty label. */
	size_t n = len;
	if (arg[n - 1] == '.')
		n--;
	if (n == 0)
		return fail("name is empty");
	if (n > TC_DNS_NAME_LEN - 1)
		return fail("name is longer than %d bytes", TC_DNS_NAME_LEN - 1);
	if (n + 1 > cap)
		return TC_ERR_NOSPACE;

	size_t start = 0;
	for (size_t i = 0; i <= n; i++) {
		if (i != n && arg[i] != '.')
			continue;
		size_t llen = i - start;
		/* The refusal that matters. An argument like
		 * "tcABC...xyz.example.com", or an address with a stray dot after
		 * it, would otherwise put a bearer credential into a DNS query --
		 * cleartext, to a resolver the user does not control, and onward
		 * from there. The typo is easy; the disclosure is permanent. */
		if (llen > 0 && parses_as_address(arg + start, llen))
			return fail("that contains a tailcat address as a DNS label; "
			            "refusing to put it in a DNS query");
		int rc = check_label(arg + start, llen);
		if (rc != TC_OK)
			return rc;
		start = i + 1;
	}

	memcpy(out, arg, n);
	out[n] = '\0';
	*kind = TC_DNSARG_NAME;
	return TC_OK;
}

/* ---- reading the answer -------------------------------------------------
 *
 * By hand, rather than through <resolv.h>'s ns_initparse and ns_parserr.
 * Those are in libresolv under glibc and built into Cosmopolitan, so using
 * them means the two toolchains this project builds with disagree about how
 * to link -- and the whole point of the second toolchain is that it sees the
 * same code. Sixty lines of parser is a better trade than a conditional in
 * the Makefile.
 *
 * It also puts the bounds checks here, which matters more: this is a buffer
 * that arrived from the network, carrying lengths chosen by whoever answered
 * the query, and every one of them is used to move a cursor.
 */

#define DNS_HEADER_LEN 12
#define DNS_TYPE_TXT 16
#define DNS_CLASS_IN 1

static unsigned rd_u16(const uint8_t *p)
{
	return ((unsigned)p[0] << 8) | p[1];
}

/* skip_name advances past a domain name in the wire format.
 *
 * Names are sequences of length-prefixed labels ending in a zero byte, except
 * that a label length with its top two bits set is a pointer to somewhere
 * earlier in the message -- and a pointer ends the name, so this never has to
 * follow one. Not following one is also what makes the compression-pointer
 * loop impossible here: the classic DNS parser bug is a pointer cycle, and a
 * parser that never chases a pointer cannot spin on one. */
static int skip_name(const uint8_t *msg, size_t len, size_t *off)
{
	size_t at = *off;

	for (;;) {
		if (at >= len)
			return TC_ERR_TRUNC;
		uint8_t b = msg[at];
		if (b == 0) {
			*off = at + 1;
			return TC_OK;
		}
		if ((b & 0xc0u) == 0xc0u) {
			if (at + 2 > len)
				return TC_ERR_TRUNC;
			*off = at + 2;
			return TC_OK;
		}
		if ((b & 0xc0u) != 0)
			return TC_ERR_INVAL; /* reserved label type */
		at += 1u + b;
		if (at > len)
			return TC_ERR_TRUNC;
	}
}

int tc_dns_txt_find_tailcat(char *out, size_t cap, const uint8_t *msg,
                            size_t len)
{
	if (out == NULL || cap == 0 || msg == NULL)
		return TC_ERR_INVAL;
	out[0] = '\0';
	if (len < DNS_HEADER_LEN)
		return TC_ERR_INVAL;

	unsigned qdcount = rd_u16(msg + 4);
	unsigned ancount = rd_u16(msg + 6);
	size_t off = DNS_HEADER_LEN;

	for (unsigned i = 0; i < qdcount; i++) {
		int rc = skip_name(msg, len, &off);
		if (rc != TC_OK)
			return rc;
		if (off + 4 > len)
			return TC_ERR_TRUNC;
		off += 4; /* qtype, qclass */
	}

	for (unsigned i = 0; i < ancount; i++) {
		int rc = skip_name(msg, len, &off);
		if (rc != TC_OK)
			return rc;
		if (off + 10 > len)
			return TC_ERR_TRUNC;
		unsigned type = rd_u16(msg + off);
		unsigned cls = rd_u16(msg + off + 2);
		size_t rdlen = rd_u16(msg + off + 8);
		off += 10;
		if (off + rdlen > len)
			return TC_ERR_TRUNC;
		size_t rdata = off;
		off += rdlen;

		if (type != DNS_TYPE_TXT || cls != DNS_CLASS_IN)
			continue;

		/* A TXT record's data is one or more length-prefixed strings. Each
		 * is at most 255 bytes, so a value longer than that arrives split
		 * across several and has to be joined -- reading only the first
		 * would produce a truncated address and a confusing error a long
		 * way from here. */
		char joined[TC_ADDR_STR_MAX + sizeof TXT_PREFIX + 8];
		size_t w = 0, at = rdata;
		bool overflow = false;
		while (at < rdata + rdlen) {
			size_t slen = msg[at];
			at++;
			if (at + slen > rdata + rdlen)
				return TC_ERR_TRUNC;
			if (w + slen >= sizeof joined) {
				overflow = true;
				break;
			}
			memcpy(joined + w, msg + at, slen);
			w += slen;
			at += slen;
		}
		if (overflow)
			continue; /* far longer than any address; not ours */
		joined[w] = '\0';

		if (strncmp(joined, TXT_PREFIX, sizeof TXT_PREFIX - 1) != 0)
			continue;

		/* Trimmed, because a zone file is edited by hand. */
		char *v = joined + sizeof TXT_PREFIX - 1;
		while (*v == ' ' || *v == '\t')
			v++;
		size_t vlen = strlen(v);
		while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t' ||
		                    v[vlen - 1] == '\r' || v[vlen - 1] == '\n'))
			vlen--;
		if (vlen == 0)
			continue;
		if (vlen + 1 > cap)
			return TC_ERR_NOSPACE;
		memcpy(out, v, vlen);
		out[vlen] = '\0';
		return TC_OK;
	}
	return TC_ERR_NOTFOUND;
}

int tc_dns_lookup_tailcat(char *out, size_t cap, const char *name)
{
	static uint8_t buf[4096];

	if (out == NULL || cap == 0 || name == NULL)
		return TC_ERR_INVAL;

	h_errno = 0;
	int n = res_query(name, ns_c_in, ns_t_txt, buf, (int)sizeof buf);
	if (n <= 0) {
		/* Telling these apart matters to whoever is reading the message: a
		 * name that does not exist is a typo, and a resolver that will not
		 * answer is a network problem. Reporting both as "timed out" sends
		 * the reader to look at the wrong thing. */
		switch (h_errno) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			return TC_ERR_NOTFOUND;
		case TRY_AGAIN:
			return TC_ERR_TIMEOUT;
		default:
			return TC_ERR_INVAL;
		}
	}
	return tc_dns_txt_find_tailcat(out, cap, buf, (size_t)n);
}
