/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Destinations that might be DNS names.
 *
 * Two things are being checked and only one of them is "does it work".
 *
 * The other is a disclosure. A tailcat address is a bearer credential and a
 * DNS query is cleartext to a resolver the user does not control, so an
 * argument that has an address inside it must never be looked up. The typo
 * that produces one -- a trailing dot, a pasted address with a domain stuck
 * to it -- is easy to make and the leak it causes cannot be undone. Most of
 * this file is that case.
 */

#include "tc/dnsaddr.h"

#include <string.h>

#include "tctest.h"

/* A real address, from tests/test_addr.c's vectors: short form, region 302. */
#define ADDR "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu"

static tc_dnsarg_kind kind_of(const char *arg)
{
	tc_dnsarg_kind k = (tc_dnsarg_kind)-1;
	char name[TC_DNS_NAME_LEN];
	TCT_EQ_INT(tc_dns_classify(&k, name, sizeof name, arg), TC_OK);
	return k;
}

static const char *name_of(const char *arg)
{
	static char name[TC_DNS_NAME_LEN];
	tc_dnsarg_kind k;
	TCT_EQ_INT(tc_dns_classify(&k, name, sizeof name, arg), TC_OK);
	TCT_EQ_INT((int)k, (int)TC_DNSARG_NAME);
	return name;
}

static void refused(const char *arg)
{
	tc_dnsarg_kind k;
	char name[TC_DNS_NAME_LEN];
	int rc = tc_dns_classify(&k, name, sizeof name, arg);
	if (rc == TC_OK)
		TCT_FAILF("\"%s\" should have been refused", arg);
	else
		TCT_TRUE(rc != TC_OK);
	/* And nothing written on the way to refusing, so a caller that ignores
	 * the return value cannot resolve a half-built name. */
	TCT_EQ_STR(name, "");
}

static void test_addresses(void)
{
	TCT_CASE("an address is an address");
	TCT_EQ_INT((int)kind_of(ADDR), (int)TC_DNSARG_ADDRESS);

	TCT_CASE("and takes precedence over anything else it might look like");
	/* It has no dots, so there is no ambiguity here -- but the order of the
	 * checks is what guarantees that, and the order is worth pinning. */
	char name[TC_DNS_NAME_LEN];
	tc_dnsarg_kind k;
	TCT_EQ_INT(tc_dns_classify(&k, name, sizeof name, ADDR), TC_OK);
	TCT_EQ_STR(name, "");
}

static void test_names(void)
{
	TCT_CASE("an ordinary name");
	TCT_EQ_INT((int)kind_of("example.com"), (int)TC_DNSARG_NAME);
	TCT_EQ_STR(name_of("example.com"), "example.com");
	TCT_EQ_STR(name_of("my-server.example.com"), "my-server.example.com");

	TCT_CASE("a fully qualified name loses its trailing dot");
	/* Otherwise the last label is empty and the name is rejected, which
	 * would refuse a spelling that is not only legal but more precise. */
	TCT_EQ_STR(name_of("example.com."), "example.com");

	TCT_CASE("digits, hyphens and mixed case are all fine");
	TCT_EQ_STR(name_of("Host-01.Sub2.Example.COM"), "Host-01.Sub2.Example.COM");
}

static void test_the_disclosure(void)
{
	TCT_CASE("an address with a domain stuck to it is refused, not resolved");
	/* The case this file exists for. Resolving it would put the address --
	 * the whole credential -- into a DNS query in cleartext. */
	refused(ADDR ".example.com");
	refused("sub." ADDR ".example.com");
	refused("example.com." ADDR);

	TCT_CASE("and an address with a trailing dot");
	/* A plausible paste. The dot makes it not parse as an address, and a
	 * naive implementation then treats the whole thing as a name. */
	refused(ADDR ".");

	TCT_CASE("the refusal says why");
	tc_dnsarg_kind k;
	char name[TC_DNS_NAME_LEN];
	(void)tc_dns_classify(&k, name, sizeof name, ADDR ".example.com");
	TCT_TRUE(strstr(tc_dns_error_string(), "tailcat address") != NULL);
	TCT_TRUE(strstr(tc_dns_error_string(), "refusing") != NULL);

	TCT_CASE("a label that merely starts with tc is not an address");
	/* The check is "does it parse", not "does it look like one", so
	 * ordinary names beginning with tc still resolve. */
	TCT_EQ_STR(name_of("tcp.example.com"), "tcp.example.com");
	TCT_EQ_STR(name_of("tc.example.com"), "tc.example.com");
}

static void test_bad_names(void)
{
	TCT_CASE("something that is neither");
	refused("localhost");
	refused("");
	refused("notanaddress");

	TCT_CASE("empty labels");
	refused("example..com");
	refused(".example.com");

	TCT_CASE("characters a DNS name may not hold");
	/* This string is about to be handed to a resolver, so the character set
	 * is narrow on purpose. */
	refused("exa mple.com");
	refused("example.com/../evil");
	refused("example.com;id");
	refused("ex\tample.com");
	refused("\xc3\xa9xample.com");
	refused("example.com\n");

	TCT_CASE("hyphens at the edges of a label");
	refused("-example.com");
	refused("example-.com");
	refused("a.-b.c");

	TCT_CASE("labels and names that are too long");
	char big[600];
	memset(big, 'a', sizeof big - 1);
	big[sizeof big - 1] = '\0';
	big[64] = '.'; /* first label is 64 bytes: one too many */
	refused(big);

	memset(big, 'a', sizeof big - 1);
	for (size_t i = 10; i < sizeof big - 1; i += 11)
		big[i] = '.'; /* every label legal, whole name far too long */
	big[300] = '\0';
	refused(big);

	TCT_CASE("a destination that does not fit the caller's buffer");
	tc_dnsarg_kind k;
	char tiny[8];
	TCT_EQ_INT(tc_dns_classify(&k, tiny, sizeof tiny, "example.com"),
	           TC_ERR_NOSPACE);

	TCT_CASE("NULL arguments");
	char name[TC_DNS_NAME_LEN];
	TCT_EQ_INT(tc_dns_classify(NULL, name, sizeof name, "a.b"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_classify(&k, NULL, 16, "a.b"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_classify(&k, name, 0, "a.b"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_classify(&k, name, sizeof name, NULL), TC_ERR_INVAL);
}

/* ---- reading a response -------------------------------------------------
 *
 * Built by hand rather than captured, so that the shapes that matter can be
 * built on purpose: several TXT records with ours not first, a value split
 * across strings, and a truncated one.
 */

typedef struct {
	uint8_t b[1024];
	size_t n;
} msg;

static void put(msg *m, const void *p, size_t n)
{
	memcpy(m->b + m->n, p, n);
	m->n += n;
}

static void put_u16(msg *m, unsigned v)
{
	uint8_t x[2] = { (uint8_t)(v >> 8), (uint8_t)v };
	put(m, x, 2);
}

/* header: one question, `answers` answers */
static void begin(msg *m, unsigned answers)
{
	m->n = 0;
	put_u16(m, 0x1234); /* id */
	put_u16(m, 0x8180); /* response, recursion available */
	put_u16(m, 1);      /* qdcount */
	put_u16(m, answers);
	put_u16(m, 0);
	put_u16(m, 0);
	/* question: example.com TXT IN */
	put(m, "\7example\3com\0", 13);
	put_u16(m, 16); /* TXT */
	put_u16(m, 1);  /* IN */
}

/* one TXT answer whose rdata is the given length-prefixed strings */
static void answer_txt(msg *m, const uint8_t *rdata, size_t rdlen)
{
	put(m, "\300\14", 2); /* pointer to the question's name */
	put_u16(m, 16);       /* TXT */
	put_u16(m, 1);        /* IN */
	put_u16(m, 0);
	put_u16(m, 300); /* ttl */
	put_u16(m, (unsigned)rdlen);
	put(m, rdata, rdlen);
}

static void answer_str(msg *m, const char *s)
{
	uint8_t rd[512];
	size_t len = strlen(s);
	rd[0] = (uint8_t)len;
	memcpy(rd + 1, s, len);
	answer_txt(m, rd, len + 1);
}

static void test_reading(void)
{
	msg m;
	char out[512];

	TCT_CASE("the address comes out of a tailcat= record");
	begin(&m, 1);
	answer_str(&m, "tailcat=" ADDR);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n), TC_OK);
	TCT_EQ_STR(out, ADDR);

	TCT_CASE("other records are skipped, wherever ours sits");
	/* A real zone has SPF, verification tokens and whatever else. Ours
	 * being first is the case that would pass by accident. */
	begin(&m, 3);
	answer_str(&m, "v=spf1 include:_spf.example.com ~all");
	answer_str(&m, "google-site-verification=abc123");
	answer_str(&m, "tailcat=" ADDR);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n), TC_OK);
	TCT_EQ_STR(out, ADDR);

	TCT_CASE("a value split across strings is joined");
	/* A TXT string is at most 255 bytes, so a long address arrives in
	 * pieces. Reading only the first piece would produce a truncated
	 * address that parses as nothing and reports a confusing error. */
	uint8_t rd[600];
	const char *head = "tailcat=" ADDR;
	size_t hl = strlen(head);
	size_t first = 20;
	rd[0] = (uint8_t)first;
	memcpy(rd + 1, head, first);
	rd[1 + first] = (uint8_t)(hl - first);
	memcpy(rd + 2 + first, head + first, hl - first);
	begin(&m, 1);
	answer_txt(&m, rd, 2 + hl);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n), TC_OK);
	TCT_EQ_STR(out, ADDR);

	TCT_CASE("surrounding whitespace is trimmed");
	begin(&m, 1);
	answer_str(&m, "tailcat=  " ADDR "  ");
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n), TC_OK);
	TCT_EQ_STR(out, ADDR);

	TCT_CASE("no tailcat record at all");
	begin(&m, 2);
	answer_str(&m, "v=spf1 -all");
	answer_str(&m, "something=else");
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n),
	           TC_ERR_NOTFOUND);

	TCT_CASE("an empty answer section");
	begin(&m, 0);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n),
	           TC_ERR_NOTFOUND);

	TCT_CASE("an empty value is not an address");
	begin(&m, 1);
	answer_str(&m, "tailcat=");
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n),
	           TC_ERR_NOTFOUND);

	TCT_CASE("a string that claims more bytes than the record holds");
	/* Straight off the network, so the length byte is attacker-chosen. */
	begin(&m, 1);
	uint8_t bad[4] = { 200, 'a', 'b', 'c' };
	answer_txt(&m, bad, sizeof bad);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n),
	           TC_ERR_TRUNC);

	TCT_CASE("a truncated message");
	/* TRUNC rather than INVAL: the message is well formed as far as it
	 * goes, and it stops in the middle of a record. The distinction is the
	 * difference between "your resolver is broken" and "someone cut this
	 * short", which are worth telling apart. */
	begin(&m, 1);
	answer_str(&m, "tailcat=" ADDR);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, m.n / 2),
	           TC_ERR_TRUNC);

	TCT_CASE("a message too short to hold a header");
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, 0),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, m.b, 11),
	           TC_ERR_INVAL);

	TCT_CASE("a destination too small for the address");
	char tiny[8];
	begin(&m, 1);
	answer_str(&m, "tailcat=" ADDR);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(tiny, sizeof tiny, m.b, m.n),
	           TC_ERR_NOSPACE);

	TCT_CASE("NULL arguments");
	TCT_EQ_INT(tc_dns_txt_find_tailcat(NULL, 16, m.b, m.n), TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, 0, m.b, m.n), TC_ERR_INVAL);
	TCT_EQ_INT(tc_dns_txt_find_tailcat(out, sizeof out, NULL, 4),
	           TC_ERR_INVAL);
}

int main(void)
{
	test_addresses();
	test_names();
	test_the_disclosure();
	test_bad_names();
	test_reading();
	return tct_report("dnsaddr");
}
