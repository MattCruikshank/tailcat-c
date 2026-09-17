/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Port-forwarding mapping syntax.
 *
 * `8080` and `18080:8080` mean different things, and getting them the wrong
 * way round would listen on the port the user meant to reach and reach the
 * one they meant to listen on -- which works, connects, and does entirely the
 * wrong thing. So these tests check both numbers of every mapping, not just
 * that it parsed.
 */

#include "tc/fwdspec.h"

#include "tctest.h"

static void test_single_port(void)
{
	TCT_CASE("one port means the same port on both sides");
	tc_fwd_spec f;
	TCT_EQ_INT(tc_fwd_parse(&f, "8080"), TC_OK);
	TCT_EQ_INT(f.local_port, 8080);
	TCT_EQ_INT(f.remote_port, 8080);

	TCT_EQ_INT(tc_fwd_parse(&f, "1"), TC_OK);
	TCT_EQ_INT(f.local_port, 1);
	TCT_EQ_INT(f.remote_port, 1);

	TCT_EQ_INT(tc_fwd_parse(&f, "65535"), TC_OK);
	TCT_EQ_INT(f.local_port, 65535);
	TCT_EQ_INT(f.remote_port, 65535);
}

static void test_two_ports(void)
{
	TCT_CASE("local:remote, in that order");
	/* The order is the whole point: reversed, this listens on the port the
	 * user meant to reach and reaches the one they meant to listen on. It
	 * would connect, and do the wrong thing. */
	tc_fwd_spec f;
	TCT_EQ_INT(tc_fwd_parse(&f, "18080:8080"), TC_OK);
	TCT_EQ_INT(f.local_port, 18080);
	TCT_EQ_INT(f.remote_port, 8080);

	TCT_EQ_INT(tc_fwd_parse(&f, "2222:22"), TC_OK);
	TCT_EQ_INT(f.local_port, 2222);
	TCT_EQ_INT(f.remote_port, 22);

	TCT_CASE("local port 0 asks the OS to choose");
	TCT_EQ_INT(tc_fwd_parse(&f, "0:8080"), TC_OK);
	TCT_EQ_INT(f.local_port, 0);
	TCT_EQ_INT(f.remote_port, 8080);

	TCT_CASE("but a bare 0 is refused");
	/* It would mean "choose a local port and forward it to nothing". */
	TCT_TRUE(tc_fwd_parse(&f, "0") != TC_OK);
	TCT_TRUE(tc_fwd_parse(&f, "8080:0") != TC_OK);
}

static void test_exit_node_form(void)
{
	TCT_CASE("a mapping may name a destination beyond the server");
	tc_fwd_spec f;
	TCT_EQ_INT(tc_fwd_parse(&f, "13306:192.168.1.10:3306"), TC_OK);
	TCT_EQ_INT(f.local_port, 13306);
	TCT_EQ_INT(f.remote_port, 3306);
	TCT_EQ_INT(f.dst.ip_len, 4);
	TCT_EQ_INT(f.dst.port, 3306);
	char s[64];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &f.dst), TC_OK);
	TCT_EQ_STR(s, "192.168.1.10:3306");

	TCT_CASE("an IPv4 destination stays IPv4 here");
	/* Wrapping it for the IPv6-only tunnel is nat64.h's job, and it happens
	 * at the point of use. If it happened here, the structure would no
	 * longer say what the user typed, and an error message built from it
	 * would name an address they have never seen. */
	TCT_TRUE(f.dst.ip[0] == 192 && f.dst.ip[3] == 10);

	TCT_CASE("an IPv6 destination, in brackets");
	TCT_EQ_INT(tc_fwd_parse(&f, "80:[2001:db8::1]:443"), TC_OK);
	TCT_EQ_INT(f.local_port, 80);
	TCT_EQ_INT(f.remote_port, 443);
	TCT_EQ_INT(f.dst.ip_len, 16);
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &f.dst), TC_OK);
	TCT_EQ_STR(s, "[2001:db8::1]:443");

	TCT_CASE("and an ordinary mapping names no destination at all");
	/* ip_len 0 is what tells the caller to dial the server itself rather
	 * than to ask it to forward, so the two forms must stay distinguishable
	 * without a separate flag to forget to set. */
	TCT_EQ_INT(tc_fwd_parse(&f, "18080:8080"), TC_OK);
	TCT_EQ_INT(f.dst.ip_len, 0);
	TCT_EQ_INT(tc_fwd_parse(&f, "8080"), TC_OK);
	TCT_EQ_INT(f.dst.ip_len, 0);

	TCT_CASE("unbracketed IPv6 is refused rather than guessed at");
	/* "80:::1:443" has no unambiguous reading, and RFC 3986 settled this
	 * argument for URLs in favour of brackets. Guessing would sometimes
	 * forward to the wrong port of the right host, which is the kind of
	 * wrong that looks like a network problem. */
	TCT_EQ_INT(tc_fwd_parse(&f, "80:::1:443"), TC_ERR_INVAL);
	TCT_TRUE(strstr(tc_fwd_error_string(), "brackets") != NULL);
	TCT_EQ_INT(tc_fwd_parse(&f, "80:2001:db8::1:443"), TC_ERR_INVAL);

	TCT_CASE("a hostname is refused, because it would resolve here");
	/* "database" means something different on the far side of the tunnel,
	 * which is usually the whole reason for forwarding to it. Resolving it
	 * on this machine would silently reach the wrong one. */
	TCT_EQ_INT(tc_fwd_parse(&f, "5432:database:5432"), TC_ERR_INVAL);
	TCT_TRUE(strstr(tc_fwd_error_string(), "literal") != NULL);
	TCT_EQ_INT(tc_fwd_parse(&f, "80:example.com:443"), TC_ERR_INVAL);

	TCT_CASE("malformed destinations");
	static const char *const bad[] = {
		"80::443",              /* no host between the colons */
		"80:[2001:db8::1:443",  /* unclosed bracket */
		"80:[192.168.1.1]:443", /* brackets around an IPv4 address */
		"80:[]:443",
		"80:1.2.3.4:",
		"80:1.2.3.4:0",
		"80:1.2.3.4:65536",
		"80:999.1.1.1:443",
		"80:1.2.3.4:http",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		if (tc_fwd_parse(&f, bad[i]) == TC_OK)
			TCT_FAILF("accepted %s", bad[i]);
		tct_checks++;
		TCT_TRUE(tc_fwd_error_string()[0] != '\0');
	}
}

static void test_rejects(void)
{
	TCT_CASE("malformed mappings are refused");
	tc_fwd_spec f;
	static const char *const bad[] = {
		"",     ":",      "80:",    ":80",   "http",  "80:http",
		"-1",   "65536",  "80:65536", "8 0",  "80,443", "0x50",
		"+80",  "80:-1",  "80:+1",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		if (tc_fwd_parse(&f, bad[i]) == TC_OK)
			TCT_FAILF("accepted \"%s\" as %u:%u", bad[i],
			          (unsigned)f.local_port, (unsigned)f.remote_port);
		tct_checks++;
		if (tc_fwd_error_string()[0] == '\0')
			TCT_FAILF("no diagnostic for \"%s\"", bad[i]);
		tct_checks++;
	}

	TCT_CASE("null arguments are refused");
	TCT_EQ_INT(tc_fwd_parse(NULL, "80"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_fwd_parse(&f, NULL), TC_ERR_INVAL);
}

int main(void)
{
	test_single_port();
	test_two_ports();
	test_exit_node_form();
	test_rejects();
	return tct_report("fwdspec");
}
