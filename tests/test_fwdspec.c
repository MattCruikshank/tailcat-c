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
	TCT_CASE("the address form is refused by name, not as a syntax error");
	/* `13306:192.168.1.10:3306` is valid upstream syntax that needs the
	 * server to be an exit node. Telling the user that is different from
	 * telling them their mapping is malformed. */
	tc_fwd_spec f;
	TCT_EQ_INT(tc_fwd_parse(&f, "13306:192.168.1.10:3306"),
	           TC_ERR_UNSUPPORTED);
	TCT_TRUE(strstr(tc_fwd_error_string(), "exit node") != NULL);

	TCT_EQ_INT(tc_fwd_parse(&f, "80:[2001:db8::1]:443"), TC_ERR_UNSUPPORTED);
	TCT_TRUE(strstr(tc_fwd_error_string(), "exit node") != NULL);
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
