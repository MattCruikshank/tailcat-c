/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Served-port spec parsing.
 *
 * The thing this decides is which ports on the machine a remote peer can
 * reach, so a spec that parses into a *slightly* different set than the user
 * typed is a security bug with a friendly face. The tests lean on exact
 * membership at the edges -- 0, 1, 65535, reversed ranges, a range of one --
 * rather than on the spec round-tripping.
 */

#include "tc/portset.h"

#include "tctest.h"

static size_t popcount_set(const tc_portset *ps)
{
	size_t n = 0;
	for (uint32_t p = 1; p <= 65535; p++)
		if (tc_portset_has(ps, (uint16_t)p))
			n++;
	return n;
}

static void test_single_ports(void)
{
	TCT_CASE("single ports and lists");
	static tc_portset ps;
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "22,80,443", NULL), TC_OK);
	TCT_TRUE(tc_portset_has(&ps, 22));
	TCT_TRUE(tc_portset_has(&ps, 80));
	TCT_TRUE(tc_portset_has(&ps, 443));
	TCT_TRUE(!tc_portset_has(&ps, 21));
	TCT_TRUE(!tc_portset_has(&ps, 81));
	TCT_EQ_INT((int)ps.count, 3);
	TCT_EQ_INT((int)popcount_set(&ps), 3);

	TCT_CASE("whitespace around entries is tolerated");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, " 22 , 80 ", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 2);
	TCT_TRUE(tc_portset_has(&ps, 22));

	TCT_CASE("a repeated port is counted once");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "80,80,80", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 1);

	TCT_CASE("several specs fold into one set");
	/* Upstream allows the list to be spread over several arguments. */
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "22", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_parse(&ps, "80,443", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 3);
}

static void test_ranges(void)
{
	TCT_CASE("an inclusive range includes both ends");
	static tc_portset ps;
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "8000-8002", NULL), TC_OK);
	TCT_TRUE(!tc_portset_has(&ps, 7999));
	TCT_TRUE(tc_portset_has(&ps, 8000));
	TCT_TRUE(tc_portset_has(&ps, 8001));
	TCT_TRUE(tc_portset_has(&ps, 8002));
	TCT_TRUE(!tc_portset_has(&ps, 8003));
	TCT_EQ_INT((int)ps.count, 3);

	TCT_CASE("a reversed range is accepted, as upstream does");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "90-80", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 11);
	TCT_TRUE(tc_portset_has(&ps, 80));
	TCT_TRUE(tc_portset_has(&ps, 90));

	TCT_CASE("a range of one");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "443-443", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 1);

	TCT_CASE("a range touching the top port terminates");
	/* Counting to 65535 inclusive in a uint16_t never ends. The loop
	 * counter is deliberately wider than the values it holds, and this is
	 * the test that would hang if that were undone. */
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "65530-65535", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 6);
	TCT_TRUE(tc_portset_has(&ps, 65535));

	TCT_CASE("all is every port except 0");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "all", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 65535);
	TCT_TRUE(tc_portset_has(&ps, 1));
	TCT_TRUE(tc_portset_has(&ps, 65535));
	TCT_TRUE(!tc_portset_has(&ps, 0));

	TCT_CASE("all mixed with other entries");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "80,all", NULL), TC_OK);
	TCT_EQ_INT((int)ps.count, 65535);
}

static void test_rejects(void)
{
	TCT_CASE("malformed specs are refused, not guessed at");
	static tc_portset ps;
	static const char *const bad[] = {
		"",          "   ",      ",",        "80,",     ",80",
		"80,,443",   "http",     "80/tcp",   "8o",      "-80",
		"80-",       "-",        "80-90-100", "65536",  "80-65536",
		"0",         "0-10",     "80 443",   "0x50",    "+80",
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		tc_portset_clear(&ps);
		if (tc_portset_parse(&ps, bad[i], NULL) == TC_OK)
			TCT_FAILF("accepted \"%s\" (%zu ports)", bad[i], ps.count);
		tct_checks++;
		if (tc_portset_error_string()[0] == '\0')
			TCT_FAILF("no diagnostic for \"%s\"", bad[i]);
		tct_checks++;
	}

	TCT_CASE("port 0 is never a member");
	/* Not a real port. Admitting it would mean answering a SYN that could
	 * only have come from something malformed. */
	tc_portset_clear(&ps);
	tc_portset_add(&ps, 0);
	TCT_EQ_INT((int)ps.count, 0);
	TCT_TRUE(!tc_portset_has(&ps, 0));
	tc_portset_add_range(&ps, 0, 2);
	TCT_TRUE(!tc_portset_has(&ps, 0));
	TCT_TRUE(tc_portset_has(&ps, 1));
	TCT_EQ_INT((int)ps.count, 2);

	TCT_CASE("null arguments are refused");
	TCT_EQ_INT(tc_portset_parse(NULL, "80", NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_portset_parse(&ps, NULL, NULL), TC_ERR_INVAL);
	TCT_TRUE(!tc_portset_has(NULL, 80));
	tc_portset_clear(NULL);
	tc_portset_add(NULL, 80);
	tc_portset_add_range(NULL, 1, 2);
}

static void test_services(void)
{
	TCT_CASE("a named service is reported by name, not as a syntax error");
	/* "ssh is not implemented here" and "that is not a port" are different
	 * things to be told, and the CLI can only say the first if the parser
	 * distinguishes them. */
	static const struct {
		const char *spec;
		tc_portset_service want;
	} cases[] = {
		{ "ssh", TC_PORTSET_SVC_SSH },
		{ "no-auth-ssh", TC_PORTSET_SVC_NO_AUTH_SSH },
		{ "files", TC_PORTSET_SVC_FILES },
		{ "exec", TC_PORTSET_SVC_EXEC },
		{ "exit-node", TC_PORTSET_SVC_EXIT_NODE },
		{ "80,ssh", TC_PORTSET_SVC_SSH },
	};
	static tc_portset ps;
	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		tc_portset_clear(&ps);
		tc_portset_service svc = TC_PORTSET_SVC_NONE;
		TCT_EQ_INT(tc_portset_parse(&ps, cases[i].spec, &svc),
		           TC_ERR_UNSUPPORTED);
		TCT_EQ_INT((int)svc, (int)cases[i].want);
		TCT_EQ_STR(tc_portset_service_name(svc),
		           tc_portset_service_name(cases[i].want));
	}

	TCT_CASE("ports before the service are still parsed");
	/* So a caller that chooses to carry on has the part that made sense. */
	tc_portset_clear(&ps);
	tc_portset_service svc = TC_PORTSET_SVC_NONE;
	TCT_EQ_INT(tc_portset_parse(&ps, "80,443,ssh", &svc), TC_ERR_UNSUPPORTED);
	TCT_TRUE(tc_portset_has(&ps, 80));
	TCT_TRUE(tc_portset_has(&ps, 443));
}

static void test_describe(void)
{
	TCT_CASE("the summary coalesces ranges back");
	static tc_portset ps;
	char buf[128];

	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "22,80,443", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "22, 80, 443");

	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "8000-8999", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "8000-8999");

	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "80,81,82,443", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "80-82, 443");

	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "all", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "1-65535 (all)");

	TCT_CASE("an empty set says so rather than printing nothing");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_EQ_STR(buf, "no ports");

	TCT_CASE("a long list is truncated rather than overflowing");
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "1,3,5,7,9,11,13,15,17,19", NULL), TC_OK);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, sizeof buf), TC_OK);
	TCT_TRUE(strstr(buf, "...") != NULL);

	TCT_CASE("a buffer too small is refused, not overrun");
	char tiny[8];
	tc_portset_clear(&ps);
	TCT_EQ_INT(tc_portset_parse(&ps, "8000-8999,9000-9999", NULL), TC_OK);
	int rc = tc_portset_describe(&ps, tiny, sizeof tiny);
	TCT_TRUE(rc == TC_ERR_NOSPACE || rc == TC_OK);
	TCT_TRUE(tiny[sizeof tiny - 1] == '\0' || rc == TC_ERR_NOSPACE);
	TCT_EQ_INT(tc_portset_describe(&ps, buf, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_portset_describe(NULL, buf, sizeof buf), TC_ERR_INVAL);
}

int main(void)
{
	test_single_ports();
	test_ranges();
	test_rejects();
	test_services();
	test_describe();
	return tct_report("portset");
}
