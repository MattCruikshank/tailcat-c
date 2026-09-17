/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Durations.
 *
 * This exists because strtoul was doing the job and getting it wrong without
 * saying so: "2m" became 2. The tests that matter here are therefore not the
 * ones where a duration parses, but the ones where a sloppier parser would
 * also have returned a number -- just the wrong one.
 */

#include "tc/duration.h"

#include "tctest.h"

static unsigned ok(const char *s)
{
	unsigned v = 12345;
	TCT_EQ_INT(tc_parse_duration_s(&v, s), TC_OK);
	return v;
}

static void bad(const char *s)
{
	unsigned v = 12345;
	int rc = tc_parse_duration_s(&v, s);
	if (rc == TC_OK)
		TCT_FAILF("\"%s\" should have been refused, gave %u", s, v);
	else
		TCT_TRUE(rc != TC_OK);
	/* And it must not have written anything on the way to refusing. */
	TCT_EQ_INT((int)v, 12345);
}

static void test_bare_seconds(void)
{
	TCT_CASE("a bare number is seconds, as it always was here");
	TCT_EQ_INT((int)ok("0"), 0);
	TCT_EQ_INT((int)ok("1"), 1);
	TCT_EQ_INT((int)ok("60"), 60);
	TCT_EQ_INT((int)ok("3600"), 3600);
}

static void test_units(void)
{
	TCT_CASE("the units upstream's flags take");
	TCT_EQ_INT((int)ok("30s"), 30);
	TCT_EQ_INT((int)ok("2m"), 120);
	TCT_EQ_INT((int)ok("1h"), 3600);

	TCT_CASE("the one that was wrong by sixty");
	/* strtoul("2m") is 2. The command still ran; it just gave up fifty-eight
	 * seconds early, and said nothing about it. */
	TCT_TRUE(ok("2m") != 2);

	TCT_CASE("compound durations, and the same value spelled three ways");
	TCT_EQ_INT((int)ok("1m30s"), 90);
	TCT_EQ_INT((int)ok("90s"), 90);
	TCT_EQ_INT((int)ok("90000ms"), 90);
	TCT_EQ_INT((int)ok("1h30m"), 5400);
	TCT_EQ_INT((int)ok("1h0m0s"), 3600);

	TCT_CASE("ms is not m followed by s");
	/* The unit table is ordered longest-first for exactly this. Matching "m"
	 * first would read 500ms as 500 minutes and leave a stray "s". */
	TCT_EQ_INT((int)ok("500ms"), 1);
	TCT_TRUE(ok("500ms") != 500 * 60);

	TCT_CASE("sub-second values round up, never to zero");
	/* Zero means "no deadline" to every caller here, so rounding 1ms down
	 * would turn the shortest timeout anyone can ask for into the longest. */
	TCT_EQ_INT((int)ok("1ns"), 1);
	TCT_EQ_INT((int)ok("1us"), 1);
	TCT_EQ_INT((int)ok("1ms"), 1);
	TCT_EQ_INT((int)ok("999ms"), 1);
	TCT_EQ_INT((int)ok("1001ms"), 2);

	TCT_CASE("and only a literal zero is zero");
	TCT_EQ_INT((int)ok("0"), 0);
	TCT_EQ_INT((int)ok("0s"), 0);
	TCT_EQ_INT((int)ok("0m"), 0);

	TCT_CASE("a leading plus, which Go accepts");
	TCT_EQ_INT((int)ok("+45s"), 45);
}

static void test_refusals(void)
{
	TCT_CASE("the inputs strtoul would have accepted a prefix of");
	/* Every one of these produced a number before. That is the bug. */
	bad("2minutes");
	bad("30sec");
	bad("10x");
	bad("5s5");
	bad("1m30");
	bad("100 s");
	bad("3,600");

	TCT_CASE("an empty or sign-only value");
	bad("");
	bad("+");
	bad("-");
	bad("s");
	bad("ms");

	TCT_CASE("negative durations are refused, not clamped");
	/* A deadline in the past is not something to guess an intention for. */
	bad("-1");
	bad("-30s");

	TCT_CASE("nothing that is not a number or a unit");
	bad("abc");
	bad("1.5s");   /* Go allows it; whole seconds here, so say so */
	bad("0x10");
	bad(" 30s");
	bad("30s ");

	TCT_CASE("values too large to hold");
	bad("99999999999999999999");
	bad("99999999999h");

	TCT_CASE("a NULL destination or string");
	unsigned v;
	TCT_EQ_INT(tc_parse_duration_s(NULL, "1s"), TC_ERR_INVAL);
	TCT_EQ_INT(tc_parse_duration_s(&v, NULL), TC_ERR_INVAL);
}

static void test_boundaries(void)
{
	TCT_CASE("the largest value that still fits");
	unsigned v;
	TCT_EQ_INT(tc_parse_duration_s(&v, "4294967295s"), TC_OK);
	TCT_EQ_INT((int)(v == 4294967295u), 1);
	bad("4294967296s");

	TCT_CASE("a sum that overflows only when added");
	/* Each part fits; the total does not. A parser checking only the parts
	 * would wrap and return something small and plausible. */
	bad("9223372036854775807ns9223372036854775807ns");
}

int main(void)
{
	test_bare_seconds();
	test_units();
	test_refusals();
	test_boundaries();
	return tct_report("duration");
}
