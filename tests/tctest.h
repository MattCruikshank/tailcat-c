/* SPDX-License-Identifier: BSD-3-Clause
 * A deliberately tiny test harness: no allocation, no dependencies.
 */
#ifndef TC_TCTEST_H_
#define TC_TCTEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tct_fails;
static int tct_checks;
static const char *tct_case;

#define TCT_CASE(name)                                                        \
	do {                                                                      \
		tct_case = (name);                                                    \
	} while (0)

#define TCT_FAILF(...)                                                        \
	do {                                                                      \
		tct_fails++;                                                          \
		fprintf(stderr, "FAIL %s:%d [%s]: ", __FILE__, __LINE__,              \
		        tct_case ? tct_case : "-");                                   \
		fprintf(stderr, __VA_ARGS__);                                         \
		fputc('\n', stderr);                                                  \
	} while (0)

#define TCT_TRUE(cond)                                                        \
	do {                                                                      \
		tct_checks++;                                                         \
		if (!(cond))                                                          \
			TCT_FAILF("expected true: %s", #cond);                            \
	} while (0)

#define TCT_EQ_INT(got, want)                                                 \
	do {                                                                      \
		tct_checks++;                                                         \
		long long g_ = (long long)(got), w_ = (long long)(want);              \
		if (g_ != w_)                                                         \
			TCT_FAILF("%s: got %lld, want %lld", #got, g_, w_);               \
	} while (0)

#define TCT_EQ_STR(got, want)                                                 \
	do {                                                                      \
		tct_checks++;                                                         \
		const char *g_ = (got), *w_ = (want);                                 \
		if (g_ == NULL || w_ == NULL || strcmp(g_, w_) != 0)                  \
			TCT_FAILF("%s: got \"%s\", want \"%s\"", #got,                    \
			          g_ ? g_ : "(null)", w_ ? w_ : "(null)");                \
	} while (0)

#define TCT_EQ_MEM(got, want, n)                                              \
	do {                                                                      \
		tct_checks++;                                                         \
		if (memcmp((got), (want), (n)) != 0) {                                \
			TCT_FAILF("%s: bytes differ", #got);                              \
			tct_hexdump("  got ", (const unsigned char *)(got), (n));         \
			tct_hexdump("  want", (const unsigned char *)(want), (n));        \
		}                                                                     \
	} while (0)

/* Not every suite compares buffers, so this may legitimately go unused. */
__attribute__((unused)) static void tct_hexdump(const char *label,
                                              const unsigned char *p, size_t n)
{
	fprintf(stderr, "%s (%zu): ", label, n);
	for (size_t i = 0; i < n; i++)
		fprintf(stderr, "%02x", p[i]);
	fputc('\n', stderr);
}

static int tct_report(const char *suite)
{
	if (tct_fails == 0) {
		printf("ok   %-24s %d checks\n", suite, tct_checks);
		return 0;
	}
	printf("FAIL %-24s %d checks, %d failures\n", suite, tct_checks, tct_fails);
	return 1;
}

#endif /* TC_TCTEST_H_ */
