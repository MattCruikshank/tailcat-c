/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See include/tc/duration.h.
 */
#include "tc/duration.h"

#include <limits.h>
#include <string.h>

/* Everything is accumulated in nanoseconds and converted once, so "1h30m"
 * and "5400s" cannot disagree. A uint64 of nanoseconds reaches about 584
 * years, which is further than any deadline here needs to go. */
#define NS_PER_US 1000ull
#define NS_PER_MS (1000ull * NS_PER_US)
#define NS_PER_S (1000ull * NS_PER_MS)
#define NS_PER_M (60ull * NS_PER_S)
#define NS_PER_H (60ull * NS_PER_M)

/* The unit table, longest spellings first: "ms" has to be matched before "m"
 * or "500ms" reads as 500 minutes followed by a stray "s". */
static const struct {
	const char *name;
	uint64_t ns;
} units[] = {
	{ "ns", 1ull },      { "us", NS_PER_US }, { "ms", NS_PER_MS },
	{ "h", NS_PER_H },   { "m", NS_PER_M },   { "s", NS_PER_S },
};

int tc_parse_duration_s(unsigned *out, const char *s)
{
	uint64_t total = 0;
	bool any = false;

	if (out == NULL || s == NULL || s[0] == '\0')
		return TC_ERR_INVAL;
	/* Go accepts a sign; a negative deadline is not a thing this program
	 * can act on, so it is refused rather than clamped. */
	if (s[0] == '-')
		return TC_ERR_INVAL;
	if (s[0] == '+')
		s++;

	const char *p = s;
	while (*p != '\0') {
		if (*p < '0' || *p > '9')
			return TC_ERR_INVAL;

		uint64_t n = 0;
		while (*p >= '0' && *p <= '9') {
			uint64_t d = (uint64_t)(*p - '0');
			if (n > (UINT64_MAX - d) / 10u)
				return TC_ERR_RANGE;
			n = n * 10u + d;
			p++;
		}

		/* No unit at all: the whole string is a count of seconds, which is
		 * the spelling this program documented before it took durations. It
		 * is only legal as the entire value, so "1m30" is rejected rather
		 * than read as ninety of something. */
		if (*p == '\0') {
			if (any)
				return TC_ERR_INVAL;
			if (n > UINT64_MAX / NS_PER_S)
				return TC_ERR_RANGE;
			total = n * NS_PER_S;
			any = true;
			break;
		}

		size_t k;
		for (k = 0; k < sizeof units / sizeof units[0]; k++) {
			size_t len = strlen(units[k].name);
			if (strncmp(p, units[k].name, len) == 0) {
				if (n > UINT64_MAX / units[k].ns)
					return TC_ERR_RANGE;
				uint64_t add = n * units[k].ns;
				if (total > UINT64_MAX - add)
					return TC_ERR_RANGE;
				total += add;
				p += len;
				any = true;
				break;
			}
		}
		if (k == sizeof units / sizeof units[0])
			return TC_ERR_INVAL;
	}

	if (!any)
		return TC_ERR_INVAL;

	/* Rounded up. Zero is reserved: every caller here reads it as "no
	 * deadline", so a 500ms timeout must not become one.
	 *
	 * Divided before the rounding rather than after, because the obvious
	 * (total + NS_PER_S - 1) / NS_PER_S overflows for a total near the top
	 * of the range and wraps to a small, plausible answer. Its own test
	 * caught that: two nanosecond counts that each fit and together do not
	 * were accepted and returned 0. */
	uint64_t secs = total / NS_PER_S;
	if (total % NS_PER_S != 0) {
		if (secs == UINT64_MAX)
			return TC_ERR_RANGE;
		secs++;
	}
	if (secs > (uint64_t)UINT_MAX)
		return TC_ERR_RANGE;
	*out = (unsigned)secs;
	return TC_OK;
}
