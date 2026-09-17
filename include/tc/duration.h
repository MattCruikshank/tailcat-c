/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Durations, in the form upstream's flags take.
 *
 * `--timeout` is a Go duration there: "30s", "2m", "1h30m", "500ms". Here it
 * was read with strtoul, which stops at the first character it does not
 * understand and reports nothing. "30s" became 30, which is right by
 * accident; "2m" became 2, which is wrong by a factor of sixty, and wrong
 * silently -- the command ran, it just gave up fifty-eight seconds early.
 *
 * A bare number is still seconds, because that is what this program's own
 * documentation has always said and scripts will have been written to it.
 */
#ifndef TC_DURATION_H_
#define TC_DURATION_H_

#include "tc/tc.h"

/* tc_parse_duration_s reads a duration and rounds it to whole seconds.
 *
 * Accepts a bare decimal count of seconds, or one or more number-and-unit
 * pairs using ns, us, ms, s, m or h -- so "90s", "1m30s" and "90000ms" are
 * the same value. Rounds *up*, because a sub-second timeout that rounded
 * down to zero would mean "no deadline" to every caller here, which is the
 * opposite of what the user asked for. Only a literal zero gives zero.
 *
 * Returns TC_ERR_INVAL for an empty string, a negative value, an unknown
 * unit or any trailing text, and TC_ERR_RANGE if the total does not fit.
 * Refusing is the point: the bug being fixed was a parser that accepted
 * nonsense and carried on. */
int tc_parse_duration_s(unsigned *out, const char *s);

#endif /* TC_DURATION_H_ */
