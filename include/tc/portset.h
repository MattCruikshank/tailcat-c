/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The set of ports a server offers, and the spec syntax that describes it.
 *
 * Upstream's `tailcat serve 22,80,443,8000-8999` takes a comma-separated list
 * of ports, inclusive ranges, and named services, and the list may be spread
 * over several arguments. This parses the same syntax.
 *
 * A bitmap rather than a list of ranges: `all` is 65,535 ports, membership is
 * tested once per inbound SYN, and 8 KB of exact answer is cheaper to reason
 * about than a range list that has to stay sorted and coalesced. Port 0 is
 * never a member -- it is not a real port, and admitting it would mean
 * answering a SYN that could only have come from something malformed.
 */
#ifndef TC_PORTSET_H_
#define TC_PORTSET_H_

#include "tc/tc.h"

typedef struct {
	uint8_t bits[8192]; /* one bit per port, index 0 unused */
	size_t count;
} tc_portset;

/* Named services upstream accepts that we do not implement. They are parsed
 * and reported by name rather than lumped in with a syntax error, because
 * "ssh is not implemented here" and "that is not a port" are different
 * things to be told. */
typedef enum {
	TC_PORTSET_SVC_NONE = 0,
	TC_PORTSET_SVC_SSH,
	TC_PORTSET_SVC_NO_AUTH_SSH,
	TC_PORTSET_SVC_FILES,
	TC_PORTSET_SVC_EXEC,
	TC_PORTSET_SVC_EXIT_NODE
} tc_portset_service;

void tc_portset_clear(tc_portset *ps);
void tc_portset_add(tc_portset *ps, uint16_t port);
bool tc_portset_has(const tc_portset *ps, uint16_t port);

/* tc_portset_add_range adds lo..hi inclusive, in either order. */
void tc_portset_add_range(tc_portset *ps, uint16_t lo, uint16_t hi);

/* tc_portset_parse folds one spec into ps, which the caller has cleared.
 *
 * Accepts `80`, `8000-8999`, `all`, and comma-separated combinations. On
 * meeting a named service it stops and reports which one through *service,
 * returning TC_ERR_UNSUPPORTED; anything already parsed stays in ps.
 *
 * Returns TC_ERR_INVAL for syntax errors and TC_ERR_RANGE for a number above
 * 65535. `tc_portset_error_string` describes the last failure. */
int tc_portset_parse(tc_portset *ps, const char *spec,
                     tc_portset_service *service);

const char *tc_portset_error_string(void);

/* tc_portset_service_name is the spec word for a service, for diagnostics. */
const char *tc_portset_service_name(tc_portset_service svc);

/* tc_portset_describe writes a short human summary such as "22, 80, 443" or
 * "1-65535 (all)" into out, for the line a server prints at startup. */
int tc_portset_describe(const tc_portset *ps, char *out, size_t cap);

#endif /* TC_PORTSET_H_ */
