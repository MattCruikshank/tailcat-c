/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Port-forwarding mappings, and the spec syntax that describes them.
 *
 * Upstream's `tailcat forward <addr> <mapping> ...` takes:
 *
 *     8080                    listen on 8080, reach the server's 8080
 *     18080:8080              listen on 18080, reach the server's 8080
 *     0:8080                  let the OS choose the local port
 *     13306:192.168.1.10:3306 reach an address beyond the server
 *
 * The last form needs the server to be running as an exit node, which we do
 * not implement, so it is recognised and refused by name rather than being
 * called a syntax error -- the same distinction portset.h draws for named
 * services.
 */
#ifndef TC_FWDSPEC_H_
#define TC_FWDSPEC_H_

#include "tc/tc.h"

typedef struct {
	/* 0 means "ask the operating system for a free port". */
	uint16_t local_port;
	uint16_t remote_port;
} tc_fwd_spec;

/* tc_fwd_parse reads one mapping.
 *
 * Returns TC_ERR_UNSUPPORTED for the `local:host:port` form, which needs an
 * exit node, and TC_ERR_INVAL for anything malformed.
 * tc_fwd_error_string describes the last failure. */
int tc_fwd_parse(tc_fwd_spec *out, const char *spec);

const char *tc_fwd_error_string(void);

#endif /* TC_FWDSPEC_H_ */
