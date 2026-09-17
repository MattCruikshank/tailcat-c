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
 *     13306:[2001:db8::1]:3306 the same, for an IPv6 destination
 *
 * The last two need the server to be running as an exit node, which it will
 * only do if it was started with `serve exit-node`. A server that was not
 * answers with a reset, the same as any closed port.
 */
#ifndef TC_FWDSPEC_H_
#define TC_FWDSPEC_H_

#include "tc/endpoint.h"

typedef struct {
	/* 0 means "ask the operating system for a free port". */
	uint16_t local_port;
	uint16_t remote_port;

	/* Where the traffic goes once it is through the tunnel.
	 *
	 * ip_len 0 means the server itself, which is the ordinary case. Anything
	 * else is a destination beyond it, and needs an exit node. An IPv4
	 * destination is stored as IPv4 here; wrapping it for the IPv6-only
	 * tunnel is nat64.h's job and happens at the point of use, so that what
	 * the user typed is still what this structure says. */
	tc_endpoint dst;
} tc_fwd_spec;

/* tc_fwd_parse reads one mapping.
 *
 * The destination must be a literal address: no DNS. A name would have to be
 * resolved somewhere, and resolving it here would resolve it on the wrong
 * machine -- "database" means something different on the far side of the
 * tunnel, which is usually the whole point of forwarding to it.
 *
 * Returns TC_ERR_INVAL for anything malformed. tc_fwd_error_string describes
 * the last failure. */
int tc_fwd_parse(tc_fwd_spec *out, const char *spec);

const char *tc_fwd_error_string(void);

#endif /* TC_FWDSPEC_H_ */
