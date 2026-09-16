/* SPDX-License-Identifier: BSD-3-Clause
 *
 * An IP address and port, and the question of whether it is worth telling a
 * peer about.
 *
 * Both the STUN client and the UDP transport traffic in these, so the type
 * lives here rather than in either of them.
 */
#ifndef TC_ENDPOINT_H_
#define TC_ENDPOINT_H_

#include "tc/tc.h"

/* Four or sixteen bytes, and a port. Not a sockaddr: this crosses module
 * boundaries and appears in tests, and a sockaddr would drag <sys/socket.h>
 * into every header that mentions an address. */
typedef struct {
	uint8_t ip[16];
	uint8_t ip_len; /* 4 or 16; 0 means unset */
	uint16_t port;
} tc_endpoint;

/* tc_endpoint_format writes "1.2.3.4:567" or "[2001:db8::1]:567". */
int tc_endpoint_format(char *out, size_t cap, const tc_endpoint *ep);

bool tc_endpoint_equal(const tc_endpoint *a, const tc_endpoint *b);

/* tc_endpoint_is_candidate reports whether an address of ours is worth
 * offering a peer as somewhere to reach us directly.
 *
 * This is a filter on what we *advertise*, not on what we accept. Getting it
 * wrong is not a security problem so much as a waste: every rejected address
 * is a probe the peer would have sent to somewhere it could never reach, and
 * every wrongly rejected one is a direct path that never gets found. */
bool tc_endpoint_is_candidate(const tc_endpoint *ep);

#endif /* TC_ENDPOINT_H_ */
