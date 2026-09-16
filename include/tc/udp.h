/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A UDP socket pair, and the local addresses to advertise on it.
 *
 * This is what a direct peer-to-peer path is made of. Until now every packet
 * went through a relay over TCP; this opens the door to sending one straight
 * at a peer, which is the whole point of Phase 4.
 *
 * Two sockets, not one. A single IPv6 socket with V6ONLY off can carry IPv4
 * through v4-mapped addresses, but then every address this code handles has
 * two spellings and the bugs live in the seam between them. Separate sockets
 * cost one extra descriptor and remove that class entirely.
 *
 * Both are bound to the same port where the operating system allows it, so a
 * peer told "reach me on port N" can use N whichever family it picks.
 */
#ifndef TC_UDP_H_
#define TC_UDP_H_

#include "tc/endpoint.h"

/* Local addresses offered to a peer at once. A machine with more interfaces
 * than this has more than a peer would sensibly probe. */
#ifndef TC_UDP_MAX_LOCAL
#define TC_UDP_MAX_LOCAL 12
#endif

typedef struct {
	int fd4;
	int fd6;
	uint16_t port; /* the bound port, which may not be the one requested */
} tc_udp;

/* tc_udp_open binds both sockets. port 0 asks the operating system to choose,
 * which is what a client wants; a server that has advertised a port passes it.
 *
 * Succeeds if either family binds: a host with no IPv6 is ordinary, and so is
 * one where IPv6 is all there is. */
int tc_udp_open(tc_udp *u, uint16_t port);

void tc_udp_close(tc_udp *u);

/* tc_udp_send transmits one datagram. Returns TC_ERR_INVAL if the endpoint's
 * family has no socket -- an IPv6 peer on an IPv4-only host is a real
 * situation, not a caller error, and the caller decides what to do about it. */
int tc_udp_send(tc_udp *u, const tc_endpoint *dst, const void *pkt,
                size_t len);

/* tc_udp_recv reads one datagram from either socket, reporting who sent it.
 *
 * Returns TC_ERR_TIMEOUT when nothing arrives within timeout_ms, which is not
 * an error: on a direct path silence is the normal state between packets. */
int tc_udp_recv(tc_udp *u, tc_endpoint *src, uint8_t *buf, size_t cap,
                size_t *out_len, int timeout_ms);

/* tc_udp_fds writes the descriptors for an event loop to poll. */
size_t tc_udp_fds(const tc_udp *u, int *out, size_t cap);

/* tc_udp_local_endpoints lists this machine's own addresses paired with the
 * bound port -- the candidates to offer a peer, in the order they were found.
 *
 * Loopback, link-local, multicast and carrier-NAT addresses are left out; see
 * tc_endpoint_is_candidate for why each. Private addresses stay, because two
 * peers on one LAN reaching each other directly is the best case there is.
 *
 * Returns how many were written. Zero is possible and is not a failure: a
 * host behind NAT with nothing but a private address still has the relay, and
 * STUN will supply the address the outside world sees. */
size_t tc_udp_local_endpoints(const tc_udp *u, tc_endpoint *out, size_t cap);

#endif /* TC_UDP_H_ */
