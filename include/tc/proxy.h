/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Splicing tunnel connections to host sockets, many at a time.
 *
 * `serve 80` proxies an inbound tunnel connection to localhost:80; `forward`
 * will do the reverse; `socks` will do it with a negotiation in front. All
 * three are the same machine underneath -- a set of (tunnel connection, host
 * socket) pairs with bytes moving both ways -- so it lives here once rather
 * than three times in the CLI.
 *
 * Two things this gets right that a naive copy loop does not:
 *
 *   Half close is propagated. When the tunnel side finishes sending, the
 *   host socket is shut down for writing once the last byte has been handed
 *   over, and vice versa. Without that, `echo hi | tailcat <addr> 80` hangs:
 *   the local service is waiting for an EOF that never arrives.
 *
 *   Nothing blocks. Every socket is put in non-blocking mode on adoption, and
 *   a short write parks the remainder in a staging buffer. One slow peer must
 *   not stop the WireGuard timers, which run in the same loop.
 *
 * The caller drives it: poll whatever tc_proxy_interest reports, then call
 * tc_proxy_pump. The tunnel connections belong to the demultiplexer and are
 * never freed here; the host sockets are owned by the proxy and closed by it.
 */
#ifndef TC_PROXY_H_
#define TC_PROXY_H_

#include "tc/tcp.h"

/* Staging buffer per direction per pair. Small on purpose: the real buffering
 * is the TCP send and receive buffers underneath, and this only has to hold
 * what one short write left behind. */
#ifndef TC_PROXY_BUFSZ
#define TC_PROXY_BUFSZ 8192
#endif

typedef struct tc_proxy tc_proxy;

typedef struct {
	uint64_t opened;
	uint64_t closed;
	uint64_t failed;        /* pairs dropped by an error rather than an EOF */
	uint64_t bytes_to_host; /* out of the tunnel, into the local socket */
	uint64_t bytes_to_tun;
} tc_proxy_stats;

/* tc_proxy_new allocates a proxy holding at most max_pairs. */
tc_proxy *tc_proxy_new(size_t max_pairs);

/* tc_proxy_free closes every host socket still held. The tunnel connections
 * are left alone: the demultiplexer owns those. */
void tc_proxy_free(tc_proxy *p);

/* tc_proxy_add adopts a pair and takes ownership of fd, which it switches to
 * non-blocking mode -- a caller cannot forget to.
 *
 * Returns TC_ERR_TOOMANY when full, in which case fd is NOT closed and the
 * caller still owns it. */
int tc_proxy_add(tc_proxy *p, tc_tcp_conn *tun, int fd);

/* tc_proxy_pump moves whatever can move in both directions for every pair,
 * and propagates half closes. Returns the number of pairs that moved a byte
 * or changed state, so an event loop can tell whether to poll or go round
 * again. */
size_t tc_proxy_pump(tc_proxy *p, uint64_t now_ms);

/* tc_proxy_reap drops finished and failed pairs, closing their sockets and
 * returning how many went. The tunnel connection is left to the mux to reap;
 * this only stops referring to it. */
size_t tc_proxy_reap(tc_proxy *p, uint64_t now_ms);

/* tc_proxy_forget drops the pair holding this tunnel connection without
 * touching it, for when the mux is about to free it underneath us. The host
 * socket is closed. */
void tc_proxy_forget(tc_proxy *p, const tc_tcp_conn *tun);

size_t tc_proxy_count(const tc_proxy *p);

/* tc_proxy_interest reports what pair i wants from poll(). Returns false for
 * an index past the end. A pair always wants to read unless the host side has
 * already signalled EOF or its staging buffer is full. */
bool tc_proxy_interest(const tc_proxy *p, size_t i, int *fd, bool *want_read,
                       bool *want_write);

void tc_proxy_get_stats(const tc_proxy *p, tc_proxy_stats *out);

#endif /* TC_PROXY_H_ */
