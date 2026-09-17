/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Many TCP connections over one tunnel.
 *
 * tcp.h deliberately holds exactly one connection, which is all a single pipe
 * needs. Everything past that -- serving a set of ports, forwarding local
 * ports, a SOCKS proxy -- needs many at once over the same WireGuard session,
 * and something has to decide which arriving packet belongs to which.
 *
 * That is all this is: a table keyed by the port pair, a listener set, and
 * ephemeral port allocation. The state machine in tcp.c is untouched; each
 * connection here is an ordinary tc_tcp_conn, and every packet handed to one
 * is re-validated by it. This layer only chooses the recipient.
 *
 * The tunnel is point to point -- one local address, one remote -- so the
 * remote address is fixed at construction. The *local* one is not, once exit
 * node mode is on: a peer may address a packet to somewhere beyond us, and
 * then the destination it named is what distinguishes one flow from another.
 * The key is therefore (local address, local port, remote port). A packet for
 * a key nobody owns is answered with a reset, rather than dropped, so a peer
 * dialling a closed port learns immediately.
 *
 * Usage mirrors tcp.h, with the caller still driving the clock:
 *
 *     tc_tcp_mux_listen(m, 22)              accept inbound on a port
 *     tc_tcp_mux_connect(m, 80, now, &c)    dial out from an ephemeral port
 *     tc_tcp_mux_input(m, pkt, len, now)    dispatch one received packet
 *     tc_tcp_mux_accept(m)                  take a newly arrived connection
 *     tc_tcp_mux_tick(m, now)               run every connection's timers
 *     tc_tcp_mux_reap(m)                    free the ones that finished
 */
#ifndef TC_TCPMUX_H_
#define TC_TCPMUX_H_

#include "tc/tcp.h"

/* Connections held at once. Each carries its own send buffer, receive buffer
 * and reassembly arena -- around 146 KB with the default sizes -- so this
 * bound is mostly a memory budget. They are allocated as they arrive, not up
 * front. */
#ifndef TC_TCP_MAX_CONNS
#define TC_TCP_MAX_CONNS 64
#endif

/* Ports listened on at once. */
#ifndef TC_TCP_MAX_LISTENERS
#define TC_TCP_MAX_LISTENERS 16
#endif

/* Connections accepted but not yet collected by the caller. Past this a SYN
 * is reset instead of queued, which tells the peer to back off rather than
 * letting an application that has stopped accepting consume the whole table. */
#ifndef TC_TCP_BACKLOG
#define TC_TCP_BACKLOG 8
#endif

/* The ephemeral range, per RFC 6335. */
#define TC_TCP_EPHEMERAL_LO 49152u
#define TC_TCP_EPHEMERAL_HI 65535u

typedef struct tc_tcp_mux tc_tcp_mux;

/* tc_tcp_mux_new creates a demultiplexer for one tunnel. Outgoing packets
 * from every connection go to `out`, exactly as with a lone tc_tcp_conn. */
tc_tcp_mux *tc_tcp_mux_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                           const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                           tc_tcp_output_fn out, void *out_ctx);

/* tc_tcp_mux_free closes and frees every connection still held. */
void tc_tcp_mux_free(tc_tcp_mux *m);

/* tc_tcp_mux_listen accepts inbound connections on a port. Listening costs
 * nothing until a SYN arrives: no connection is allocated in advance.
 *
 * Returns TC_ERR_EXIST if the port is already listened on, TC_ERR_TOOMANY if
 * the listener set is full, and TC_ERR_INVAL for port 0. */
int tc_tcp_mux_listen(tc_tcp_mux *m, uint16_t port);

/* tc_tcp_mux_unlisten stops accepting on a port. Connections already
 * established on it are unaffected. */
int tc_tcp_mux_unlisten(tc_tcp_mux *m, uint16_t port);

bool tc_tcp_mux_is_listening(const tc_tcp_mux *m, uint16_t port);

/* tc_tcp_accept_fn decides whether a port should be accepted on, for callers
 * whose answer does not fit a list.
 *
 * `serve all` is 65,535 ports, which no listener array wants to hold; a
 * predicate expresses it in one line and lets the caller keep the set in
 * whatever shape suits it. The filter is consulted in addition to the
 * explicit listeners, never instead of them, so adding one cannot silently
 * close a port something already listens on.
 *
 * It is called from tc_tcp_mux_input, once per inbound SYN that matches no
 * existing connection, and must not touch the mux. */
typedef bool (*tc_tcp_accept_fn)(void *ctx, uint16_t port);

void tc_tcp_mux_set_accept_filter(tc_tcp_mux *m, tc_tcp_accept_fn fn,
                                  void *ctx);

/* tc_tcp_mux_connect starts an active open to remote_port from a free
 * ephemeral port, storing the new connection in *out. It is owned by the
 * mux; do not free it.
 *
 * Returns TC_ERR_TOOMANY if the table is full or no ephemeral port is free. */
int tc_tcp_mux_connect(tc_tcp_mux *m, uint16_t remote_port, uint64_t now_ms,
                       tc_tcp_conn **out);

/* tc_tcp_mux_connect_from is the same with the local port chosen by the
 * caller, for tests that need a predictable pair. TC_ERR_EXIST if that port
 * pair is already in use. */
/* tc_tcp_mux_set_exit_node decides whether connections addressed to somewhere
 * other than our own tunnel address are accepted.
 *
 * Off by default, and it must stay that way unless asked for: an exit node
 * will dial anything its peer names, which turns a tunnel endpoint into a
 * proxy for everything the machine can reach -- other hosts on its LAN, its
 * own loopback services, its cloud metadata endpoint. That is a useful thing
 * to be and a terrible thing to become by accident, which is why upstream
 * gates it behind an explicit `exit-node` service and so do we.
 *
 * The mux only accepts the connection; where it goes is the caller's
 * decision, made with tc_tcp_local_addr on the accepted connection. */
void tc_tcp_mux_set_exit_node(tc_tcp_mux *m, bool on);

/* tc_tcp_mux_connect_to dials a destination beyond the peer, which the peer
 * must be willing to act as an exit node for.
 *
 * dst_ip is an IPv6 address; an IPv4 destination is carried inside one, see
 * nat64.h. */
int tc_tcp_mux_connect_to(tc_tcp_mux *m, const uint8_t dst_ip[16],
                          uint16_t remote_port, uint64_t now_ms,
                          tc_tcp_conn **out);

int tc_tcp_mux_connect_from(tc_tcp_mux *m, uint16_t local_port,
                            uint16_t remote_port, uint64_t now_ms,
                            tc_tcp_conn **out);

/* tc_tcp_mux_input dispatches one received IPv6 packet to the connection
 * that owns its port pair, opening one if it is a SYN for a listening port.
 *
 * Packets that are malformed, not for this tunnel, or not TCP are ignored.
 * A packet for an unowned port pair draws a reset. Always returns TC_OK
 * unless the arguments are wrong: an unwanted packet is not a caller error,
 * since anything may arrive on a shared tunnel. */
int tc_tcp_mux_input(tc_tcp_mux *m, const uint8_t *ip_pkt, size_t len,
                     uint64_t now_ms);

/* tc_tcp_mux_accept returns the oldest connection that arrived from a
 * listening port and has not been collected yet, or NULL.
 *
 * The connection is returned as soon as its SYN is answered, so it is in
 * SYN_RECEIVED rather than ESTABLISHED -- the caller should wait for
 * tc_tcp_is_established() before writing, exactly as after tc_tcp_connect. */
tc_tcp_conn *tc_tcp_mux_accept(tc_tcp_mux *m);

/* tc_tcp_mux_pending is how many connections tc_tcp_mux_accept would yield. */
size_t tc_tcp_mux_pending(const tc_tcp_mux *m);

/* tc_tcp_mux_tick runs timers on every connection. */
int tc_tcp_mux_tick(tc_tcp_mux *m, uint64_t now_ms);

/* tc_tcp_mux_next_deadline is the earliest deadline across all connections,
 * or UINT64_MAX if none has a timer pending. */
uint64_t tc_tcp_mux_next_deadline(const tc_tcp_mux *m);

/* Iteration, for a caller polling every connection for readability. The
 * order is unspecified and changes when connections are reaped, so an index
 * is only valid until the next call that adds or removes one. */
size_t tc_tcp_mux_count(const tc_tcp_mux *m);
tc_tcp_conn *tc_tcp_mux_at(const tc_tcp_mux *m, size_t i);

/* tc_tcp_mux_close aborts one connection and drops it immediately. */
void tc_tcp_mux_close(tc_tcp_mux *m, tc_tcp_conn *c, uint64_t now_ms);

/* tc_tcp_mux_reap frees every connection that has reached CLOSED, returning
 * how many went. Connections in TIME_WAIT are kept: their whole purpose is to
 * absorb a retransmitted FIN, and dropping one early would answer that FIN
 * with a reset.
 *
 * Every tc_tcp_conn pointer the caller holds may be invalidated, so call it
 * at the top of an event loop rather than mid-iteration. */
size_t tc_tcp_mux_reap(tc_tcp_mux *m);

/* Counters, for tests and diagnostics. */
typedef struct {
	uint64_t accepted;      /* inbound connections opened */
	uint64_t dialled;       /* outbound connections opened */
	uint64_t rejected_port; /* resets sent for a port nobody owns */
	uint64_t rejected_full; /* SYNs refused: table or backlog full */
	uint64_t reaped;        /* connections freed after closing */
} tc_tcp_mux_stats;

void tc_tcp_mux_get_stats(const tc_tcp_mux *m, tc_tcp_mux_stats *out);

#endif /* TC_TCPMUX_H_ */
