/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Datagrams through the tunnel.
 *
 * The tunnel carries IP, and everything built on it so far has been TCP. DNS,
 * QUIC, NTP, game traffic and syslog are not, and forwarding a UDP port is
 * the single most asked-for thing a TCP-only tunnel cannot do.
 *
 * There is much less here than in tcpmux, and that is the nature of UDP
 * rather than an omission: no handshake, no retransmission, no sequence
 * space, no teardown. What is left is a header, a checksum, and the question
 * of which local socket an arriving datagram belongs to.
 *
 * ---- the checksum is not optional --------------------------------------
 *
 * Over IPv4 a UDP checksum may be omitted by sending zero. Over IPv6 it may
 * not: RFC 8200 section 8.1 requires it, because IPv6 has no header checksum
 * of its own and nothing else would catch a corrupted address. A datagram
 * arriving with a zero checksum is therefore malformed rather than
 * unprotected, and is dropped.
 *
 * The other half of that rule is easy to miss. A checksum that *computes* to
 * zero must be transmitted as 0xFFFF, which is equal in ones-complement
 * arithmetic, so that zero keeps its meaning of "not present". Getting this
 * wrong produces a datagram that is correct roughly 65535 times in 65536 and
 * silently discarded the other time.
 *
 * ---- bindings ----------------------------------------------------------
 *
 * UDP has no connections, so there is nothing to key a flow on except the
 * port pair -- and unlike TCP, nothing ever says a flow has ended. A binding
 * is therefore created on first use and expires on idleness, exactly as a NAT
 * does, and for the same reason: the alternative is a table that only grows.
 *
 * The idle time follows RFC 4787 REQ-5, which requires a UDP mapping to
 * survive at least two minutes of silence. A shorter one breaks request and
 * response protocols that wait longer than that between packets, and DNS
 * resolvers and game servers both do.
 *
 * ---- what arriving datagrams are allowed to do -------------------------
 *
 * A datagram addressed to a port nothing is listening on is dropped in
 * silence. There is no ICMP port-unreachable, partly because there is no ICMP
 * here at all, and partly because generating one would turn the tunnel into a
 * reflector that answers unsolicited traffic.
 *
 * The receive queue is bounded, and a full queue drops the arriving datagram
 * rather than an older one. That is what a full socket buffer does, and UDP
 * callers already have to tolerate loss; silently replacing a datagram the
 * caller has not read yet would be worse than not accepting a new one.
 */
#ifndef TC_UDPMUX_H_
#define TC_UDPMUX_H_

#include "tc/tcp.h" /* for TC_IPV6_ADDR_LEN and TC_IPV6_HEADER_LEN */

#define TC_UDP_HEADER_LEN 8

/* The largest datagram the tunnel can carry.
 *
 * The same budget TC_TCP_MSS comes from -- tailcat carries at most a
 * 1232-byte UDP payload and WireGuard takes 32 of it -- less the IPv6 and UDP
 * headers instead of the IPv6 and TCP ones. Written as a difference from
 * TC_TCP_MSS so the two cannot drift apart if that budget ever changes.
 *
 * A caller handing over more gets TC_ERR_TOOMANY rather than a fragment:
 * there is no IPv6 fragmentation here, and quietly truncating a datagram
 * would corrupt it in a way UDP gives the receiver no way to notice. */
#define TC_UDP_MAX_DGRAM (TC_TCP_MSS + TC_TCP_HEADER_LEN - TC_UDP_HEADER_LEN)

#ifndef TC_UDPMUX_MAX_BINDINGS
#define TC_UDPMUX_MAX_BINDINGS 64
#endif

#ifndef TC_UDPMUX_MAX_LISTENERS
#define TC_UDPMUX_MAX_LISTENERS 16
#endif

/* Datagrams held between calls to tc_udp_mux_recv. */
#ifndef TC_UDPMUX_QUEUE
#define TC_UDPMUX_QUEUE 32
#endif

/* RFC 4787 REQ-5: a UDP mapping must not expire in under two minutes. */
#define TC_UDPMUX_BINDING_IDLE_MS (2u * 60u * 1000u)

/* The ephemeral range, per RFC 6335, as tcpmux uses. */
#define TC_UDP_EPHEMERAL_LO 49152u
#define TC_UDP_EPHEMERAL_HI 65535u

typedef struct tc_udp_mux tc_udp_mux;

/* Called with a complete IPv6 packet to transmit through the tunnel. */
typedef int (*tc_udp_output_fn)(void *ctx, const uint8_t *ip_pkt, size_t len);

/* Decides whether an arriving datagram for a port we are not explicitly
 * listening on should be accepted. Used by a server that serves a range.
 * NULL means only the explicit listeners are open. */
typedef bool (*tc_udp_accept_fn)(void *ctx, uint16_t port);

typedef struct {
	uint64_t dgrams_sent;
	uint64_t dgrams_received;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t dropped_not_udp;
	uint64_t dropped_malformed;
	uint64_t dropped_checksum;
	uint64_t dropped_no_listener;
	uint64_t dropped_queue_full;
	uint64_t bindings_expired;
} tc_udp_mux_stats;

/* tc_udp_mux_new creates a demultiplexer for one tunnel. The addresses are
 * fixed, because the tunnel is point to point. */
tc_udp_mux *tc_udp_mux_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                           const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                           tc_udp_output_fn out, void *ctx);

void tc_udp_mux_free(tc_udp_mux *m);

/* tc_udp_mux_listen accepts datagrams addressed to a port. */
int tc_udp_mux_listen(tc_udp_mux *m, uint16_t port);

void tc_udp_mux_set_accept_filter(tc_udp_mux *m, tc_udp_accept_fn fn,
                                  void *ctx);

/* tc_udp_mux_bind reserves an ephemeral local port for talking to a remote
 * one, so replies can be routed back to the socket that asked.
 *
 * Calling it again for the same remote port returns the same local port and
 * refreshes the idle timer, which is what makes a sequence of requests to one
 * service share a binding instead of exhausting the range. */
int tc_udp_mux_bind(tc_udp_mux *m, uint16_t remote_port, uint64_t now_ms,
                    uint16_t *out_local_port);

/* tc_udp_mux_send transmits one datagram. */
int tc_udp_mux_send(tc_udp_mux *m, uint16_t local_port, uint16_t remote_port,
                    const void *data, size_t len, uint64_t now_ms);

/* tc_udp_mux_input feeds one received IPv6 packet.
 *
 * Packets that are not ours -- not IPv6, not UDP, wrong addresses, bad
 * checksum, no listener -- are counted and dropped rather than reported as
 * errors. Anything may arrive on a tunnel, and a caller cannot do anything
 * useful with the distinction. Returns TC_OK if a datagram was queued. */
int tc_udp_mux_input(tc_udp_mux *m, const uint8_t *pkt, size_t len,
                     uint64_t now_ms);

/* tc_udp_mux_recv takes the oldest queued datagram.
 *
 * Returns TC_ERR_AGAIN when the queue is empty, and TC_ERR_NOSPACE if the
 * datagram does not fit -- in which case it stays queued, so a caller with a
 * bigger buffer can still get it. Truncating would hand back something that
 * is not what was sent, with no way to tell. */
int tc_udp_mux_recv(tc_udp_mux *m, uint16_t *local_port,
                    uint16_t *remote_port, uint8_t *out, size_t cap,
                    size_t *out_len);

/* tc_udp_mux_tick expires idle bindings. */
void tc_udp_mux_tick(tc_udp_mux *m, uint64_t now_ms);

void tc_udp_mux_get_stats(const tc_udp_mux *m, tc_udp_mux_stats *out);

/* tc_udp_mux_is_udp reports whether an IPv6 packet carries UDP, so a caller
 * holding both muxes can route without parsing twice. */
bool tc_udp_mux_is_udp(const uint8_t *pkt, size_t len);

#endif /* TC_UDPMUX_H_ */
