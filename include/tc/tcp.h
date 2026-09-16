/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A minimal userspace TCP over IPv6, for two peers.
 *
 * tailcat runs entirely in userspace: it never touches the host's routing
 * table, so the operating system's TCP stack is not available inside the
 * tunnel. Upstream solves this by embedding gvisor's netstack, which is over
 * a hundred thousand lines. This is the far smaller thing that a two-peer
 * netcat actually needs.
 *
 * Scope, deliberately:
 *
 *   - IPv6 only, because tailcat's tunnel addresses are IPv6 ULAs.
 *   - One connection per object. No demultiplexing across many sockets.
 *   - Cumulative acknowledgements with a bounded reassembly queue for
 *     out-of-order arrivals. No SACK, no timestamps, no window scaling.
 *   - Slow start and congestion avoidance, fast retransmit on three
 *     duplicate ACKs, RTO with Jacobson/Karels estimation and Karn's
 *     algorithm. No fast recovery.
 *   - No urgent data, no simultaneous open.
 *
 * The caller drives everything and supplies the clock, so the whole stack can
 * be tested against a simulated link with loss, reordering and delay without
 * a network or a real timer anywhere:
 *
 *     tc_tcp_connect()               start an active open
 *     tc_tcp_input(pkt, now)         feed one received IPv6 packet
 *     tc_tcp_tick(now)               run timers; call by tc_tcp_next_deadline
 *     tc_tcp_write() / tc_tcp_read() move payload
 *     tc_tcp_shutdown_write()        send FIN, keep reading
 *
 * Outgoing packets go to the callback given at construction. It is called
 * from inside the functions above, never spontaneously.
 */
#ifndef TC_TCP_H_
#define TC_TCP_H_

#include "tc/tc.h"

#define TC_IPV6_ADDR_LEN 16
#define TC_IPV6_HEADER_LEN 40
#define TC_TCP_HEADER_LEN 20

/* The tunnel carries at most a 1232-byte UDP payload (tailcat's
 * MaxUDPPayload), and the WireGuard transport header and tag take 32 of it.
 * What is left, less the IPv6 and TCP headers, is the largest segment we can
 * send without fragmenting -- which we cannot do, since there is no path MTU
 * discovery here. */
#define TC_TCP_MSS 1140

/* Buffer sizes. These bound both throughput and memory: a connection holds
 * one of each plus the reassembly arena. */
#ifndef TC_TCP_SNDBUF
#define TC_TCP_SNDBUF 65536
#endif
#ifndef TC_TCP_RCVBUF
#define TC_TCP_RCVBUF 65536
#endif

/* Out-of-order segments held while waiting for the gap to be filled. Beyond
 * this, segments are dropped and recovered by retransmission. */
#ifndef TC_TCP_OOO_SEGS
#define TC_TCP_OOO_SEGS 16
#endif

typedef enum {
	TC_TCP_CLOSED = 0,
	TC_TCP_LISTEN,
	TC_TCP_SYN_SENT,
	TC_TCP_SYN_RECEIVED,
	TC_TCP_ESTABLISHED,
	TC_TCP_FIN_WAIT_1,
	TC_TCP_FIN_WAIT_2,
	TC_TCP_CLOSING,
	TC_TCP_TIME_WAIT,
	TC_TCP_CLOSE_WAIT,
	TC_TCP_LAST_ACK
} tc_tcp_state;

/* tc_tcp_output_fn is called with a complete IPv6 packet to transmit. It
 * should return TC_OK; any other value is treated as the packet having been
 * dropped, which is safe -- TCP will retransmit. */
typedef int (*tc_tcp_output_fn)(void *ctx, const uint8_t *ip_pkt, size_t len);

typedef struct tc_tcp_conn tc_tcp_conn;

/* tc_tcp_new allocates a connection between two IPv6 addresses. */
tc_tcp_conn *tc_tcp_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                        const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                        tc_tcp_output_fn out, void *out_ctx);
void tc_tcp_free(tc_tcp_conn *c);

/* tc_tcp_connect starts an active open, sending the SYN immediately. */
int tc_tcp_connect(tc_tcp_conn *c, uint16_t local_port, uint16_t remote_port,
                   uint64_t now_ms);

/* tc_tcp_listen waits for an incoming SYN on local_port. One connection
 * only: a second SYN while established is ignored. */
int tc_tcp_listen(tc_tcp_conn *c, uint16_t local_port);

/* tc_tcp_input feeds one received IPv6 packet.
 *
 * Packets that are not for this connection -- wrong address, wrong port,
 * not TCP, bad checksum -- are ignored rather than reported as errors, since
 * anything may arrive on a shared tunnel. */
int tc_tcp_input(tc_tcp_conn *c, const uint8_t *ip_pkt, size_t len,
                 uint64_t now_ms);

/* tc_tcp_tick runs retransmission, delayed-ACK and TIME-WAIT timers. */
int tc_tcp_tick(tc_tcp_conn *c, uint64_t now_ms);

/* tc_tcp_next_deadline returns the time by which tc_tcp_tick should next be
 * called, or UINT64_MAX if no timer is pending. */
uint64_t tc_tcp_next_deadline(const tc_tcp_conn *c);

/* tc_tcp_write queues payload, storing how much was accepted in *written.
 * A short write means the send buffer is full; try again after reading or
 * after the peer acknowledges. */
int tc_tcp_write(tc_tcp_conn *c, const void *buf, size_t len, size_t *written,
                 uint64_t now_ms);

/* tc_tcp_read copies received payload out, storing the count in *nread.
 * Zero with tc_tcp_read_closed() true means the peer has finished sending. */
int tc_tcp_read(tc_tcp_conn *c, void *buf, size_t cap, size_t *nread);

/* tc_tcp_shutdown_write sends FIN once queued data has been acknowledged.
 * Reading continues to work: this is a half close, which is what piping
 * stdin to a peer and then waiting for its reply requires. */
int tc_tcp_shutdown_write(tc_tcp_conn *c, uint64_t now_ms);

/* tc_tcp_abort sends RST and moves to CLOSED. */
void tc_tcp_abort(tc_tcp_conn *c, uint64_t now_ms);

tc_tcp_state tc_tcp_get_state(const tc_tcp_conn *c);
const char *tc_tcp_state_name(tc_tcp_state s);

/* tc_tcp_readable returns how many bytes tc_tcp_read would return now. */
size_t tc_tcp_readable(const tc_tcp_conn *c);

/* tc_tcp_writable returns how many bytes tc_tcp_write would accept now. */
size_t tc_tcp_writable(const tc_tcp_conn *c);

/* tc_tcp_read_closed reports that the peer sent FIN and everything before it
 * has been read. */
bool tc_tcp_read_closed(const tc_tcp_conn *c);

/* tc_tcp_is_established reports whether payload can flow. */
bool tc_tcp_is_established(const tc_tcp_conn *c);

/* tc_tcp_send_unacked returns how many bytes are written but not yet
 * acknowledged; zero means everything handed to tc_tcp_write has arrived. */
size_t tc_tcp_send_unacked(const tc_tcp_conn *c);

/* Counters, for tests and diagnostics. */
typedef struct {
	uint64_t segs_sent;
	uint64_t segs_received;
	uint64_t segs_dropped_checksum;
	uint64_t retransmits;
	uint64_t fast_retransmits;
	uint64_t ooo_queued;
	uint64_t ooo_dropped;
	uint64_t bytes_sent;
	uint64_t bytes_received;
} tc_tcp_stats;

void tc_tcp_get_stats(const tc_tcp_conn *c, tc_tcp_stats *out);

/* tc_tcp_force_next_iss fixes the initial sequence number of the next
 * connection opened on this thread.
 *
 * FOR TESTS ONLY. Sequence numbers wrap at 2^32, and every comparison in the
 * implementation has to be correct across that wrap; without this hook the
 * only way to reach it is to transfer four gigabytes. A predictable initial
 * sequence number makes blind injection into the stream practical for an
 * off-path attacker, so nothing outside a test may call this. */
void tc_tcp_force_next_iss(uint32_t iss);

#endif /* TC_TCP_H_ */
