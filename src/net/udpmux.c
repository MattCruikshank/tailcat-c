/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See udpmux.h.
 */

#include "tc/udpmux.h"

#include <stdlib.h>
#include <string.h>

/* A flow, keyed by everything that distinguishes one.
 *
 * The remote *address* is part of the key because a destination beyond the
 * peer is possible: one local port may be talking to several, and without the
 * address their replies would be indistinguishable -- the same lesson tcpmux
 * learned when its port-pair key started colliding. remote_ip all zeroes
 * means the peer itself, which is the ordinary case. */
typedef struct {
	bool used;
	uint16_t local_port;
	uint16_t remote_port;
	uint8_t remote_ip[TC_IPV6_ADDR_LEN];
	bool has_remote_ip;
	uint64_t last_used_ms;
} binding;

/* touch refreshes a binding's idle timer, and only ever forwards.
 *
 * The clock is the caller's, and a caller that hands over a stale timestamp
 * -- a queued packet processed late, two code paths reading the clock at
 * slightly different moments -- would otherwise age a binding that is in
 * active use and expire a live flow underneath itself. */
static void touch(binding *b, uint64_t now_ms)
{
	if (b != NULL && now_ms > b->last_used_ms)
		b->last_used_ms = now_ms;
}

typedef struct {
	uint16_t local_port;
	uint16_t remote_port;
	tc_endpoint dst; /* ip_len 0 when it was addressed to us */
	size_t len;
	uint8_t data[TC_UDP_MAX_DGRAM];
} queued;

struct tc_udp_mux {
	uint8_t local_ip[TC_IPV6_ADDR_LEN];
	uint8_t remote_ip[TC_IPV6_ADDR_LEN];
	tc_udp_output_fn out;
	void *out_ctx;

	uint16_t listeners[TC_UDPMUX_MAX_LISTENERS];
	size_t num_listeners;
	tc_udp_accept_fn accept;
	void *accept_ctx;

	binding bindings[TC_UDPMUX_MAX_BINDINGS];
	uint16_t next_ephemeral;
	bool exit_node;

	/* A ring, so taking the oldest is not a memmove of the whole queue. */
	queued q[TC_UDPMUX_QUEUE];
	size_t q_head;
	size_t q_count;

	tc_udp_mux_stats stats;
};

/* ---- byte order -------------------------------------------------------- */

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* ---- checksum ---------------------------------------------------------- */

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
	size_t i = 0;
	for (; i + 1 < n; i += 2)
		sum += (uint32_t)p[i] << 8 | p[i + 1];
	if (i < n)
		sum += (uint32_t)p[i] << 8; /* odd trailing byte, zero-padded */
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* udp_checksum covers the IPv6 pseudo-header and the datagram. The
 * pseudo-header binds the datagram to its addresses, so one delivered to the
 * wrong peer fails the check rather than being accepted. */
static uint16_t udp_checksum(const uint8_t *src, const uint8_t *dst,
                             const uint8_t *udp, size_t udp_len)
{
	uint32_t sum = 0;
	uint8_t pseudo[8];

	sum = csum_add(sum, src, TC_IPV6_ADDR_LEN);
	sum = csum_add(sum, dst, TC_IPV6_ADDR_LEN);
	pseudo[0] = (uint8_t)(udp_len >> 24);
	pseudo[1] = (uint8_t)(udp_len >> 16);
	pseudo[2] = (uint8_t)(udp_len >> 8);
	pseudo[3] = (uint8_t)udp_len;
	pseudo[4] = 0;
	pseudo[5] = 0;
	pseudo[6] = 0;
	pseudo[7] = 17; /* next header: UDP */
	sum = csum_add(sum, pseudo, sizeof pseudo);
	sum = csum_add(sum, udp, udp_len);

	return csum_fold(sum);
}

/* ---- lifetime ---------------------------------------------------------- */

tc_udp_mux *tc_udp_mux_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                           const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                           tc_udp_output_fn out, void *ctx)
{
	if (local_ip == NULL || remote_ip == NULL || out == NULL)
		return NULL;

	tc_udp_mux *m = (tc_udp_mux *)calloc(1, sizeof *m);
	if (m == NULL)
		return NULL;
	memcpy(m->local_ip, local_ip, TC_IPV6_ADDR_LEN);
	memcpy(m->remote_ip, remote_ip, TC_IPV6_ADDR_LEN);
	m->out = out;
	m->out_ctx = ctx;
	m->next_ephemeral = TC_UDP_EPHEMERAL_LO;
	return m;
}

void tc_udp_mux_free(tc_udp_mux *m)
{
	if (m == NULL)
		return;
	/* Datagrams may still be queued, and their contents are the tunnel's
	 * traffic. */
	memset(m, 0, sizeof *m);
	free(m);
}

/* ---- listeners --------------------------------------------------------- */

int tc_udp_mux_listen(tc_udp_mux *m, uint16_t port)
{
	if (m == NULL || port == 0)
		return TC_ERR_INVAL;
	for (size_t i = 0; i < m->num_listeners; i++) {
		if (m->listeners[i] == port)
			return TC_OK;
	}
	if (m->num_listeners >= TC_UDPMUX_MAX_LISTENERS)
		return TC_ERR_TOOMANY;
	m->listeners[m->num_listeners++] = port;
	return TC_OK;
}

void tc_udp_mux_set_accept_filter(tc_udp_mux *m, tc_udp_accept_fn fn,
                                  void *ctx)
{
	if (m == NULL)
		return;
	m->accept = fn;
	m->accept_ctx = ctx;
}

static bool listening(const tc_udp_mux *m, uint16_t port)
{
	for (size_t i = 0; i < m->num_listeners; i++) {
		if (m->listeners[i] == port)
			return true;
	}
	if (m->accept != NULL)
		return m->accept(m->accept_ctx, port);
	return false;
}

/* ---- bindings ---------------------------------------------------------- */

/* remote_ip NULL means "the peer itself". */
static binding *find_binding(tc_udp_mux *m, uint16_t local, uint16_t remote,
                             const uint8_t remote_ip[TC_IPV6_ADDR_LEN])
{
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		binding *b = &m->bindings[i];
		if (!b->used || b->local_port != local || b->remote_port != remote)
			continue;
		if (remote_ip == NULL) {
			if (b->has_remote_ip)
				continue;
		} else {
			if (!b->has_remote_ip ||
			    memcmp(b->remote_ip, remote_ip, TC_IPV6_ADDR_LEN) != 0)
				continue;
		}
		return b;
	}
	return NULL;
}

/* remember records a flow so its replies can be routed back, creating one if
 * this is the first datagram. */
static void remember(tc_udp_mux *m, uint16_t local, uint16_t remote,
                     const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                     uint64_t now_ms)
{
	binding *b = find_binding(m, local, remote, remote_ip);
	if (b != NULL) {
		touch(b, now_ms);
		return;
	}
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		if (m->bindings[i].used)
			continue;
		b = &m->bindings[i];
		memset(b, 0, sizeof *b);
		b->used = true;
		b->local_port = local;
		b->remote_port = remote;
		if (remote_ip != NULL) {
			memcpy(b->remote_ip, remote_ip, TC_IPV6_ADDR_LEN);
			b->has_remote_ip = true;
		}
		b->last_used_ms = now_ms;
		return;
	}
	/* Full. The datagram still goes out; only the reply path is lost, which
	 * is the same outcome as a NAT that has run out of table. */
}

static bool local_port_taken(const tc_udp_mux *m, uint16_t port)
{
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		if (m->bindings[i].used && m->bindings[i].local_port == port)
			return true;
	}
	for (size_t i = 0; i < m->num_listeners; i++) {
		if (m->listeners[i] == port)
			return true;
	}
	return false;
}

int tc_udp_mux_bind(tc_udp_mux *m, uint16_t remote_port, uint64_t now_ms,
                    uint16_t *out_local_port)
{
	if (m == NULL || remote_port == 0 || out_local_port == NULL)
		return TC_ERR_INVAL;

	/* An existing binding is reused rather than replaced: a sequence of
	 * requests to one service should share a source port, both because that
	 * is what a socket does and because a new port each time would exhaust
	 * the range in a few thousand queries. */
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		if (m->bindings[i].used && !m->bindings[i].has_remote_ip &&
		    m->bindings[i].remote_port == remote_port) {
			touch(&m->bindings[i], now_ms);
			*out_local_port = m->bindings[i].local_port;
			return TC_OK;
		}
	}

	binding *slot = NULL;
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		if (!m->bindings[i].used) {
			slot = &m->bindings[i];
			break;
		}
	}
	if (slot == NULL)
		return TC_ERR_TOOMANY;

	/* Walk the ephemeral range once. Failing rather than reusing a port that
	 * is already bound keeps one flow's replies out of another's queue. */
	uint32_t span = TC_UDP_EPHEMERAL_HI - TC_UDP_EPHEMERAL_LO + 1;
	uint16_t port = 0;
	for (uint32_t tries = 0; tries < span; tries++) {
		uint16_t cand = m->next_ephemeral;
		m->next_ephemeral = (cand >= TC_UDP_EPHEMERAL_HI)
		                        ? (uint16_t)TC_UDP_EPHEMERAL_LO
		                        : (uint16_t)(cand + 1);
		if (!local_port_taken(m, cand)) {
			port = cand;
			break;
		}
	}
	if (port == 0)
		return TC_ERR_TOOMANY;

	slot->used = true;
	slot->local_port = port;
	slot->remote_port = remote_port;
	slot->last_used_ms = now_ms;
	*out_local_port = port;
	return TC_OK;
}

void tc_udp_mux_tick(tc_udp_mux *m, uint64_t now_ms)
{
	if (m == NULL)
		return;
	for (size_t i = 0; i < TC_UDPMUX_MAX_BINDINGS; i++) {
		binding *b = &m->bindings[i];
		if (!b->used)
			continue;
		if (now_ms >= b->last_used_ms + TC_UDPMUX_BINDING_IDLE_MS) {
			memset(b, 0, sizeof *b);
			m->stats.bindings_expired++;
		}
	}
}

/* ---- sending ----------------------------------------------------------- */

void tc_udp_mux_set_exit_node(tc_udp_mux *m, bool on)
{
	if (m != NULL)
		m->exit_node = on;
}

/* send_one builds and transmits one datagram to an explicit destination. */
static int send_one(tc_udp_mux *m, uint16_t local_port, uint16_t remote_port,
                    const uint8_t dst_ip[TC_IPV6_ADDR_LEN], const void *data,
                    size_t len, uint64_t now_ms)
{
	if (m == NULL || (data == NULL && len > 0))
		return TC_ERR_INVAL;
	if (local_port == 0 || remote_port == 0)
		return TC_ERR_INVAL;
	if (len > TC_UDP_MAX_DGRAM)
		return TC_ERR_TOOMANY;

	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN + TC_UDP_MAX_DGRAM];
	size_t udp_len = TC_UDP_HEADER_LEN + len;

	memset(pkt, 0, TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN);
	pkt[0] = 0x60; /* version 6, traffic class 0 */
	wr16(pkt + 4, (uint16_t)udp_len);
	pkt[6] = 17; /* next header: UDP */
	pkt[7] = 64; /* hop limit */
	memcpy(pkt + 8, m->local_ip, TC_IPV6_ADDR_LEN);
	memcpy(pkt + 24, dst_ip, TC_IPV6_ADDR_LEN);

	uint8_t *uh = pkt + TC_IPV6_HEADER_LEN;
	wr16(uh + 0, local_port);
	wr16(uh + 2, remote_port);
	wr16(uh + 4, (uint16_t)udp_len);
	wr16(uh + 6, 0);
	if (len != 0)
		memcpy(uh + TC_UDP_HEADER_LEN, data, len);

	uint16_t ck = udp_checksum(m->local_ip, dst_ip, uh, udp_len);
	/* Zero means "no checksum", which IPv6 does not allow. A computed zero
	 * is therefore sent as 0xffff, which is the same value in ones-complement
	 * arithmetic and so verifies identically. */
	if (ck == 0)
		ck = 0xffff;
	wr16(uh + 6, ck);

	/* Recorded on every send, so a flow that is talking does not expire
	 * underneath itself -- and so a reply from somewhere beyond the peer has
	 * something to match against. */
	remember(m, local_port, remote_port,
	         (memcmp(dst_ip, m->remote_ip, TC_IPV6_ADDR_LEN) == 0) ? NULL
	                                                              : dst_ip,
	         now_ms);

	m->stats.dgrams_sent++;
	m->stats.bytes_sent += len;
	return m->out(m->out_ctx, pkt, TC_IPV6_HEADER_LEN + udp_len);
}

int tc_udp_mux_send(tc_udp_mux *m, uint16_t local_port, uint16_t remote_port,
                    const void *data, size_t len, uint64_t now_ms)
{
	if (m == NULL)
		return TC_ERR_INVAL;
	return send_one(m, local_port, remote_port, m->remote_ip, data, len,
	                now_ms);
}

int tc_udp_mux_send_to(tc_udp_mux *m, uint16_t local_port,
                       const tc_endpoint *dst, const void *data, size_t len,
                       uint64_t now_ms)
{
	if (m == NULL || dst == NULL || dst->ip_len != 16)
		return TC_ERR_INVAL;
	return send_one(m, local_port, dst->port, dst->ip, data, len, now_ms);
}

int tc_udp_mux_send_as(tc_udp_mux *m, const tc_endpoint *src,
                       uint16_t dst_port, const void *data, size_t len,
                       uint64_t now_ms)
{
	if (m == NULL || src == NULL || src->ip_len != 16 || dst_port == 0)
		return TC_ERR_INVAL;
	if (src->port == 0)
		return TC_ERR_INVAL;
	if (len > TC_UDP_MAX_DGRAM)
		return TC_ERR_TOOMANY;

	/* Built by hand rather than through send_one, because this is the one
	 * path where the source is not us. */
	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN + TC_UDP_MAX_DGRAM];
	size_t udp_len = TC_UDP_HEADER_LEN + len;

	memset(pkt, 0, TC_IPV6_HEADER_LEN + TC_UDP_HEADER_LEN);
	pkt[0] = 0x60;
	wr16(pkt + 4, (uint16_t)udp_len);
	pkt[6] = 17;
	pkt[7] = 64;
	memcpy(pkt + 8, src->ip, TC_IPV6_ADDR_LEN);
	memcpy(pkt + 24, m->remote_ip, TC_IPV6_ADDR_LEN);

	uint8_t *uh = pkt + TC_IPV6_HEADER_LEN;
	wr16(uh + 0, src->port);
	wr16(uh + 2, dst_port);
	wr16(uh + 4, (uint16_t)udp_len);
	wr16(uh + 6, 0);
	if (len > 0)
		memcpy(uh + TC_UDP_HEADER_LEN, data, len);

	uint16_t ck = udp_checksum(src->ip, m->remote_ip, uh, udp_len);
	if (ck == 0)
		ck = 0xffff;
	wr16(uh + 6, ck);

	(void)now_ms;
	m->stats.dgrams_sent++;
	m->stats.bytes_sent += len;
	return m->out(m->out_ctx, pkt, TC_IPV6_HEADER_LEN + udp_len);
}

/* ---- receiving --------------------------------------------------------- */

bool tc_udp_mux_is_udp(const uint8_t *pkt, size_t len)
{
	if (pkt == NULL || len < TC_IPV6_HEADER_LEN)
		return false;
	if ((pkt[0] >> 4) != 6)
		return false;
	return pkt[6] == 17;
}

int tc_udp_mux_input(tc_udp_mux *m, const uint8_t *pkt, size_t len,
                     uint64_t now_ms)
{
	if (m == NULL || pkt == NULL)
		return TC_ERR_INVAL;

	if (!tc_udp_mux_is_udp(pkt, len)) {
		m->stats.dropped_not_udp++;
		return TC_ERR_INVAL;
	}

	/* Everything reaching here arrived over an authenticated WireGuard
	 * session with exactly one peer, so the addresses are flow identifiers
	 * rather than credentials. What they decide is what a datagram *means*.
	 *
	 * From the peer to us is the ordinary case. From the peer to somewhere
	 * else means it is asking us to forward, which only an exit node does.
	 * From somewhere else to us is the answer to something we forwarded
	 * through the peer -- and that is only believed if a flow we opened is
	 * waiting for it. */
	const uint8_t *src_ip = pkt + 8;
	bool from_peer = memcmp(src_ip, m->remote_ip, TC_IPV6_ADDR_LEN) == 0;
	bool to_us = memcmp(pkt + 24, m->local_ip, TC_IPV6_ADDR_LEN) == 0;
	if (!to_us && !(from_peer && m->exit_node)) {
		m->stats.dropped_malformed++;
		return TC_ERR_INVAL;
	}

	size_t payload_len = rd16(pkt + 4);
	if (payload_len < TC_UDP_HEADER_LEN ||
	    len < TC_IPV6_HEADER_LEN + payload_len) {
		/* The IPv6 payload length is the authority; trailing bytes beyond it
		 * are not part of the packet and are ignored, but a length claiming
		 * more than arrived is a truncated packet. */
		m->stats.dropped_malformed++;
		return TC_ERR_INVAL;
	}

	const uint8_t *uh = pkt + TC_IPV6_HEADER_LEN;
	size_t udp_len = rd16(uh + 4);
	if (udp_len != payload_len || udp_len < TC_UDP_HEADER_LEN) {
		/* The UDP length must agree with the IP payload length. Two lengths
		 * that disagree are how a parser gets talked into reading past the
		 * data it was given. */
		m->stats.dropped_malformed++;
		return TC_ERR_INVAL;
	}

	uint16_t got_ck = rd16(uh + 6);
	if (got_ck == 0) {
		/* Legal over IPv4, never over IPv6: RFC 8200 section 8.1. */
		m->stats.dropped_checksum++;
		return TC_ERR_INVAL;
	}
	/* Verifying with the field in place yields 0 when it is right, which
	 * avoids having to zero a copy of the datagram first. */
	if (udp_checksum(pkt + 8, pkt + 24, uh, udp_len) != 0) {
		m->stats.dropped_checksum++;
		return TC_ERR_INVAL;
	}

	uint16_t src_port = rd16(uh + 0);
	uint16_t dst_port = rd16(uh + 2);
	if (src_port == 0 || dst_port == 0) {
		m->stats.dropped_malformed++;
		return TC_ERR_INVAL;
	}

	/* Either something is listening on the port, or it is the reply to a
	 * flow we started. A datagram matching neither is unsolicited traffic on
	 * a point-to-point tunnel and is dropped without an answer -- an ICMP
	 * port-unreachable would make this a reflector. */
	/* A datagram addressed beyond us needs no listener: the port belongs to
	 * the destination the peer named, not to anything of ours. That is what
	 * being an exit node means, and why it is off by default. */
	binding *b = NULL;
	if (to_us) {
		b = find_binding(m, dst_port, src_port, from_peer ? NULL : src_ip);
		/* A foreign source has to match a flow we opened. A listener is not
		 * enough: it would mean anything the peer cares to spoof a source
		 * for could be delivered as though we had asked for it. */
		if (b == NULL && (!from_peer || !listening(m, dst_port))) {
			m->stats.dropped_no_listener++;
			return TC_ERR_INVAL;
		}
	}
	touch(b, now_ms);

	size_t data_len = udp_len - TC_UDP_HEADER_LEN;
	if (data_len > TC_UDP_MAX_DGRAM) {
		m->stats.dropped_malformed++;
		return TC_ERR_INVAL;
	}

	if (m->q_count >= TC_UDPMUX_QUEUE) {
		/* What a full socket buffer does. Dropping an older datagram the
		 * caller has not read yet would lose data it was already promised. */
		m->stats.dropped_queue_full++;
		return TC_ERR_AGAIN;
	}

	queued *slot = &m->q[(m->q_head + m->q_count) % TC_UDPMUX_QUEUE];
	slot->local_port = dst_port;
	slot->remote_port = src_port;
	memset(&slot->dst, 0, sizeof slot->dst);
	if (!to_us) {
		/* Where the peer asked us to send it. */
		memcpy(slot->dst.ip, pkt + 24, TC_IPV6_ADDR_LEN);
		slot->dst.ip_len = 16;
		slot->dst.port = dst_port;
	} else if (!from_peer) {
		/* Where it came from, which for a forwarded reply is the thing the
		 * caller actually needs: one local port may have several
		 * destinations in flight and nothing else tells them apart. */
		memcpy(slot->dst.ip, src_ip, TC_IPV6_ADDR_LEN);
		slot->dst.ip_len = 16;
		slot->dst.port = src_port;
	}
	slot->len = data_len;
	if (data_len != 0)
		memcpy(slot->data, uh + TC_UDP_HEADER_LEN, data_len);
	m->q_count++;

	m->stats.dgrams_received++;
	m->stats.bytes_received += data_len;
	return TC_OK;
}

int tc_udp_mux_recv_addrs(tc_udp_mux *m, tc_udp_addrs *addrs, uint8_t *out,
                          size_t cap, size_t *out_len)
{
	if (addrs == NULL)
		return TC_ERR_INVAL;
	memset(addrs, 0, sizeof *addrs);
	if (m == NULL || m->q_count == 0)
		return (m == NULL) ? TC_ERR_INVAL : TC_ERR_AGAIN;
	addrs->dst = m->q[m->q_head].dst;
	return tc_udp_mux_recv(m, &addrs->local_port, &addrs->remote_port, out,
	                       cap, out_len);
}

int tc_udp_mux_recv(tc_udp_mux *m, uint16_t *local_port,
                    uint16_t *remote_port, uint8_t *out, size_t cap,
                    size_t *out_len)
{
	if (m == NULL || out_len == NULL)
		return TC_ERR_INVAL;
	if (m->q_count == 0)
		return TC_ERR_AGAIN;

	queued *slot = &m->q[m->q_head];
	if (slot->len > cap) {
		/* Left where it is. A caller that comes back with a bigger buffer
		 * gets the whole datagram; handing over a prefix would be handing
		 * over something that is not what was sent, with nothing in UDP to
		 * say so. */
		*out_len = slot->len;
		return TC_ERR_NOSPACE;
	}

	if (slot->len != 0 && out != NULL)
		memcpy(out, slot->data, slot->len);
	*out_len = slot->len;
	if (local_port != NULL)
		*local_port = slot->local_port;
	if (remote_port != NULL)
		*remote_port = slot->remote_port;

	m->q_head = (m->q_head + 1) % TC_UDPMUX_QUEUE;
	m->q_count--;
	return TC_OK;
}

void tc_udp_mux_get_stats(const tc_udp_mux *m, tc_udp_mux_stats *out)
{
	if (m == NULL || out == NULL)
		return;
	*out = m->stats;
}
