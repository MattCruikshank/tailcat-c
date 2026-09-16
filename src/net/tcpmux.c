/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See tcpmux.h. Dispatch only: the TCP state machine lives in tcp.c and is
 * not touched here.
 *
 * The table is a flat array scanned linearly. That is the right shape at this
 * size for two reasons. A connection costs around 146 KB of buffers, so the
 * table can never grow to where hashing would pay -- sixty-four of them is
 * already nine megabytes. And a scan has no bucket arithmetic, no tombstones
 * and no resize, which is a meaningful saving in a file whose entire job is
 * to route attacker-influenced packets to the right place.
 */

#include "tc/tcpmux.h"

#include "tc/crypto.h"

#include <stdlib.h>
#include <string.h>

struct tc_tcp_mux {
	uint8_t local_ip[TC_IPV6_ADDR_LEN];
	uint8_t remote_ip[TC_IPV6_ADDR_LEN];
	tc_tcp_output_fn out;
	void *out_ctx;

	tc_tcp_conn *conns[TC_TCP_MAX_CONNS];
	size_t num_conns;

	uint16_t listeners[TC_TCP_MAX_LISTENERS];
	size_t num_listeners;

	/* Accepted but not yet collected, oldest first. These are also in
	 * conns[]: the queue holds borrowed pointers, not ownership. */
	tc_tcp_conn *backlog[TC_TCP_BACKLOG];
	size_t num_pending;

	/* Where the next ephemeral port search starts. Randomised at
	 * construction for the same reason the initial sequence number is: a
	 * predictable port pair is half of what blind injection needs. */
	uint16_t next_port;

	tc_tcp_mux_stats stats;
};

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* ---- table ----------------------------------------------------------- */

static tc_tcp_conn *find_conn(const tc_tcp_mux *m, uint16_t local_port,
                              uint16_t remote_port)
{
	for (size_t i = 0; i < m->num_conns; i++) {
		if (tc_tcp_local_port(m->conns[i]) == local_port &&
		    tc_tcp_remote_port(m->conns[i]) == remote_port)
			return m->conns[i];
	}
	return NULL;
}

static bool local_port_in_use(const tc_tcp_mux *m, uint16_t port)
{
	for (size_t i = 0; i < m->num_conns; i++) {
		if (tc_tcp_local_port(m->conns[i]) == port)
			return true;
	}
	return false;
}

/* drop_at removes one connection, freeing it and unqueueing it if it was
 * still waiting to be accepted. */
static void drop_at(tc_tcp_mux *m, size_t idx)
{
	tc_tcp_conn *c = m->conns[idx];

	for (size_t i = 0; i < m->num_pending; i++) {
		if (m->backlog[i] == c) {
			memmove(&m->backlog[i], &m->backlog[i + 1],
			        (m->num_pending - i - 1) * sizeof m->backlog[0]);
			m->num_pending--;
			break;
		}
	}

	/* The order of conns[] is unspecified, so the last entry fills the hole
	 * rather than shifting everything down. */
	m->conns[idx] = m->conns[m->num_conns - 1];
	m->num_conns--;
	tc_tcp_free(c);
}

/* ---- lifecycle ------------------------------------------------------- */

tc_tcp_mux *tc_tcp_mux_new(const uint8_t local_ip[TC_IPV6_ADDR_LEN],
                           const uint8_t remote_ip[TC_IPV6_ADDR_LEN],
                           tc_tcp_output_fn out, void *out_ctx)
{
	if (local_ip == NULL || remote_ip == NULL || out == NULL)
		return NULL;

	tc_tcp_mux *m = (tc_tcp_mux *)calloc(1, sizeof *m);
	if (m == NULL)
		return NULL;

	memcpy(m->local_ip, local_ip, TC_IPV6_ADDR_LEN);
	memcpy(m->remote_ip, remote_ip, TC_IPV6_ADDR_LEN);
	m->out = out;
	m->out_ctx = out_ctx;

	uint16_t seed = 0;
	if (tc_random_bytes(&seed, sizeof seed) != TC_OK)
		seed = 0;
	m->next_port = (uint16_t)(TC_TCP_EPHEMERAL_LO +
	                          seed % (TC_TCP_EPHEMERAL_HI -
	                                  TC_TCP_EPHEMERAL_LO + 1u));
	return m;
}

void tc_tcp_mux_free(tc_tcp_mux *m)
{
	if (m == NULL)
		return;
	for (size_t i = 0; i < m->num_conns; i++)
		tc_tcp_free(m->conns[i]);
	free(m);
}

/* ---- listeners ------------------------------------------------------- */

bool tc_tcp_mux_is_listening(const tc_tcp_mux *m, uint16_t port)
{
	if (m == NULL)
		return false;
	for (size_t i = 0; i < m->num_listeners; i++) {
		if (m->listeners[i] == port)
			return true;
	}
	return false;
}

int tc_tcp_mux_listen(tc_tcp_mux *m, uint16_t port)
{
	if (m == NULL || port == 0)
		return TC_ERR_INVAL;
	if (tc_tcp_mux_is_listening(m, port))
		return TC_ERR_EXIST;
	if (m->num_listeners >= TC_TCP_MAX_LISTENERS)
		return TC_ERR_TOOMANY;
	m->listeners[m->num_listeners++] = port;
	return TC_OK;
}

int tc_tcp_mux_unlisten(tc_tcp_mux *m, uint16_t port)
{
	if (m == NULL)
		return TC_ERR_INVAL;
	for (size_t i = 0; i < m->num_listeners; i++) {
		if (m->listeners[i] != port)
			continue;
		memmove(&m->listeners[i], &m->listeners[i + 1],
		        (m->num_listeners - i - 1) * sizeof m->listeners[0]);
		m->num_listeners--;
		return TC_OK;
	}
	return TC_ERR_INVAL;
}

/* ---- opening --------------------------------------------------------- */

int tc_tcp_mux_connect_from(tc_tcp_mux *m, uint16_t local_port,
                            uint16_t remote_port, uint64_t now_ms,
                            tc_tcp_conn **out)
{
	if (m == NULL || out == NULL || local_port == 0 || remote_port == 0)
		return TC_ERR_INVAL;
	*out = NULL;
	if (m->num_conns >= TC_TCP_MAX_CONNS)
		return TC_ERR_TOOMANY;
	if (find_conn(m, local_port, remote_port) != NULL)
		return TC_ERR_EXIST;

	tc_tcp_conn *c = tc_tcp_new(m->local_ip, m->remote_ip, m->out, m->out_ctx);
	if (c == NULL)
		return TC_ERR_NOSPACE;

	/* Registered before the SYN goes out: the output callback may deliver it
	 * synchronously and the reply could come back inside this call. */
	m->conns[m->num_conns++] = c;

	int rc = tc_tcp_connect(c, local_port, remote_port, now_ms);
	if (rc != TC_OK) {
		drop_at(m, m->num_conns - 1);
		return rc;
	}

	m->stats.dialled++;
	*out = c;
	return TC_OK;
}

int tc_tcp_mux_connect(tc_tcp_mux *m, uint16_t remote_port, uint64_t now_ms,
                       tc_tcp_conn **out)
{
	if (m == NULL || out == NULL)
		return TC_ERR_INVAL;
	*out = NULL;

	const uint32_t span = TC_TCP_EPHEMERAL_HI - TC_TCP_EPHEMERAL_LO + 1u;
	for (uint32_t tries = 0; tries < span; tries++) {
		uint16_t port = m->next_port;
		m->next_port = (uint16_t)(port >= TC_TCP_EPHEMERAL_HI
		                              ? TC_TCP_EPHEMERAL_LO
		                              : (unsigned)port + 1u);
		/* A port still held by a connection in TIME_WAIT is not free: its
		 * job is to absorb stragglers addressed to that exact pair. */
		if (local_port_in_use(m, port) || tc_tcp_mux_is_listening(m, port))
			continue;
		return tc_tcp_mux_connect_from(m, port, remote_port, now_ms, out);
	}
	return TC_ERR_TOOMANY;
}

/* ---- input ----------------------------------------------------------- */

/* accept_syn opens a connection for a SYN that arrived on a listening port. */
static void accept_syn(tc_tcp_mux *m, uint16_t local_port, const uint8_t *pkt,
                       size_t len, uint64_t now_ms)
{
	if (m->num_conns >= TC_TCP_MAX_CONNS ||
	    m->num_pending >= TC_TCP_BACKLOG) {
		/* Refusing outright is kinder than dropping: the peer finds out now
		 * instead of retransmitting until it times out. */
		m->stats.rejected_full++;
		(void)tc_tcp_reject(pkt, len, m->out, m->out_ctx);
		return;
	}

	tc_tcp_conn *c = tc_tcp_new(m->local_ip, m->remote_ip, m->out, m->out_ctx);
	if (c == NULL) {
		m->stats.rejected_full++;
		(void)tc_tcp_reject(pkt, len, m->out, m->out_ctx);
		return;
	}
	if (tc_tcp_listen(c, local_port) != TC_OK) {
		tc_tcp_free(c);
		return;
	}

	m->conns[m->num_conns++] = c;
	/* tc_tcp_input in LISTEN takes the remote port from the segment, which is
	 * what makes this connection findable from here on. */
	(void)tc_tcp_input(c, pkt, len, now_ms);

	if (tc_tcp_get_state(c) == TC_TCP_CLOSED) {
		drop_at(m, m->num_conns - 1); /* it refused the segment */
		return;
	}

	m->backlog[m->num_pending++] = c;
	m->stats.accepted++;
}

int tc_tcp_mux_input(tc_tcp_mux *m, const uint8_t *ip_pkt, size_t len,
                     uint64_t now_ms)
{
	if (m == NULL || ip_pkt == NULL)
		return TC_ERR_INVAL;
	if (len < TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN)
		return TC_OK;
	if ((ip_pkt[0] >> 4) != 6 || ip_pkt[6] != 6)
		return TC_OK;

	size_t payload_total = rd16(ip_pkt + 4);
	if (payload_total < TC_TCP_HEADER_LEN ||
	    TC_IPV6_HEADER_LEN + payload_total > len)
		return TC_OK;

	/* Both addresses must match the tunnel. Checking here as well as in
	 * tc_tcp_input keeps a foreign packet from being answered with a reset
	 * that names an address we do not own. */
	if (memcmp(ip_pkt + 8, m->remote_ip, TC_IPV6_ADDR_LEN) != 0 ||
	    memcmp(ip_pkt + 24, m->local_ip, TC_IPV6_ADDR_LEN) != 0)
		return TC_OK;

	const uint8_t *th = ip_pkt + TC_IPV6_HEADER_LEN;
	uint16_t sport = rd16(th + 0);
	uint16_t dport = rd16(th + 2);
	uint8_t flags = th[13];

	enum { TH_SYN = 0x02, TH_RST = 0x04, TH_ACK = 0x10 };

	tc_tcp_conn *c = find_conn(m, dport, sport);

	/* A bare SYN for a pair held by a connection in TIME_WAIT is the peer
	 * reusing that port, not a straggler: a straggler would carry an ACK.
	 * RFC 1122 4.2.2.13 allows accepting it, and here the usual objection --
	 * that an off-path attacker could forge it -- does not apply, because
	 * every byte reaching this stack has already been authenticated by the
	 * WireGuard session that carried it. Refusing instead would make a
	 * reused port pair hang for the length of the TIME_WAIT. */
	if (c != NULL && tc_tcp_get_state(c) == TC_TCP_TIME_WAIT &&
	    (flags & TH_SYN) && !(flags & (TH_ACK | TH_RST))) {
		for (size_t i = 0; i < m->num_conns; i++) {
			if (m->conns[i] == c) {
				drop_at(m, i);
				break;
			}
		}
		c = NULL;
	}

	if (c != NULL)
		return tc_tcp_input(c, ip_pkt, len, now_ms);

	if ((flags & TH_SYN) && !(flags & (TH_ACK | TH_RST)) &&
	    tc_tcp_mux_is_listening(m, dport)) {
		accept_syn(m, dport, ip_pkt, len, now_ms);
		return TC_OK;
	}

	/* Nobody owns this pair. A reset says so; a RST needs no answer, and
	 * tc_tcp_reject declines to give one. */
	if (tc_tcp_reject(ip_pkt, len, m->out, m->out_ctx) == TC_OK)
		m->stats.rejected_port++;
	return TC_OK;
}

/* ---- accepting, driving, reaping ------------------------------------- */

tc_tcp_conn *tc_tcp_mux_accept(tc_tcp_mux *m)
{
	if (m == NULL || m->num_pending == 0)
		return NULL;
	tc_tcp_conn *c = m->backlog[0];
	memmove(&m->backlog[0], &m->backlog[1],
	        (m->num_pending - 1) * sizeof m->backlog[0]);
	m->num_pending--;
	return c;
}

size_t tc_tcp_mux_pending(const tc_tcp_mux *m)
{
	return m == NULL ? 0 : m->num_pending;
}

int tc_tcp_mux_tick(tc_tcp_mux *m, uint64_t now_ms)
{
	if (m == NULL)
		return TC_ERR_INVAL;
	/* A connection may close during its own tick but is not removed here:
	 * the caller has to be able to read what arrived before it closed. */
	for (size_t i = 0; i < m->num_conns; i++)
		(void)tc_tcp_tick(m->conns[i], now_ms);
	return TC_OK;
}

uint64_t tc_tcp_mux_next_deadline(const tc_tcp_mux *m)
{
	uint64_t best = UINT64_MAX;
	if (m == NULL)
		return best;
	for (size_t i = 0; i < m->num_conns; i++) {
		uint64_t d = tc_tcp_next_deadline(m->conns[i]);
		if (d < best)
			best = d;
	}
	return best;
}

size_t tc_tcp_mux_count(const tc_tcp_mux *m)
{
	return m == NULL ? 0 : m->num_conns;
}

tc_tcp_conn *tc_tcp_mux_at(const tc_tcp_mux *m, size_t i)
{
	if (m == NULL || i >= m->num_conns)
		return NULL;
	return m->conns[i];
}

void tc_tcp_mux_close(tc_tcp_mux *m, tc_tcp_conn *c, uint64_t now_ms)
{
	if (m == NULL || c == NULL)
		return;
	for (size_t i = 0; i < m->num_conns; i++) {
		if (m->conns[i] != c)
			continue;
		if (tc_tcp_get_state(c) != TC_TCP_CLOSED)
			tc_tcp_abort(c, now_ms);
		drop_at(m, i);
		return;
	}
}

size_t tc_tcp_mux_reap(tc_tcp_mux *m)
{
	if (m == NULL)
		return 0;
	size_t freed = 0;
	for (size_t i = 0; i < m->num_conns;) {
		if (tc_tcp_get_state(m->conns[i]) == TC_TCP_CLOSED) {
			drop_at(m, i); /* the last entry moved into i, so do not advance */
			freed++;
		} else {
			i++;
		}
	}
	m->stats.reaped += freed;
	return freed;
}

void tc_tcp_mux_get_stats(const tc_tcp_mux *m, tc_tcp_mux_stats *out)
{
	if (out == NULL)
		return;
	if (m == NULL)
		memset(out, 0, sizeof *out);
	else
		*out = m->stats;
}
