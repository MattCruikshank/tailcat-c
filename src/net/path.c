/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See path.h.
 */

#include "tc/path.h"

#include "tc/crypto.h"

#include <stdio.h>
#include <string.h>

/* ---- candidates -------------------------------------------------------- */

static tc_path_cand *find_cand(tc_path *p, const tc_endpoint *ep)
{
	for (size_t i = 0; i < p->num_cands; i++) {
		if (tc_endpoint_equal(&p->cands[i].ep, ep))
			return &p->cands[i];
	}
	return NULL;
}

/* worst_cand picks which candidate to evict when the table is full.
 *
 * Never the one in use, and otherwise the least useful: unproven before
 * proven, and among equals the one heard from longest ago. A peer that floods
 * us with addresses must not be able to push out the path we are running on. */
static tc_path_cand *worst_cand(tc_path *p)
{
	tc_path_cand *worst = NULL;
	for (size_t i = 0; i < p->num_cands; i++) {
		if (p->best >= 0 && (size_t)p->best == i)
			continue;
		tc_path_cand *c = &p->cands[i];
		if (worst == NULL) {
			worst = c;
			continue;
		}
		if (worst->proven != c->proven) {
			if (!c->proven)
				worst = c;
			continue;
		}
		uint64_t cw = (worst->last_recv_ms > worst->last_pong_ms)
		                  ? worst->last_recv_ms
		                  : worst->last_pong_ms;
		uint64_t cc = (c->last_recv_ms > c->last_pong_ms) ? c->last_recv_ms
		                                                  : c->last_pong_ms;
		if (cc < cw)
			worst = c;
	}
	return worst;
}

/* add_cand records an address worth probing, returning the entry for it. */
static tc_path_cand *add_cand(tc_path *p, const tc_endpoint *ep,
                              uint64_t now_ms)
{
	if (ep->ip_len == 0 || ep->port == 0)
		return NULL;

	tc_path_cand *c = find_cand(p, ep);
	if (c != NULL) {
		/* Deliberately left alone. A peer re-advertises the same address in
		 * every CallMeMaybe it sends, so treating that as a reason to resume
		 * full-rate probing would mean an address that does not exist is
		 * never actually given up on. Evidence wakes a candidate; a peer
		 * repeating itself does not. See wake_cand. */
		return c;
	}

	if (p->num_cands < TC_PATH_MAX_CANDIDATES) {
		c = &p->cands[p->num_cands++];
	} else {
		c = worst_cand(p);
		if (c == NULL)
			return NULL;
		/* The index of the path in use must survive an eviction elsewhere in
		 * the table, so entries are replaced in place and never compacted. */
	}

	memset(c, 0, sizeof *c);
	c->ep = *ep;
	c->rtt_ms = -1;
	(void)now_ms;
	return c;
}

/* wake_cand resumes probing an address we had set aside, because something
 * has actually arrived from it. That is evidence the address exists and
 * something is listening, which is more than any advertisement can be. */
static void wake_cand(tc_path_cand *c)
{
	c->sleeping = false;
	c->dead_rounds = 0;
	c->wake_at_ms = 0;
	c->first_probe_ms = 0;
}

/* ---- sending ----------------------------------------------------------- */

static int seal_and_send_udp(tc_path *p, const tc_endpoint *dst,
                             const tc_disco_msg *m)
{
	uint8_t pkt[1024];
	size_t n = 0;
	int rc = tc_disco_seal(pkt, sizeof pkt, &n, m, p->our_disco_pub,
	                       p->our_disco_priv, p->peer_disco_pub);
	if (rc != TC_OK)
		return rc;
	if (p->udp == NULL)
		return TC_ERR_INVAL;
	return p->udp(p->ctx, dst, pkt, n);
}

static int send_ping(tc_path *p, tc_path_cand *c, uint64_t now_ms)
{
	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PING;
	/* Fresh per probe. Reusing one would let a Pong for an old probe be
	 * counted as the answer to a new one, and a path that stopped working
	 * would keep looking alive on the strength of a reply from before it
	 * did. */
	if (tc_random_bytes(m.ping.txid, TC_DISCO_TXID_LEN) != TC_OK)
		return TC_ERR_INVAL;

	memcpy(c->txid, m.ping.txid, TC_DISCO_TXID_LEN);
	c->probe_outstanding = true;
	c->probe_sent_ms = now_ms;
	if (c->first_probe_ms == 0)
		c->first_probe_ms = now_ms;

	p->stats.pings_sent++;
	return seal_and_send_udp(p, &c->ep, &m);
}

static int send_pong(tc_path *p, const tc_endpoint *dst,
                     const uint8_t txid[TC_DISCO_TXID_LEN],
                     const tc_endpoint *src)
{
	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	memcpy(m.pong.txid, txid, TC_DISCO_TXID_LEN);
	/* The address the Ping appeared to come from. This is how a peer behind
	 * NAT learns what the world sees it as without asking a STUN server, and
	 * it is why a Pong is worth more than an acknowledgement. */
	m.pong.src = *src;
	p->stats.pongs_sent++;
	return seal_and_send_udp(p, dst, &m);
}

static int send_call_me_maybe(tc_path *p, uint64_t now_ms)
{
	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_CALL_ME_MAYBE;

	size_t n = 0;
	for (size_t i = 0; i < p->num_local && n < TC_DISCO_MAX_ENDPOINTS; i++)
		m.call_me_maybe.eps[n++] = p->local[i];

	/* The address the peer says it sees us at goes last and only if it is
	 * not already there. It is the one we could not have worked out alone. */
	if (p->has_seen_by_peer && n < TC_DISCO_MAX_ENDPOINTS) {
		bool dup = false;
		for (size_t i = 0; i < n; i++) {
			if (tc_endpoint_equal(&m.call_me_maybe.eps[i], &p->seen_by_peer))
				dup = true;
		}
		if (!dup)
			m.call_me_maybe.eps[n++] = p->seen_by_peer;
	}
	m.call_me_maybe.num = n;

	uint8_t pkt[1024];
	size_t len = 0;
	int rc = tc_disco_seal(pkt, sizeof pkt, &len, &m, p->our_disco_pub,
	                       p->our_disco_priv, p->peer_disco_pub);
	if (rc != TC_OK)
		return rc;
	if (p->relay == NULL)
		return TC_ERR_INVAL;

	p->stats.call_me_maybes_sent++;
	(void)now_ms;
	return p->relay(p->ctx, pkt, len);
}

/* ---- setup ------------------------------------------------------------- */

int tc_path_init(tc_path *p, const uint8_t our_disco_priv[32],
                 const uint8_t our_disco_pub[32],
                 const uint8_t peer_disco_pub[32], tc_path_udp_fn udp,
                 tc_path_relay_fn relay, void *ctx)
{
	if (p == NULL || our_disco_priv == NULL || our_disco_pub == NULL ||
	    peer_disco_pub == NULL)
		return TC_ERR_INVAL;

	memset(p, 0, sizeof *p);
	memcpy(p->our_disco_priv, our_disco_priv, 32);
	memcpy(p->our_disco_pub, our_disco_pub, 32);
	memcpy(p->peer_disco_pub, peer_disco_pub, 32);
	p->udp = udp;
	p->relay = relay;
	p->ctx = ctx;
	p->best = -1; /* the relay, until something is proven */
	return TC_OK;
}

int tc_path_set_local(tc_path *p, const tc_endpoint *eps, size_t n)
{
	if (p == NULL || (eps == NULL && n > 0))
		return TC_ERR_INVAL;

	p->num_local = 0;
	for (size_t i = 0; i < n && p->num_local < TC_PATH_MAX_LOCAL; i++) {
		/* Filtered here rather than at the far end: every address a peer
		 * could not reach is a probe it wastes, and loopback in particular
		 * would have it probing itself. */
		if (!tc_endpoint_is_candidate(&eps[i]))
			continue;
		bool dup = false;
		for (size_t j = 0; j < p->num_local; j++) {
			if (tc_endpoint_equal(&p->local[j], &eps[i]))
				dup = true;
		}
		if (!dup)
			p->local[p->num_local++] = eps[i];
	}
	return TC_OK;
}

int tc_path_start(tc_path *p, uint64_t now_ms)
{
	if (p == NULL)
		return TC_ERR_INVAL;
	p->next_cmm_ms = now_ms + TC_PATH_CMM_MS;
	return send_call_me_maybe(p, now_ms);
}

/* ---- receiving --------------------------------------------------------- */

static void note_pong(tc_path *p, tc_path_cand *c, const tc_disco_msg *m,
                      uint64_t now_ms)
{
	int rtt = (now_ms > c->probe_sent_ms) ? (int)(now_ms - c->probe_sent_ms)
	                                      : 0;
	c->probe_outstanding = false;
	c->last_pong_ms = now_ms;
	c->last_recv_ms = now_ms;
	c->dead_rounds = 0;
	c->wake_at_ms = 0;
	c->sleeping = false;
	c->rtt_ms = rtt;
	c->proven = true;
	p->stats.pongs_received++;

	/* The peer tells us where our Ping appeared to come from. Worth keeping
	 * even when we already have a STUN answer: this one was observed on the
	 * path actually in use, whereas STUN's was observed towards a relay. */
	if (m->pong.src.ip_len != 0 && tc_endpoint_is_candidate(&m->pong.src)) {
		p->seen_by_peer = m->pong.src;
		p->has_seen_by_peer = true;
	}
}

int tc_path_input_disco(tc_path *p, const tc_endpoint *src,
                        const uint8_t *pkt, size_t len, uint64_t now_ms)
{
	if (p == NULL || src == NULL || pkt == NULL)
		return TC_ERR_INVAL;
	if (!tc_disco_looks_like(pkt, len))
		return TC_ERR_INVAL;

	tc_disco_msg m;
	int rc = tc_disco_open(&m, pkt, len, p->our_disco_priv, p->peer_disco_pub);
	if (rc != TC_OK) {
		/* Sealed to someone else, from a key that is not our peer's, or
		 * simply corrupt. It is disco-shaped but not ours, and a caller must
		 * not go on to treat it as tunnel traffic either -- so it is
		 * consumed and dropped. */
		p->stats.discarded++;
		return TC_OK;
	}

	switch (m.type) {
	case TC_DISCO_PING: {
		p->stats.pings_received++;
		/* An address we have never heard of is the other side's hole
		 * punching arriving before its CallMeMaybe did, or from a NAT that
		 * rewrote what the peer thought its address was. Either way it is
		 * the most valuable kind of candidate there is: something has
		 * already come through it. */
		tc_path_cand *c = add_cand(p, src, now_ms);
		if (c != NULL) {
			c->last_recv_ms = now_ms;
			wake_cand(c);
		}

		/* Answered to src, not to anything the packet claims about itself.
		 * A reply to a claimed address would be a reply the peer cannot
		 * receive, and would make us a reflector for anyone who can forge
		 * one. */
		return send_pong(p, src, m.ping.txid, src);
	}

	case TC_DISCO_PONG: {
		tc_path_cand *c = find_cand(p, src);
		if (c == NULL || !c->probe_outstanding) {
			p->stats.discarded++;
			return TC_OK;
		}
		/* The transaction ID must be the one we sent to this address. A peer
		 * holding the disco key could otherwise answer a probe we never made
		 * and set the round trip of a path it prefers. */
		if (!tc_ct_equal(c->txid, m.pong.txid, TC_DISCO_TXID_LEN)) {
			p->stats.discarded++;
			return TC_OK;
		}
		note_pong(p, c, &m, now_ms);
		return TC_OK;
	}

	case TC_DISCO_CALL_ME_MAYBE:
		/* Over UDP this says nothing new -- we can already reach the sender,
		 * since the packet arrived. Accept the addresses anyway; they may
		 * include a better one than the path it came in on. */
		p->stats.call_me_maybes_received++;
		for (size_t i = 0; i < m.call_me_maybe.num; i++)
			(void)add_cand(p, &m.call_me_maybe.eps[i], now_ms);
		return TC_OK;

	default:
		p->stats.discarded++;
		return TC_OK;
	}
}

int tc_path_input_relay(tc_path *p, const uint8_t *pkt, size_t len,
                        uint64_t now_ms)
{
	if (p == NULL || pkt == NULL)
		return TC_ERR_INVAL;
	if (!tc_disco_looks_like(pkt, len))
		return TC_ERR_INVAL;

	tc_disco_msg m;
	if (tc_disco_open(&m, pkt, len, p->our_disco_priv, p->peer_disco_pub) !=
	    TC_OK) {
		p->stats.discarded++;
		return TC_OK;
	}

	/* Only CallMeMaybe means anything here. A Ping or Pong that arrived
	 * through the relay proves nothing about any direct path -- the relay
	 * carried it -- and treating one as proof is how a session ends up
	 * addressed to somewhere nothing is listening. */
	if (m.type != TC_DISCO_CALL_ME_MAYBE) {
		p->stats.discarded++;
		return TC_OK;
	}

	p->stats.call_me_maybes_received++;
	for (size_t i = 0; i < m.call_me_maybe.num; i++)
		(void)add_cand(p, &m.call_me_maybe.eps[i], now_ms);

	/* Probe at once rather than waiting for the next tick. Both sides do
	 * this on receipt, so the two bursts cross in the middle and each opens
	 * the hole the other needs. */
	for (size_t i = 0; i < p->num_cands; i++) {
		tc_path_cand *c = &p->cands[i];
		if (!c->sleeping && !c->probe_outstanding)
			(void)send_ping(p, c, now_ms);
	}
	return TC_OK;
}

void tc_path_note_recv(tc_path *p, const tc_endpoint *src, uint64_t now_ms)
{
	if (p == NULL || src == NULL)
		return;
	tc_path_cand *c = find_cand(p, src);
	if (c == NULL) {
		/* Tunnel traffic from an address we have no candidate for. It
		 * authenticated as WireGuard to get here, so the peer really is at
		 * that address; it is worth probing, but not worth trusting until it
		 * answers one. */
		c = add_cand(p, src, now_ms);
		if (c == NULL)
			return;
	}
	c->last_recv_ms = now_ms;
	wake_cand(c);
}

/* ---- choosing ---------------------------------------------------------- */

/* alive reports whether a candidate has shown itself to work recently enough
 * to keep sending into. */
static bool alive(const tc_path_cand *c, uint64_t now_ms)
{
	if (!c->proven)
		return false;
	uint64_t last = (c->last_recv_ms > c->last_pong_ms) ? c->last_recv_ms
	                                                    : c->last_pong_ms;
	return now_ms < last + TC_PATH_TRUST_MS;
}

static void rechoose(tc_path *p, uint64_t now_ms)
{
	int current = p->best;

	/* A path in use that is still alive keeps the job unless something is
	 * clearly better. Moving a working session for a millisecond is churn,
	 * and churn on the data path is how packets get lost. */
	if (current >= 0 && alive(&p->cands[current], now_ms)) {
		int best_other = -1, best_rtt = 0;
		for (size_t i = 0; i < p->num_cands; i++) {
			if ((int)i == current || !alive(&p->cands[i], now_ms))
				continue;
			if (best_other < 0 || p->cands[i].rtt_ms < best_rtt) {
				best_other = (int)i;
				best_rtt = p->cands[i].rtt_ms;
			}
		}
		if (best_other >= 0 &&
		    best_rtt + TC_PATH_GOOD_ENOUGH_MS < p->cands[current].rtt_ms) {
			p->best = best_other;
			p->best_since_ms = now_ms;
			p->stats.switches++;
		}
		return;
	}

	int best = -1, best_rtt = 0;
	for (size_t i = 0; i < p->num_cands; i++) {
		if (!alive(&p->cands[i], now_ms))
			continue;
		if (best < 0 || p->cands[i].rtt_ms < best_rtt) {
			best = (int)i;
			best_rtt = p->cands[i].rtt_ms;
		}
	}

	if (best == current)
		return;
	if (best < 0)
		p->stats.downgrades++;
	else if (current < 0)
		p->stats.upgrades++;
	else
		p->stats.switches++;
	p->best = best;
	p->best_since_ms = now_ms;
}

tc_path_kind tc_path_best(const tc_path *p, tc_endpoint *out, uint64_t now_ms)
{
	if (p == NULL || p->best < 0)
		return TC_PATH_RELAY;
	const tc_path_cand *c = &p->cands[p->best];
	/* Checked again on the way out rather than trusting what the last tick
	 * decided: a caller may ask between ticks, and the whole point of the
	 * trust window is that it expires on time. */
	if (!alive(c, now_ms))
		return TC_PATH_RELAY;
	if (out != NULL)
		*out = c->ep;
	return TC_PATH_DIRECT;
}

bool tc_path_knows(const tc_path *p, const tc_endpoint *ep)
{
	if (p == NULL || ep == NULL)
		return false;
	for (size_t i = 0; i < p->num_cands; i++) {
		if (tc_endpoint_equal(&p->cands[i].ep, ep))
			return true;
	}
	return false;
}

/* ---- the schedule ------------------------------------------------------ */

/* probe_due reports when this candidate should next be probed, or UINT64_MAX
 * for never. */
static uint64_t probe_due(const tc_path *p, const tc_path_cand *c,
                          uint64_t now_ms)
{
	if (c->sleeping)
		return UINT64_MAX;

	bool in_use = (p->best >= 0 && &p->cands[p->best] == c);

	if (c->proven) {
		/* A path carrying traffic needs no probing; the traffic is the
		 * proof. Probe only once it has gone quiet, and only if we would
		 * care -- an idle candidate we are not using can wait. */
		uint64_t last = (c->last_recv_ms > c->last_pong_ms) ? c->last_recv_ms
		                                                    : c->last_pong_ms;
		if (!in_use && now_ms >= last + TC_PATH_TRUST_MS)
			return UINT64_MAX; /* stale and unused: let it go quiet */
		return last + TC_PATH_HEARTBEAT_MS;
	}

	if (c->probe_outstanding)
		return c->probe_sent_ms + TC_PATH_PROBE_MS;
	return (c->first_probe_ms == 0) ? now_ms : c->first_probe_ms;
}

int tc_path_tick(tc_path *p, uint64_t now_ms)
{
	if (p == NULL)
		return TC_ERR_INVAL;

	for (size_t i = 0; i < p->num_cands; i++) {
		tc_path_cand *c = &p->cands[i];

		/* An unproven candidate that has been probed for long enough is set
		 * aside. It is not forgotten: another CallMeMaybe, or a Ping from
		 * it, wakes it up. Probing it forever would spend packets on an
		 * address that does not exist. */
		if (!c->proven && !c->sleeping && c->first_probe_ms != 0 &&
		    now_ms >= c->first_probe_ms + TC_PATH_PROBE_GIVEUP_MS) {
			c->sleeping = true;
			c->probe_outstanding = false;
			if (c->dead_rounds < 32)
				c->dead_rounds++;
			uint64_t back = TC_PATH_PROBE_GIVEUP_MS;
			for (unsigned k = 1; k < c->dead_rounds; k++) {
				back *= 2;
				if (back >= TC_PATH_PROBE_MAX_BACKOFF_MS)
					break;
			}
			if (back > TC_PATH_PROBE_MAX_BACKOFF_MS)
				back = TC_PATH_PROBE_MAX_BACKOFF_MS;
			c->wake_at_ms = now_ms + back;
			continue;
		}

		/* The backoff has run out: one more round of probing. An address can
		 * start working -- a peer moves, a firewall rule changes -- and the
		 * only way to find out is to try again eventually. */
		if (c->sleeping && !c->proven && now_ms >= c->wake_at_ms) {
			c->sleeping = false;
			c->first_probe_ms = 0;
			c->probe_outstanding = false;
		}

		if (probe_due(p, c, now_ms) <= now_ms)
			(void)send_ping(p, c, now_ms);
	}

	rechoose(p, now_ms);

	if (now_ms >= p->next_cmm_ms) {
		/* Offered often while there is no direct path, and occasionally once
		 * there is: our addresses change when an interface does, and a peer
		 * working from a stale list will not find us after a network
		 * change. */
		(void)send_call_me_maybe(p, now_ms);
		p->next_cmm_ms =
		    now_ms + ((p->best >= 0) ? TC_PATH_CMM_IDLE_MS : TC_PATH_CMM_MS);
	}
	return TC_OK;
}

uint64_t tc_path_next_deadline(const tc_path *p, uint64_t now_ms)
{
	if (p == NULL)
		return UINT64_MAX;
	uint64_t next = p->next_cmm_ms;
	for (size_t i = 0; i < p->num_cands; i++) {
		const tc_path_cand *c = &p->cands[i];
		uint64_t d = probe_due(p, c, now_ms);
		if (!c->proven && !c->sleeping && c->first_probe_ms != 0) {
			uint64_t giveup = c->first_probe_ms + TC_PATH_PROBE_GIVEUP_MS;
			if (giveup < d)
				d = giveup;
		}
		if (!c->proven && c->sleeping && c->wake_at_ms < d)
			d = c->wake_at_ms;
		if (d < next)
			next = d;
	}
	/* The trust window expiring is itself work: it is what moves a session
	 * back to the relay, and nothing else would wake us to do it. */
	if (p->best >= 0) {
		const tc_path_cand *c = &p->cands[p->best];
		uint64_t last = (c->last_recv_ms > c->last_pong_ms) ? c->last_recv_ms
		                                                    : c->last_pong_ms;
		uint64_t expiry = last + TC_PATH_TRUST_MS;
		if (expiry < next)
			next = expiry;
	}
	return next;
}

/* ---- reporting --------------------------------------------------------- */

int tc_path_describe(char *out, size_t cap, const tc_path *p, uint64_t now_ms)
{
	if (out == NULL || cap == 0 || p == NULL)
		return TC_ERR_INVAL;
	out[0] = '\0';

	size_t proven = 0;
	for (size_t i = 0; i < p->num_cands; i++) {
		if (p->cands[i].proven)
			proven++;
	}

	tc_endpoint ep;
	int n;
	if (tc_path_best(p, &ep, now_ms) == TC_PATH_DIRECT) {
		char s[80];
		if (tc_endpoint_format(s, sizeof s, &ep) != TC_OK)
			return TC_ERR_INVAL;
		n = snprintf(out, cap, "direct to %s, %dms (%zu of %zu candidates "
		                       "proven)",
		             s, p->cands[p->best].rtt_ms, proven, p->num_cands);
	} else {
		n = snprintf(out, cap,
		             "via the relay (%zu of %zu candidates proven)", proven,
		             p->num_cands);
	}
	return (n > 0 && (size_t)n < cap) ? TC_OK : TC_ERR_NOSPACE;
}

void tc_path_get_stats(const tc_path *p, tc_path_stats *out)
{
	if (p == NULL || out == NULL)
		return;
	*out = p->stats;
}
