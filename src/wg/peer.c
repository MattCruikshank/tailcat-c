/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See wgpeer.h. The keypair triple and the timers around it.
 *
 * Every rule here is load-bearing in a way that only shows up after minutes
 * of running, which is why the tests drive a virtual clock through hours of
 * simulated time rather than trusting the code to look right.
 */

#include "tc/wgpeer.h"

#include "tc/crypto.h"

#include <string.h>

/* ---- small helpers --------------------------------------------------- */

static uint32_t rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static uint64_t age_of(const tc_wg_keypair *k, uint64_t now)
{
	/* The caller's clock is monotonic, but a keypair born in the same
	 * millisecond as a query must read as age zero rather than underflow. */
	return now > k->birth_ms ? now - k->birth_ms : 0;
}

static bool usable_for_send(const tc_wg_keypair *k, uint64_t now)
{
	return k->valid && k->s.established &&
	       age_of(k, now) < TC_WG_REJECT_AFTER_TIME_MS &&
	       k->s.send_counter < TC_WG_REJECT_AFTER_MESSAGES;
}

static bool usable_for_recv(const tc_wg_keypair *k, uint64_t now)
{
	return k->valid && k->s.established &&
	       age_of(k, now) < TC_WG_REJECT_AFTER_TIME_MS;
}

static void kill_keypair(tc_wg_keypair *k)
{
	tc_wg_session_clear(&k->s);
	tc_memzero_explicit(k, sizeof *k);
}

/* jitter returns 0..332 ms. WireGuard jitters handshake retries so that two
 * peers which lost each other do not resend in lockstep indefinitely. */
static uint32_t jitter(tc_wg_peer *p)
{
	uint64_t x = p->rng;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	p->rng = x;
	return (uint32_t)((x * 0x2545f4914f6cdd1dULL) >> 32) % 333u;
}

/* ---- lifecycle -------------------------------------------------------- */

int tc_wg_peer_init(tc_wg_peer *p, const tc_wg_identity *id,
                    const uint8_t remote_static[TC_WG_KEY_LEN],
                    const uint8_t psk[TC_WG_KEY_LEN], tc_wg_send_fn send,
                    void *send_ctx)
{
	if (p == NULL || id == NULL || remote_static == NULL || send == NULL)
		return TC_ERR_INVAL;

	memset(p, 0, sizeof *p);
	p->id = *id;
	memcpy(p->remote_static, remote_static, TC_WG_KEY_LEN);
	if (psk != NULL) {
		memcpy(p->psk, psk, TC_WG_KEY_LEN);
		p->has_psk = true;
	}
	p->send = send;
	p->send_ctx = send_ctx;

	if (tc_random_bytes(&p->rng, sizeof p->rng) != TC_OK || p->rng == 0)
		p->rng = 0x9e3779b97f4a7c15ull;
	return TC_OK;
}

void tc_wg_peer_clear(tc_wg_peer *p)
{
	if (p == NULL)
		return;
	kill_keypair(&p->current);
	kill_keypair(&p->previous);
	kill_keypair(&p->next);
	tc_memzero_explicit(p, sizeof *p);
}

void tc_wg_peer_force_rng(tc_wg_peer *p, uint64_t seed)
{
	if (p != NULL)
		p->rng = seed | 1u;
}

/* ---- starting a handshake --------------------------------------------- */

/* emit_initiation builds and sends a brand-new initiation, replacing whatever
 * handshake was in progress.
 *
 * It must be a new one every time, including on a retry. Resending the
 * identical bytes looks like the thrifty choice -- it saves the peer redoing
 * the expensive half against a fresh ephemeral key -- but the peer enforces
 * initiation replay protection, and a replayed timestamp is precisely what
 * that rejects. A retry of the same bytes is silently dropped, so a single
 * lost handshake packet would strand the tunnel until the attempt is
 * abandoned. wireguard-go calls CreateMessageInitiation on every send for
 * this reason. */
static int emit_initiation(tc_wg_peer *p)
{
	if (tc_wg_handshake_init(&p->hs, &p->id, p->remote_static,
	                         p->has_psk ? p->psk : NULL) != TC_OK)
		return TC_ERR_INVAL;
	if (tc_wg_create_initiation(p->hs_msg, &p->hs, &p->id, 0) != TC_OK)
		return TC_ERR_INVAL;
	(void)p->send(p->send_ctx, p->hs_msg, sizeof p->hs_msg);
	return TC_OK;
}

int tc_wg_peer_start_handshake(tc_wg_peer *p, uint64_t now_ms)
{
	if (p == NULL)
		return TC_ERR_INVAL;
	if (p->hs_active)
		return TC_OK; /* one at a time; the timer will retry it */

	int rc = emit_initiation(p);
	if (rc != TC_OK)
		return rc;

	p->hs_active = true;
	p->hs_first_ms = now_ms;
	p->hs_next_ms = now_ms + TC_WG_REKEY_TIMEOUT_MS + jitter(p);
	p->stats.handshakes_initiated++;
	return TC_OK;
}

/* maybe_rekey starts a renewal if the current session has reached the point
 * where WireGuard says it should be replaced. Called after every send, which
 * is where WireGuard checks: an idle session is allowed to age out and is
 * replaced by the handshake that the next send triggers. */
static void maybe_rekey(tc_wg_peer *p, uint64_t now)
{
	if (p->hs_active || !p->current.valid)
		return;

	uint64_t age = age_of(&p->current, now);
	uint64_t limit = p->current.s.is_initiator
	                     ? TC_WG_REKEY_AFTER_TIME_MS
	                     : TC_WG_REKEY_AFTER_TIME_ON_RECV_MS;

	if (age >= limit || p->current.s.send_counter >= TC_WG_REKEY_AFTER_MESSAGES)
		(void)tc_wg_peer_start_handshake(p, now);
}

/* ---- keypair rotation -------------------------------------------------- */

/* adopt_as_initiator installs a keypair we derived from a response we asked
 * for. The peer built that response, so it certainly holds these keys and we
 * can start sending under them immediately. */
static void adopt_as_initiator(tc_wg_peer *p, const tc_wg_session *s,
                               uint64_t now)
{
	bool replaced = p->current.valid;

	kill_keypair(&p->previous);
	if (p->next.valid) {
		/* A keypair we were offered as responder never got proven, and this
		 * one supersedes it. Keeping it as `previous` means packets already
		 * in flight under it still decrypt -- which matters more than keeping
		 * the outgoing `current`, since the peer has moved on from it. */
		p->previous = p->next;
		tc_memzero_explicit(&p->next, sizeof p->next);
		kill_keypair(&p->current);
	} else if (p->current.valid) {
		p->previous = p->current;
	}
	if (replaced)
		p->stats.rekeys++;

	memset(&p->current, 0, sizeof p->current);
	p->current.s = *s;
	p->current.birth_ms = now;
	p->current.valid = true;
	p->stats.handshakes_completed++;
}

/* adopt_as_responder parks a keypair derived from an initiation we answered.
 * Our response may never have arrived, so nothing is sent under it until a
 * data packet proves the initiator has it. */
static void adopt_as_responder(tc_wg_peer *p, const tc_wg_session *s,
                               uint64_t now)
{
	kill_keypair(&p->next);
	/* An unproven previous is worth less than the chance to keep `current`
	 * working through this handshake, so previous goes and current stays. */
	kill_keypair(&p->previous);

	memset(&p->next, 0, sizeof p->next);
	p->next.s = *s;
	p->next.birth_ms = now;
	p->next.valid = true;
	p->stats.handshakes_completed++;
}

/* promote_next is called when a data packet authenticates under `next`, which
 * is the only proof that the initiator received our response. */
static void promote_next(tc_wg_peer *p)
{
	kill_keypair(&p->previous);
	if (p->current.valid) {
		p->previous = p->current;
		p->stats.rekeys++;
	}
	p->current = p->next;
	tc_memzero_explicit(&p->next, sizeof p->next);
	p->stats.promotions++;
}

/* ---- sending ----------------------------------------------------------- */

int tc_wg_peer_send(tc_wg_peer *p, const void *pt, size_t len, uint64_t now_ms)
{
	if (p == NULL || (pt == NULL && len != 0))
		return TC_ERR_INVAL;

	if (!usable_for_send(&p->current, now_ms)) {
		(void)tc_wg_peer_start_handshake(p, now_ms);
		return TC_ERR_AGAIN;
	}

	uint8_t pkt[TC_WG_TRANSPORT_HEADER_SIZE + TC_WG_MAX_PAYLOAD +
	            TC_WG_TAG_LEN];
	size_t pkt_len = 0;
	int rc = tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &p->current.s, pt, len);
	if (rc != TC_OK)
		return rc;

	(void)p->send(p->send_ctx, pkt, pkt_len);

	/* Anything we send answers the peer, so no separate keepalive is owed. */
	p->keepalive_armed = false;

	maybe_rekey(p, now_ms);
	return TC_OK;
}

/* send_keepalive transmits an empty transport packet. */
static void send_keepalive(tc_wg_peer *p, uint64_t now)
{
	if (!usable_for_send(&p->current, now))
		return;
	uint8_t pkt[TC_WG_TRANSPORT_HEADER_SIZE + TC_WG_TAG_LEN];
	size_t pkt_len = 0;
	if (tc_wg_encrypt(pkt, sizeof pkt, &pkt_len, &p->current.s, NULL, 0) !=
	    TC_OK)
		return;
	(void)p->send(p->send_ctx, pkt, pkt_len);
	p->stats.keepalives_sent++;
	maybe_rekey(p, now);
}

/* ---- receiving --------------------------------------------------------- */

static int handle_initiation(tc_wg_peer *p, const uint8_t *msg, size_t len,
                             uint64_t now)
{
	if (len != TC_WG_INITIATION_SIZE)
		return TC_OK;

	tc_wg_handshake hs;
	if (tc_wg_handshake_init(&hs, &p->id, p->remote_static,
	                         p->has_psk ? p->psk : NULL) != TC_OK)
		return TC_OK;

	uint8_t peer_static[TC_WG_KEY_LEN];
	uint8_t ts[TC_WG_TIMESTAMP_LEN];
	if (tc_wg_consume_initiation(&hs, &p->id, msg, peer_static, ts) != TC_OK) {
		tc_memzero_explicit(&hs, sizeof hs);
		return TC_OK;
	}

	/* Initiation replay protection. TAI64N is big-endian, so an ordinary
	 * memcmp orders it; anything not strictly newer than the last one this
	 * peer sent is a replay of a message we have already answered. Without
	 * this, a recorded initiation can be used to make us burn a handshake
	 * and discard a working session at will. */
	if (p->has_last_timestamp &&
	    memcmp(ts, p->last_timestamp, TC_WG_TIMESTAMP_LEN) <= 0) {
		p->stats.rejected_replay++;
		tc_memzero_explicit(&hs, sizeof hs);
		return TC_OK;
	}

	uint8_t resp[TC_WG_RESPONSE_SIZE];
	if (tc_wg_create_response(resp, &hs, &p->id, 0) != TC_OK) {
		tc_memzero_explicit(&hs, sizeof hs);
		return TC_OK;
	}

	tc_wg_session s;
	if (tc_wg_begin_session(&s, &hs) != TC_OK) {
		tc_memzero_explicit(&hs, sizeof hs);
		return TC_OK;
	}

	/* Only record the timestamp once the whole message has been accepted,
	 * so a partly-valid one cannot advance the watermark and lock out the
	 * peer's genuine retries. */
	memcpy(p->last_timestamp, ts, TC_WG_TIMESTAMP_LEN);
	p->has_last_timestamp = true;

	(void)p->send(p->send_ctx, resp, sizeof resp);
	p->stats.handshakes_responded++;
	adopt_as_responder(p, &s, now);

	tc_memzero_explicit(&s, sizeof s);
	tc_memzero_explicit(&hs, sizeof hs);
	return TC_OK;
}

static int handle_response(tc_wg_peer *p, const uint8_t *msg, size_t len,
                           uint64_t now)
{
	if (len != TC_WG_RESPONSE_SIZE || !p->hs_active)
		return TC_OK;
	/* The response must name the index we chose, or it answers a handshake
	 * that is not ours. */
	if (rd32le(msg + 8) != p->hs.local_index)
		return TC_OK;
	if (tc_wg_consume_response(&p->hs, &p->id, msg) != TC_OK)
		return TC_OK;

	tc_wg_session s;
	if (tc_wg_begin_session(&s, &p->hs) != TC_OK)
		return TC_OK;

	p->hs_active = false;
	tc_memzero_explicit(&p->hs, sizeof p->hs);
	tc_memzero_explicit(p->hs_msg, sizeof p->hs_msg);

	adopt_as_initiator(p, &s, now);
	tc_memzero_explicit(&s, sizeof s);
	return TC_OK;
}

static int handle_transport(tc_wg_peer *p, const uint8_t *msg, size_t len,
                            uint8_t *out, size_t cap, size_t *out_len,
                            uint64_t now)
{
	if (len < TC_WG_TRANSPORT_HEADER_SIZE + TC_WG_TAG_LEN)
		return TC_OK;
	uint32_t idx = rd32le(msg + 4);

	/* Newest first: during a changeover most traffic is on the new keys. */
	tc_wg_keypair *k = NULL;
	if (p->next.valid && p->next.s.local_index == idx)
		k = &p->next;
	else if (p->current.valid && p->current.s.local_index == idx)
		k = &p->current;
	else if (p->previous.valid && p->previous.s.local_index == idx)
		k = &p->previous;

	if (k == NULL) {
		p->stats.rejected_unknown_key++;
		return TC_OK;
	}
	if (!usable_for_recv(k, now)) {
		/* Past REJECT_AFTER_TIME the keys must not be used at all, however
		 * well the packet authenticates. */
		p->stats.rejected_expired++;
		return TC_OK;
	}

	size_t n = 0;
	if (tc_wg_decrypt(out, cap, &n, &k->s, msg, len) != TC_OK)
		return TC_OK; /* forged, replayed, or truncated */

	/* Only now is the packet proven. A keypair waiting in `next` has just
	 * been shown to work, which is the signal to start sending under it. */
	if (k == &p->next) {
		promote_next(p);
		k = &p->current;
	} else if (k == &p->previous) {
		p->stats.recv_on_previous++;
	}

	if (n == 0) {
		/* A keepalive. It proves the session is alive and needs no answer;
		 * answering every keepalive with a keepalive never terminates. */
		return TC_OK;
	}

	/* WireGuard answers data with an empty packet if nothing else goes back
	 * within the keepalive timeout, so a peer that is only receiving still
	 * tells the sender its session is live. */
	if (!p->keepalive_armed) {
		p->keepalive_armed = true;
		p->keepalive_at = now + TC_WG_KEEPALIVE_TIMEOUT_MS;
	}

	*out_len = n;
	return TC_OK;
}

int tc_wg_peer_input(tc_wg_peer *p, const uint8_t *msg, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len,
                     uint64_t now_ms)
{
	if (p == NULL || msg == NULL || out_len == NULL)
		return TC_ERR_INVAL;
	*out_len = 0;
	if (len < 4)
		return TC_OK;

	/* The type is a little-endian u32, so the upper three bytes must be
	 * zero; a peer that sets them is not speaking this protocol. */
	if (msg[1] != 0 || msg[2] != 0 || msg[3] != 0)
		return TC_OK;

	switch (msg[0]) {
	case TC_WG_MSG_INITIATION:
		return handle_initiation(p, msg, len, now_ms);
	case TC_WG_MSG_RESPONSE:
		return handle_response(p, msg, len, now_ms);
	case TC_WG_MSG_TRANSPORT:
		if (out == NULL)
			return TC_ERR_INVAL;
		return handle_transport(p, msg, len, out, cap, out_len, now_ms);
	case TC_WG_MSG_COOKIE_REPLY:
		/* Not implemented; see PLAN.md 2.3. A peer under load that demands a
		 * cookie will not get one, and our handshake will simply time out. */
		return TC_OK;
	default:
		return TC_OK;
	}
}

/* ---- timers ------------------------------------------------------------ */

int tc_wg_peer_tick(tc_wg_peer *p, uint64_t now_ms)
{
	if (p == NULL)
		return TC_ERR_INVAL;

	/* Expire keys before anything else, so nothing below can use them. */
	if (p->current.valid && !usable_for_recv(&p->current, now_ms))
		kill_keypair(&p->current);
	if (p->previous.valid && !usable_for_recv(&p->previous, now_ms))
		kill_keypair(&p->previous);
	if (p->next.valid && !usable_for_recv(&p->next, now_ms))
		kill_keypair(&p->next);

	if (p->hs_active && now_ms >= p->hs_next_ms) {
		if (now_ms - p->hs_first_ms >= TC_WG_REKEY_ATTEMPT_TIME_MS) {
			/* Ninety seconds of silence: the peer is gone, or something
			 * between us is. Give up rather than resend forever; the next
			 * send starts a fresh attempt with a new ephemeral key. */
			p->hs_active = false;
			tc_memzero_explicit(&p->hs, sizeof p->hs);
			tc_memzero_explicit(p->hs_msg, sizeof p->hs_msg);
			p->stats.handshakes_abandoned++;
		} else {
			/* A fresh initiation, not the previous one again: see
			 * emit_initiation. The attempt clock is not reset, so the whole
			 * sequence still gives up after REKEY_ATTEMPT_TIME. */
			(void)emit_initiation(p);
			p->hs_next_ms = now_ms + TC_WG_REKEY_TIMEOUT_MS + jitter(p);
			p->stats.handshakes_retried++;
		}
	}

	if (p->keepalive_armed && now_ms >= p->keepalive_at) {
		p->keepalive_armed = false;
		send_keepalive(p, now_ms);
	}

	return TC_OK;
}

uint64_t tc_wg_peer_next_deadline(const tc_wg_peer *p)
{
	uint64_t best = UINT64_MAX;
	if (p == NULL)
		return best;

	if (p->hs_active && p->hs_next_ms < best)
		best = p->hs_next_ms;
	if (p->keepalive_armed && p->keepalive_at < best)
		best = p->keepalive_at;

	/* A keypair's expiry is a deadline too: past it the peer must stop using
	 * the keys even if nothing else is happening. */
	const tc_wg_keypair *ks[3] = { &p->current, &p->previous, &p->next };
	for (int i = 0; i < 3; i++) {
		if (!ks[i]->valid)
			continue;
		uint64_t at = ks[i]->birth_ms + TC_WG_REJECT_AFTER_TIME_MS;
		if (at < best)
			best = at;
	}
	return best;
}

bool tc_wg_peer_is_up(const tc_wg_peer *p, uint64_t now_ms)
{
	return p != NULL && usable_for_send(&p->current, now_ms);
}

bool tc_wg_peer_has_keys(const tc_wg_peer *p, uint64_t now_ms)
{
	return p != NULL && (usable_for_recv(&p->current, now_ms) ||
	                     usable_for_recv(&p->next, now_ms));
}

bool tc_wg_peer_handshaking(const tc_wg_peer *p)
{
	return p != NULL && p->hs_active;
}

void tc_wg_peer_get_stats(const tc_wg_peer *p, tc_wg_peer_stats *out)
{
	if (out == NULL)
		return;
	if (p == NULL)
		memset(out, 0, sizeof *out);
	else
		*out = p->stats;
}
