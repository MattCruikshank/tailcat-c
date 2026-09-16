/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Session lifetime: rekeying, the keypair triple, keepalives and expiry.
 *
 * This is the one part of the project whose failure mode is invisible in a
 * short test. A session built once and used forever works perfectly for two
 * minutes -- long enough for every interop check, every live run and every
 * demo -- and then stops. So these tests do not check that a tunnel comes up;
 * they run two peers through *hours* of simulated time and check that it is
 * still up at the end, and that every byte sent arrived.
 *
 * The clock is supplied by the test, so an hour of protocol time costs
 * milliseconds and nothing sleeps.
 */

#include "tc/wgpeer.h"

#include "tc/crypto.h"

#include "tctest.h"

#include <stdlib.h>

/* ---- simulated link ---------------------------------------------------- */

#define LINK_MAXPKT 1400
#define LINK_QUEUE 256

typedef struct {
	uint8_t data[LINK_MAXPKT];
	size_t len;
	bool to_b;
	uint64_t at;
	bool used;
	uint64_t seqno;
} link_pkt;

typedef struct {
	tc_wg_peer a, b;
	link_pkt q[LINK_QUEUE];
	uint64_t now;
	uint64_t counter;

	unsigned loss_pct;
	uint32_t latency_ms;
	bool partitioned;     /* drop everything, to simulate the peer vanishing */
	unsigned drop_responses; /* drop this many handshake responses */

	uint64_t rng;
	bool overflow;

	/* What each side received, for the continuity checks. */
	uint64_t a_recv, b_recv;
	uint8_t last_b[LINK_MAXPKT];
	size_t last_b_len;
} link_t;

static uint32_t lrand(link_t *l)
{
	uint64_t x = l->rng;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	l->rng = x;
	return (uint32_t)((x * 0x2545f4914f6cdd1dULL) >> 32);
}

static int link_out(link_t *l, const uint8_t *p, size_t n, bool to_b)
{
	if (n > LINK_MAXPKT) {
		l->overflow = true;
		return TC_OK;
	}
	if (l->partitioned)
		return TC_OK;
	if (l->drop_responses != 0 && n == TC_WG_RESPONSE_SIZE &&
	    p[0] == TC_WG_MSG_RESPONSE) {
		l->drop_responses--;
		return TC_OK;
	}
	if (l->loss_pct != 0 && (lrand(l) % 100u) < l->loss_pct)
		return TC_OK;

	for (size_t i = 0; i < LINK_QUEUE; i++) {
		if (l->q[i].used)
			continue;
		memcpy(l->q[i].data, p, n);
		l->q[i].len = n;
		l->q[i].to_b = to_b;
		l->q[i].at = l->now + l->latency_ms;
		l->q[i].used = true;
		l->q[i].seqno = l->counter++;
		return TC_OK;
	}
	l->overflow = true;
	return TC_OK;
}

static int out_a(void *ctx, const uint8_t *p, size_t n)
{
	return link_out((link_t *)ctx, p, n, true);
}

static int out_b(void *ctx, const uint8_t *p, size_t n)
{
	return link_out((link_t *)ctx, p, n, false);
}

/* link_deliver hands over everything due now. */
static void link_deliver(link_t *l)
{
	for (;;) {
		size_t best = LINK_QUEUE;
		for (size_t i = 0; i < LINK_QUEUE; i++) {
			if (!l->q[i].used || l->q[i].at > l->now)
				continue;
			if (best == LINK_QUEUE || l->q[i].seqno < l->q[best].seqno)
				best = i;
		}
		if (best == LINK_QUEUE)
			break;
		l->q[best].used = false;

		uint8_t payload[LINK_MAXPKT];
		size_t n = 0;
		tc_wg_peer *dst = l->q[best].to_b ? &l->b : &l->a;
		(void)tc_wg_peer_input(dst, l->q[best].data, l->q[best].len, payload,
		                       sizeof payload, &n, l->now);
		if (n > 0) {
			if (l->q[best].to_b) {
				l->b_recv++;
				memcpy(l->last_b, payload, n);
				l->last_b_len = n;
			} else {
				l->a_recv++;
			}
		}
	}
}

/* The TAI64N offset is global and each test restarts its own clock at zero, so
 * without a base that only ever grows, a later test would mint initiations
 * that look *older* than an earlier one's -- and be rejected as replays.
 * Every test starts a simulated day after the one before. */
static uint64_t g_clock_base;

/* advance moves the clock forward in small steps, running timers. */
static void advance(link_t *l, uint64_t ms)
{
	uint64_t target = l->now + ms;
	while (l->now < target) {
		uint64_t next = target;
		for (size_t i = 0; i < LINK_QUEUE; i++)
			if (l->q[i].used && l->q[i].at < next)
				next = l->q[i].at;
		uint64_t da = tc_wg_peer_next_deadline(&l->a);
		uint64_t db = tc_wg_peer_next_deadline(&l->b);
		if (da > l->now && da < next)
			next = da;
		if (db > l->now && db < next)
			next = db;
		if (next <= l->now)
			next = l->now + 1;
		l->now = next;
		/* Drag the TAI64N clock along with the virtual one. Two simulated
		 * hours pass in well under a millisecond of real time, so without
		 * this every rekey initiation would carry the same timestamp and the
		 * peer would -- correctly -- reject all but the first as replays. */
		tc_wg_timestamp_force_offset_ms(g_clock_base + l->now);

		link_deliver(l);
		tc_wg_peer_tick(&l->a, l->now);
		tc_wg_peer_tick(&l->b, l->now);
		link_deliver(l);
	}
}

static tc_wg_identity g_ida, g_idb;
static uint8_t g_psk[32];

static void link_init(link_t *l, uint64_t seed)
{
	memset(l, 0, sizeof *l);
	l->rng = seed | 1u;
	l->latency_ms = 5;
	g_clock_base += 24u * 60u * 60u * 1000u;
	tc_wg_timestamp_force_offset_ms(g_clock_base);
	tc_wg_peer_init(&l->a, &g_ida, g_idb.public_key, g_psk, out_a, l);
	tc_wg_peer_init(&l->b, &g_idb, g_ida.public_key, g_psk, out_b, l);
	tc_wg_peer_force_rng(&l->a, seed * 7 + 1);
	tc_wg_peer_force_rng(&l->b, seed * 13 + 1);
}

static void link_done(link_t *l)
{
	tc_wg_peer_clear(&l->a);
	tc_wg_peer_clear(&l->b);
}

/* bring_up runs A's handshake to completion. */
static bool bring_up(link_t *l)
{
	tc_wg_peer_start_handshake(&l->a, l->now);
	for (int i = 0; i < 200; i++) {
		advance(l, 20);
		if (tc_wg_peer_is_up(&l->a, l->now))
			return true;
	}
	return false;
}

/* ping sends one payload from A and returns whether B received it. */
static bool ping(link_t *l, uint8_t tag)
{
	uint8_t msg[64];
	memset(msg, tag, sizeof msg);
	uint64_t before = l->b_recv;
	if (tc_wg_peer_send(&l->a, msg, sizeof msg, l->now) != TC_OK)
		return false;
	advance(l, 50);
	return l->b_recv > before && l->last_b_len == sizeof msg &&
	       l->last_b[0] == tag;
}

/* ---- the basics -------------------------------------------------------- */

static void test_handshake_and_data(void)
{
	TCT_CASE("a handshake brings the tunnel up and data flows");
	link_t l;
	link_init(&l, 1);

	TCT_TRUE(!tc_wg_peer_is_up(&l.a, l.now));
	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0xA1));

	TCT_CASE("a responder cannot send until the initiator has");
	/* Its keypair sits in `next` until a data packet proves the initiator
	 * received the response, which is WireGuard's rule and not a limitation
	 * here: sending under an unproven keypair black-holes traffic. */
	tc_wg_peer_stats st;
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.handshakes_responded, 1);
	TCT_EQ_INT((int)st.promotions, 1); /* the ping above proved it */
	TCT_TRUE(tc_wg_peer_is_up(&l.b, l.now));

	TCT_CASE("B can now answer");
	uint8_t msg[32];
	memset(msg, 0xB2, sizeof msg);
	uint64_t before = l.a_recv;
	TCT_EQ_INT(tc_wg_peer_send(&l.b, msg, sizeof msg, l.now), TC_OK);
	advance(&l, 50);
	TCT_TRUE(l.a_recv > before);

	link_done(&l);
}

static void test_responder_holds_next(void)
{
	TCT_CASE("a responder does not send under an unproven keypair");
	link_t l;
	link_init(&l, 2);

	/* Run A's handshake but never let A send data, so B's keypair stays in
	 * `next`. If B sent under it and the response had been lost, every byte
	 * would vanish for a full handshake timeout. */
	TCT_TRUE(bring_up(&l));
	tc_wg_peer_stats st;
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.handshakes_responded, 1);
	TCT_EQ_INT((int)st.promotions, 0);
	TCT_TRUE(!tc_wg_peer_is_up(&l.b, l.now));

	uint8_t msg[16];
	memset(msg, 0xCC, sizeof msg);
	TCT_EQ_INT(tc_wg_peer_send(&l.b, msg, sizeof msg, l.now), TC_ERR_AGAIN);

	link_done(&l);
}

static void test_retry_after_lost_response(void)
{
	TCT_CASE("a handshake recovers when the first response is lost");
	/* The retry must be a *new* initiation. Resending the identical bytes is
	 * the tempting optimisation -- it saves the peer redoing the expensive
	 * half -- and it does not work, because the peer's own replay protection
	 * rejects a repeated timestamp. The whole handshake would then be stuck
	 * until the attempt is abandoned ninety seconds later, from a single
	 * dropped packet. This test exists because that was the bug. */
	link_t l;
	link_init(&l, 3);

	/* The initiation must *arrive* -- that is what makes the peer record a
	 * timestamp -- and the response must be lost. Dropping the initiation
	 * instead would prove nothing, since a peer that never saw one has
	 * nothing to compare a retry against. */
	l.drop_responses = 1;
	tc_wg_peer_start_handshake(&l.a, l.now);
	advance(&l, 1000);

	bool up = false;
	for (int i = 0; i < 120; i++) {
		advance(&l, 1000);
		if (tc_wg_peer_is_up(&l.a, l.now)) {
			up = true;
			break;
		}
	}
	TCT_TRUE(up);

	tc_wg_peer_stats sa, sb;
	tc_wg_peer_get_stats(&l.a, &sa);
	tc_wg_peer_get_stats(&l.b, &sb);
	/* It must have taken a retry to get here, or the test proved nothing. */
	if (sa.handshakes_retried == 0)
		TCT_FAILF("the first response was not actually lost");
	tct_checks++;
	if (sb.handshakes_responded < 2)
		TCT_FAILF("the peer answered %llu initiations, so the retry never "
		          "reached it as a new handshake",
		          (unsigned long long)sb.handshakes_responded);
	tct_checks++;
	/* And the peer must not have dismissed any retry as a replay. */
	TCT_EQ_INT((int)sb.rejected_replay, 0);

	TCT_TRUE(ping(&l, 0xD1));

	link_done(&l);
}

/* ---- the point of the whole file --------------------------------------- */

static void test_survives_hours(unsigned loss, uint64_t seed, const char *what)
{
	TCT_CASE(what);
	/* Two hours of protocol time. A session that is never renewed dies after
	 * three minutes, so this fails within the first 1/40th of the run if
	 * rekeying does not work at all -- and near the end if it merely leaks a
	 * keypair slot or drifts a timer. */
	link_t l;
	link_init(&l, seed);
	l.loss_pct = loss;

	TCT_TRUE(bring_up(&l));

	const uint64_t kTotal = 2u * 60u * 60u * 1000u;
	const uint64_t kStep = 10000u; /* send something every ten seconds */
	uint64_t sent = 0, delivered = 0;
	uint64_t failed_windows = 0;
	uint8_t tag = 0;

	while (l.now < kTotal) {
		uint64_t before = l.b_recv;
		uint8_t msg[128];
		memset(msg, tag, sizeof msg);

		/* A send during a rekey returns TC_ERR_AGAIN, which is ordinary
		 * packet loss as far as anything above is concerned. Retrying inside
		 * the window is exactly what TCP would do. */
		bool ok = false;
		/* Thirty seconds of patience per window. A rekey whose initiation is
		 * lost waits REKEY_TIMEOUT before resending, so a lossy link really
		 * does produce outages of several seconds -- that is WireGuard, not a
		 * defect. What must not happen is an outage that never ends. */
		for (int attempt = 0; attempt < 60; attempt++) {
			if (tc_wg_peer_send(&l.a, msg, sizeof msg, l.now) == TC_OK) {
				sent++;
				advance(&l, 500);
				if (l.b_recv > before) {
					ok = true;
					break;
				}
			} else {
				advance(&l, 500);
			}
		}
		if (ok)
			delivered++;
		else
			failed_windows++;

		/* B answers, which is what drives B's own rekey timer. */
		(void)tc_wg_peer_send(&l.b, msg, 32, l.now);

		advance(&l, kStep);
		tag++;
	}

	TCT_TRUE(tc_wg_peer_is_up(&l.a, l.now));

	/* With a clean link every window must succeed. With loss, the retry loop
	 * covers far more than the loss rate needs, so this is still absolute. */
	if (failed_windows != 0)
		TCT_FAILF("%llu of %llu ten-second windows delivered nothing",
		          (unsigned long long)failed_windows,
		          (unsigned long long)(delivered + failed_windows));
	tct_checks++;

	tc_wg_peer_stats sa, sb;
	tc_wg_peer_get_stats(&l.a, &sa);
	tc_wg_peer_get_stats(&l.b, &sb);

	/* Two hours at a 120-second rekey interval is about sixty renewals. Far
	 * fewer would mean the timer is not firing; far more would mean it is
	 * firing repeatedly on a session that never gets used. */
	if (sa.rekeys < 45 || sa.rekeys > 75)
		TCT_FAILF("%llu rekeys in two hours, expected roughly 60",
		          (unsigned long long)sa.rekeys);
	tct_checks++;

	/* The changeover must actually be seamless, which means packets really
	 * do arrive under the outgoing keypair while the new one settles. If
	 * this is zero the overlap is not being exercised and the triple is
	 * untested however green the run looks. */
	if (sb.recv_on_previous == 0 && sa.recv_on_previous == 0)
		TCT_FAILF("no packet ever arrived on a previous keypair: the "
		          "changeover overlap is not being tested");
	tct_checks++;

	if (l.overflow)
		TCT_FAILF("the simulated link overflowed");
	tct_checks++;

	link_done(&l);
}

/* ---- expiry ------------------------------------------------------------ */

static void test_expiry(void)
{
	TCT_CASE("a session past REJECT_AFTER_TIME is refused");
	link_t l;
	link_init(&l, 5);
	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0x11));

	/* Cut the link and keep trying to send for longer than three minutes.
	 * The sends matter: WireGuard renews on transmit, so a peer with nothing
	 * to say never notices anything is wrong. Both sides must end with no
	 * usable session rather than quietly keeping expired keys. */
	l.partitioned = true;
	uint8_t probe[8];
	memset(probe, 0x10, sizeof probe);
	/* The handshake only starts once the session reaches its rekey age, so
	 * abandonment is REKEY_AFTER_TIME + REKEY_ATTEMPT_TIME away, not
	 * REKEY_ATTEMPT_TIME. */
	for (int i = 0; i < 300; i++) {
		(void)tc_wg_peer_send(&l.a, probe, sizeof probe, l.now);
		advance(&l, 1000);
	}

	TCT_TRUE(!tc_wg_peer_is_up(&l.a, l.now));
	TCT_TRUE(!tc_wg_peer_is_up(&l.b, l.now));

	TCT_CASE("and the peer gives up handshaking after REKEY_ATTEMPT_TIME");
	tc_wg_peer_stats st;
	tc_wg_peer_get_stats(&l.a, &st);
	if (st.handshakes_abandoned == 0)
		TCT_FAILF("never abandoned a handshake against a peer that is gone");
	tct_checks++;
	if (st.handshakes_retried < 5)
		TCT_FAILF("only %llu retries before giving up",
		          (unsigned long long)st.handshakes_retried);
	tct_checks++;

	TCT_CASE("the tunnel recovers when the peer comes back");
	l.partitioned = false;
	uint8_t msg[8];
	memset(msg, 0x22, sizeof msg);
	bool back = false;
	for (int i = 0; i < 100; i++) {
		(void)tc_wg_peer_send(&l.a, msg, sizeof msg, l.now);
		advance(&l, 1000);
		if (tc_wg_peer_is_up(&l.a, l.now)) {
			back = true;
			break;
		}
	}
	TCT_TRUE(back);
	TCT_TRUE(ping(&l, 0x33));

	link_done(&l);
}

/* ---- keepalives -------------------------------------------------------- */

static void test_keepalive(void)
{
	TCT_CASE("a data packet is answered with a keepalive if nothing else is");
	link_t l;
	link_init(&l, 7);
	TCT_TRUE(bring_up(&l));

	uint8_t msg[16];
	memset(msg, 0x44, sizeof msg);
	TCT_EQ_INT(tc_wg_peer_send(&l.a, msg, sizeof msg, l.now), TC_OK);
	advance(&l, 100);

	tc_wg_peer_stats st;
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.keepalives_sent, 0); /* not yet: the timer is running */

	advance(&l, TC_WG_KEEPALIVE_TIMEOUT_MS + 500);
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.keepalives_sent, 1);

	TCT_CASE("a keepalive is not answered with a keepalive");
	/* Two peers echoing each other's keepalives would never stop. */
	advance(&l, TC_WG_KEEPALIVE_TIMEOUT_MS * 4);
	tc_wg_peer_get_stats(&l.a, &st);
	TCT_EQ_INT((int)st.keepalives_sent, 0);
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.keepalives_sent, 1);

	TCT_CASE("real traffic cancels the keepalive");
	uint64_t before_a;
	tc_wg_peer_get_stats(&l.b, &st);
	before_a = st.keepalives_sent;
	TCT_EQ_INT(tc_wg_peer_send(&l.a, msg, sizeof msg, l.now), TC_OK);
	advance(&l, 100);
	TCT_EQ_INT(tc_wg_peer_send(&l.b, msg, sizeof msg, l.now), TC_OK);
	advance(&l, TC_WG_KEEPALIVE_TIMEOUT_MS + 500);
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)(st.keepalives_sent - before_a), 0);

	link_done(&l);
}

/* ---- initiation replay (PLAN 2.4) -------------------------------------- */

static void test_initiation_replay(void)
{
	TCT_CASE("a replayed initiation is rejected");
	/* Without this, anyone who recorded one initiation can make a peer burn
	 * a handshake and discard a working session whenever they like. */
	link_t l;
	link_init(&l, 9);

	/* Capture A's initiation off the wire. */
	tc_wg_peer_start_handshake(&l.a, l.now);
	uint8_t init[TC_WG_INITIATION_SIZE];
	size_t init_len = 0;
	for (size_t i = 0; i < LINK_QUEUE; i++) {
		if (l.q[i].used && l.q[i].to_b &&
		    l.q[i].len == TC_WG_INITIATION_SIZE) {
			memcpy(init, l.q[i].data, l.q[i].len);
			init_len = l.q[i].len;
			break;
		}
	}
	TCT_EQ_INT((int)init_len, TC_WG_INITIATION_SIZE);

	advance(&l, 200);
	TCT_TRUE(tc_wg_peer_is_up(&l.a, l.now));
	TCT_TRUE(ping(&l, 0x55));

	tc_wg_peer_stats before, after;
	tc_wg_peer_get_stats(&l.b, &before);

	/* Feed the very same bytes again. */
	uint8_t payload[256];
	size_t n = 0;
	TCT_EQ_INT(tc_wg_peer_input(&l.b, init, init_len, payload, sizeof payload,
	                            &n, l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);

	tc_wg_peer_get_stats(&l.b, &after);
	TCT_EQ_INT((int)(after.rejected_replay - before.rejected_replay), 1);
	/* And it must not have answered or built anything. */
	TCT_EQ_INT((int)(after.handshakes_responded - before.handshakes_responded),
	           0);

	TCT_CASE("the working session is untouched by the replay");
	TCT_TRUE(ping(&l, 0x66));

	TCT_CASE("a genuine new initiation is still accepted");
	advance(&l, 2000); /* so the timestamp is strictly newer */
	l.a.hs_active = false;
	TCT_EQ_INT(tc_wg_peer_start_handshake(&l.a, l.now), TC_OK);
	advance(&l, 500);
	tc_wg_peer_get_stats(&l.b, &after);
	TCT_EQ_INT((int)(after.handshakes_responded - before.handshakes_responded),
	           1);

	link_done(&l);
}

/* ---- cookies (PLAN 2.3) ------------------------------------------------ */

static void test_cookie_exchange(void)
{
	TCT_CASE("a peer under load demands a cookie and the handshake completes");
	/* The exchange costs one extra round trip: the first initiation is
	 * refused with a cookie, and the retry carries a mac2 derived from it. */
	link_t l;
	link_init(&l, 31);
	tc_wg_peer_set_under_load(&l.b, true);

	TCT_EQ_INT(tc_wg_peer_start_handshake(&l.a, l.now), TC_OK);

	bool up = false;
	for (int i = 0; i < 200; i++) {
		advance(&l, 100);
		if (tc_wg_peer_is_up(&l.a, l.now)) {
			up = true;
			break;
		}
	}
	TCT_TRUE(up);

	tc_wg_peer_stats sa, sb;
	tc_wg_peer_get_stats(&l.a, &sa);
	tc_wg_peer_get_stats(&l.b, &sb);

	/* It must actually have gone through the cookie path, or this test is
	 * only checking that handshakes work. */
	TCT_EQ_INT((int)sb.cookies_sent, 1);
	TCT_EQ_INT((int)sb.rejected_mac2, 1);
	TCT_EQ_INT((int)sa.cookies_received, 1);
	TCT_EQ_INT((int)sb.handshakes_responded, 1);

	TCT_CASE("and the retry was prompt, not a full REKEY_TIMEOUT later");
	/* The peer said exactly what was missing, so waiting five seconds to
	 * act on it would be five seconds of dead tunnel for no reason. */
	if (l.now > 2000)
		TCT_FAILF("took %llums to complete, so the cookie did not trigger "
		          "an immediate retry",
		          (unsigned long long)l.now);
	tct_checks++;

	TCT_TRUE(ping(&l, 0xE1));

	TCT_CASE("a later handshake reuses the cookie and is not refused again");
	uint64_t before_cookies = sb.cookies_sent;
	advance(&l, 2000);
	l.a.hs_active = false;
	TCT_EQ_INT(tc_wg_peer_start_handshake(&l.a, l.now), TC_OK);
	advance(&l, 500);
	tc_wg_peer_get_stats(&l.b, &sb);
	TCT_EQ_INT((int)(sb.cookies_sent - before_cookies), 0);
	TCT_EQ_INT((int)sb.handshakes_responded, 2);

	link_done(&l);
}

static void test_cookie_expiry(void)
{
	TCT_CASE("a cookie older than the refresh interval is demanded again");
	/* The responder rotates its secret every two minutes, so a cookie past
	 * that no longer verifies and the exchange has to happen afresh. */
	link_t l;
	link_init(&l, 33);
	tc_wg_peer_set_under_load(&l.b, true);

	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0xE2));

	tc_wg_peer_stats sb;
	tc_wg_peer_get_stats(&l.b, &sb);
	TCT_EQ_INT((int)sb.cookies_sent, 1);

	/* Past the refresh interval, with the session dead too. */
	advance(&l, TC_WG_COOKIE_REFRESH_MS + 10000);
	uint8_t msg[16];
	memset(msg, 0xE3, sizeof msg);
	bool back = false;
	for (int i = 0; i < 100; i++) {
		(void)tc_wg_peer_send(&l.a, msg, sizeof msg, l.now);
		advance(&l, 500);
		if (tc_wg_peer_is_up(&l.a, l.now)) {
			back = true;
			break;
		}
	}
	TCT_TRUE(back);

	tc_wg_peer_get_stats(&l.b, &sb);
	if (sb.cookies_sent < 2)
		TCT_FAILF("the stale cookie was accepted: only %llu were ever issued",
		          (unsigned long long)sb.cookies_sent);
	tct_checks++;

	link_done(&l);
}

static void test_cookie_reply_cannot_be_forged(void)
{
	TCT_CASE("a cookie reply from anyone else is ignored");
	link_t l;
	link_init(&l, 35);
	tc_wg_peer_set_under_load(&l.b, true);
	TCT_TRUE(bring_up(&l));

	tc_wg_peer_stats before, after;
	tc_wg_peer_get_stats(&l.a, &before);

	/* A well-formed reply sealed under a key A does not expect. */
	uint8_t junk[TC_WG_COOKIE_REPLY_SIZE];
	memset(junk, 0, sizeof junk);
	junk[0] = TC_WG_MSG_COOKIE_REPLY;
	TCT_EQ_INT(tc_random_bytes(junk + 8, sizeof junk - 8), TC_OK);

	uint8_t out[64];
	size_t n = 1;
	TCT_EQ_INT(tc_wg_peer_input(&l.a, junk, sizeof junk, out, sizeof out, &n,
	                            l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);
	tc_wg_peer_get_stats(&l.a, &after);
	TCT_EQ_INT((int)(after.cookies_received - before.cookies_received), 0);

	TCT_CASE("a truncated cookie reply is ignored");
	TCT_EQ_INT(tc_wg_peer_input(&l.a, junk, 20, out, sizeof out, &n, l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);

	TCT_CASE("and the session is undisturbed");
	TCT_TRUE(ping(&l, 0xE4));

	link_done(&l);
}

static void test_not_under_load_by_default(void)
{
	TCT_CASE("a peer not under load never demands a cookie");
	/* The default has to stay off: an extra round trip on every handshake
	 * would be a real cost for a tool whose traffic is already bounded by
	 * the relay. */
	link_t l;
	link_init(&l, 37);
	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0xE5));

	tc_wg_peer_stats sa, sb;
	tc_wg_peer_get_stats(&l.a, &sa);
	tc_wg_peer_get_stats(&l.b, &sb);
	TCT_EQ_INT((int)sb.cookies_sent, 0);
	TCT_EQ_INT((int)sa.cookies_received, 0);
	TCT_EQ_INT((int)sb.rejected_mac2, 0);
	/* And no extra round trip: one initiation, one response. */
	TCT_EQ_INT((int)sa.handshakes_initiated, 1);
	TCT_EQ_INT((int)sa.handshakes_retried, 0);

	link_done(&l);
}

/* ---- dispatch and malformed input -------------------------------------- */

static void test_rejects_junk(void)
{
	TCT_CASE("malformed and foreign messages are ignored, not fatal");
	link_t l;
	link_init(&l, 11);
	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0x77));

	uint8_t out[256];
	size_t n = 1;
	uint8_t junk[200];
	memset(junk, 0, sizeof junk);

	/* Too short, unknown type, and a type whose upper bytes are not zero. */
	TCT_EQ_INT(tc_wg_peer_input(&l.b, junk, 2, out, sizeof out, &n, l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);
	junk[0] = 9;
	TCT_EQ_INT(tc_wg_peer_input(&l.b, junk, sizeof junk, out, sizeof out, &n,
	                            l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);
	junk[0] = TC_WG_MSG_TRANSPORT;
	junk[1] = 1;
	TCT_EQ_INT(tc_wg_peer_input(&l.b, junk, sizeof junk, out, sizeof out, &n,
	                            l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);

	TCT_CASE("a transport packet for a keypair we do not hold is counted");
	tc_wg_peer_stats st;
	junk[1] = 0;
	junk[4] = 0xde;
	junk[5] = 0xad;
	junk[6] = 0xbe;
	junk[7] = 0xef;
	TCT_EQ_INT(tc_wg_peer_input(&l.b, junk, sizeof junk, out, sizeof out, &n,
	                            l.now),
	           TC_OK);
	tc_wg_peer_get_stats(&l.b, &st);
	TCT_EQ_INT((int)st.rejected_unknown_key, 1);

	TCT_CASE("a forged packet on a real index does not disturb the session");
	/* Same index as the live keypair, wrong contents: it must fail the tag
	 * and leave the replay window alone. */
	junk[4] = (uint8_t)(l.b.current.s.local_index);
	junk[5] = (uint8_t)(l.b.current.s.local_index >> 8);
	junk[6] = (uint8_t)(l.b.current.s.local_index >> 16);
	junk[7] = (uint8_t)(l.b.current.s.local_index >> 24);
	TCT_EQ_INT(tc_wg_peer_input(&l.b, junk, sizeof junk, out, sizeof out, &n,
	                            l.now),
	           TC_OK);
	TCT_EQ_INT((int)n, 0);
	TCT_TRUE(ping(&l, 0x88));

	TCT_CASE("null arguments are refused");
	TCT_EQ_INT(tc_wg_peer_input(NULL, junk, 4, out, sizeof out, &n, 0),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_wg_peer_input(&l.b, NULL, 4, out, sizeof out, &n, 0),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_wg_peer_tick(NULL, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_wg_peer_send(NULL, out, 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_wg_peer_init(&l.a, &g_ida, NULL, NULL, out_a, &l),
	           TC_ERR_INVAL);
	TCT_TRUE(!tc_wg_peer_is_up(NULL, 0));
	TCT_TRUE(!tc_wg_peer_handshaking(NULL));
	TCT_TRUE(tc_wg_peer_next_deadline(NULL) == UINT64_MAX);
	tc_wg_peer_clear(NULL);

	link_done(&l);
}

/* ---- the counter limit -------------------------------------------------- */

static void test_rekeys_on_message_count(void)
{
	TCT_CASE("a rekey is triggered by message count, not only by time");
	/* Reaching 2^60 messages honestly is not possible in a test, so the
	 * counter is wound forward directly -- the branch being checked is the
	 * one that compares it, and that branch is otherwise unreachable. */
	link_t l;
	link_init(&l, 13);
	TCT_TRUE(bring_up(&l));
	TCT_TRUE(ping(&l, 0x99));

	TCT_TRUE(!tc_wg_peer_handshaking(&l.a));
	l.a.current.s.send_counter = TC_WG_REKEY_AFTER_MESSAGES;

	uint8_t msg[16];
	memset(msg, 0xAB, sizeof msg);
	TCT_EQ_INT(tc_wg_peer_send(&l.a, msg, sizeof msg, l.now), TC_OK);
	TCT_TRUE(tc_wg_peer_handshaking(&l.a));

	advance(&l, 500);
	TCT_TRUE(!tc_wg_peer_handshaking(&l.a));
	TCT_TRUE(ping(&l, 0xAC));

	TCT_CASE("and sending is refused outright past REJECT_AFTER_MESSAGES");
	l.a.current.s.send_counter = TC_WG_REJECT_AFTER_MESSAGES;
	TCT_EQ_INT(tc_wg_peer_send(&l.a, msg, sizeof msg, l.now), TC_ERR_AGAIN);

	link_done(&l);
}

int main(void)
{
	if (tc_wg_identity_generate(&g_ida) != TC_OK ||
	    tc_wg_identity_generate(&g_idb) != TC_OK) {
		fprintf(stderr, "could not generate identities\n");
		return 1;
	}
	if (tc_random_bytes(g_psk, sizeof g_psk) != TC_OK)
		return 1;

	test_handshake_and_data();
	test_responder_holds_next();
	test_retry_after_lost_response();
	test_survives_hours(0, 21, "two hours on a clean link, no gaps");
	test_survives_hours(5, 22, "two hours with 5% loss, no gaps");
	test_expiry();
	test_keepalive();
	test_initiation_replay();
	test_cookie_exchange();
	test_cookie_expiry();
	test_cookie_reply_cannot_be_forged();
	test_not_under_load_by_default();
	test_rejects_junk();
	test_rekeys_on_message_count();
	return tct_report("wgpeer");
}
