/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Demultiplexer tests.
 *
 * The property that matters here is that streams do not cross. A dispatcher
 * that is subtly wrong -- keying on the wrong port, matching the first
 * connection rather than the right one, reusing a slot that moved during a
 * reap -- still passes a single-connection test and still looks fine with two
 * idle connections. It shows up when several connections carry *different*
 * bytes at the same time through a link that reorders.
 *
 * So the central test runs many connections at once, each carrying a stream
 * that is a function of its own identity, and checks that every byte arriving
 * on a connection belongs to it. Mis-delivery cannot hide: the first stray
 * byte fails the comparison.
 *
 * As in test_tcp.c, two of our own stacks talk through a simulated link and
 * the test supplies the clock, so all of this runs with no timers and no
 * network.
 */

#include "tc/tcpmux.h"

#include "tctest.h"

#include <stdlib.h>

/* ---- simulated link --------------------------------------------------- */

#define LINK_MAXPKT 1400
#define LINK_QUEUE 2048

typedef struct {
	uint8_t data[LINK_MAXPKT];
	size_t len;
	bool to_b;
	uint64_t at;
	bool used;
	uint64_t seqno;
} link_pkt;

typedef struct {
	tc_tcp_mux *a, *b;
	link_pkt q[LINK_QUEUE];
	uint64_t now;
	uint64_t counter;

	unsigned loss_pct;
	unsigned reorder_pct;
	uint32_t latency_ms;

	uint64_t rng;
	bool overflow;
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

static bool chance(link_t *l, unsigned pct)
{
	return pct != 0 && (lrand(l) % 100u) < pct;
}

static int link_out(link_t *l, const uint8_t *p, size_t n, bool to_b)
{
	if (n > LINK_MAXPKT) {
		l->overflow = true;
		return TC_OK;
	}
	if (chance(l, l->loss_pct))
		return TC_OK;

	uint64_t delay = l->latency_ms;
	if (chance(l, l->reorder_pct))
		delay += 5 + lrand(l) % 25;

	for (size_t i = 0; i < LINK_QUEUE; i++) {
		if (l->q[i].used)
			continue;
		memcpy(l->q[i].data, p, n);
		l->q[i].len = n;
		l->q[i].to_b = to_b;
		l->q[i].at = l->now + delay;
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

static void link_step(link_t *l)
{
	uint64_t next = UINT64_MAX;
	for (size_t i = 0; i < LINK_QUEUE; i++)
		if (l->q[i].used && l->q[i].at < next)
			next = l->q[i].at;

	uint64_t da = tc_tcp_mux_next_deadline(l->a);
	uint64_t db = tc_tcp_mux_next_deadline(l->b);
	if (da < next)
		next = da;
	if (db < next)
		next = db;

	if (next == UINT64_MAX)
		next = l->now + 10;
	if (next < l->now)
		next = l->now;
	l->now = next;

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
		tc_tcp_mux *dst = l->q[best].to_b ? l->b : l->a;
		tc_tcp_mux_input(dst, l->q[best].data, l->q[best].len, l->now);
	}

	tc_tcp_mux_tick(l->a, l->now);
	tc_tcp_mux_tick(l->b, l->now);
}

static const uint8_t kIpA[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 1 };
static const uint8_t kIpB[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 2 };

static void link_init(link_t *l, uint64_t seed)
{
	memset(l, 0, sizeof *l);
	l->rng = seed | 1u;
	l->latency_ms = 5;
	l->a = tc_tcp_mux_new(kIpA, kIpB, out_a, l);
	l->b = tc_tcp_mux_new(kIpB, kIpA, out_b, l);
}

static void link_done(link_t *l)
{
	tc_tcp_mux_free(l->a);
	tc_tcp_mux_free(l->b);
}

/* ---- many streams at once --------------------------------------------- */

#define NSTREAMS 8

/* Every byte is a function of the stream it belongs to, so a byte delivered
 * to the wrong connection is detected where it lands. */
static uint8_t pattern(int id, size_t off)
{
	size_t v = (size_t)id * 37u + off * 11u + (off >> 8) * 7u + 3u;
	return (uint8_t)v;
}

static size_t stream_len(int id)
{
	return 4000 + (size_t)id * 2600;
}

typedef struct {
	tc_tcp_conn *conn;
	size_t sent;
	size_t got;
	bool half_closed;
	bool done;
} endpoint;

static void test_concurrent_streams(unsigned loss, unsigned reorder,
                                    uint64_t seed, const char *what)
{
	TCT_CASE(what);

	link_t l;
	link_init(&l, seed);
	l.loss_pct = loss;
	l.reorder_pct = reorder;

	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	endpoint A[NSTREAMS];
	endpoint B[NSTREAMS];
	uint16_t a_port[NSTREAMS];
	memset(A, 0, sizeof A);
	memset(B, 0, sizeof B);

	for (int i = 0; i < NSTREAMS; i++) {
		TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &A[i].conn), TC_OK);
		a_port[i] = tc_tcp_local_port(A[i].conn);
		/* Every dial must get a distinct ephemeral port, or two streams
		 * would share a key and the table could not tell them apart. */
		for (int j = 0; j < i; j++) {
			if (a_port[j] == a_port[i])
				TCT_FAILF("ephemeral port %u handed out twice", a_port[i]);
		}
		if (a_port[i] < TC_TCP_EPHEMERAL_LO)
			TCT_FAILF("port %u is below the ephemeral range", a_port[i]);
	}
	tct_checks += NSTREAMS;

	bool failed = false;
	int guard = 0;
	for (; guard < 400000; guard++) {
		/* Collect anything B has accepted, matching it to the stream by the
		 * remote port -- which is the dispatcher's own answer to "whose is
		 * this", checked against what the dialer chose. */
		tc_tcp_conn *nc;
		while ((nc = tc_tcp_mux_accept(l.b)) != NULL) {
			uint16_t rp = tc_tcp_remote_port(nc);
			int id = -1;
			for (int i = 0; i < NSTREAMS; i++)
				if (a_port[i] == rp)
					id = i;
			if (id < 0) {
				TCT_FAILF("accepted a connection from unknown port %u", rp);
				failed = true;
				break;
			}
			if (B[id].conn != NULL) {
				TCT_FAILF("stream %d was accepted twice", id);
				failed = true;
				break;
			}
			B[id].conn = nc;
		}
		if (failed)
			break;

		for (int i = 0; i < NSTREAMS; i++) {
			/* Writer side. */
			endpoint *w = &A[i];
			if (tc_tcp_is_established(w->conn) && w->sent < stream_len(i)) {
				uint8_t buf[2048];
				size_t room = tc_tcp_writable(w->conn);
				size_t want = stream_len(i) - w->sent;
				if (want > sizeof buf)
					want = sizeof buf;
				if (want > room)
					want = room;
				if (want > 0) {
					for (size_t k = 0; k < want; k++)
						buf[k] = pattern(i, w->sent + k);
					size_t wrote = 0;
					tc_tcp_write(w->conn, buf, want, &wrote, l.now);
					w->sent += wrote;
				}
			}
			if (w->sent == stream_len(i) && !w->half_closed &&
			    tc_tcp_send_unacked(w->conn) == 0) {
				tc_tcp_shutdown_write(w->conn, l.now);
				w->half_closed = true;
			}

			/* Reader side. */
			endpoint *r = &B[i];
			if (r->conn == NULL)
				continue;
			for (;;) {
				uint8_t buf[2048];
				size_t n = 0;
				if (tc_tcp_read(r->conn, buf, sizeof buf, &n) != TC_OK || n == 0)
					break;
				for (size_t k = 0; k < n; k++) {
					if (buf[k] != pattern(i, r->got + k)) {
						TCT_FAILF("stream %d byte %zu is 0x%02x, want 0x%02x "
						          "-- a packet was delivered to the wrong "
						          "connection",
						          i, r->got + k, buf[k],
						          pattern(i, r->got + k));
						failed = true;
						break;
					}
				}
				r->got += n;
				if (failed)
					break;
			}
			if (failed)
				break;
			if (!r->done && tc_tcp_read_closed(r->conn))
				r->done = true;
		}
		if (failed)
			break;

		bool all = true;
		for (int i = 0; i < NSTREAMS; i++)
			if (!B[i].done || B[i].got != stream_len(i))
				all = false;
		if (all)
			break;

		link_step(&l);
	}

	if (!failed) {
		if (guard >= 400000)
			TCT_FAILF("did not finish: the link or the stacks stalled");
		tct_checks++;
		for (int i = 0; i < NSTREAMS; i++) {
			if (B[i].got != stream_len(i))
				TCT_FAILF("stream %d delivered %zu of %zu bytes", i, B[i].got,
				          stream_len(i));
			tct_checks++;
		}
	}
	if (l.overflow)
		TCT_FAILF("the simulated link overflowed");
	tct_checks++;

	tc_tcp_mux_stats st;
	tc_tcp_mux_get_stats(l.b, &st);
	TCT_EQ_INT((int)st.accepted, NSTREAMS);
	tc_tcp_mux_get_stats(l.a, &st);
	TCT_EQ_INT((int)st.dialled, NSTREAMS);
	/* Nothing here addresses a port nobody owns. */
	TCT_EQ_INT((int)st.rejected_port, 0);

	link_done(&l);
}

/* ---- a closed port ----------------------------------------------------- */

static void test_closed_port_is_refused(void)
{
	TCT_CASE("dialling a port nobody listens on is refused, not ignored");
	/* The difference matters: a dropped SYN makes the dialer retransmit for
	 * a minute before giving up, which a user reads as a hang. */
	link_t l;
	link_init(&l, 99);

	tc_tcp_conn *c = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 9999, l.now, &c), TC_OK);

	for (int i = 0; i < 200; i++) {
		if (tc_tcp_get_state(c) == TC_TCP_CLOSED)
			break;
		link_step(&l);
	}
	TCT_EQ_INT(tc_tcp_get_state(c), TC_TCP_CLOSED);

	tc_tcp_mux_stats st;
	tc_tcp_mux_get_stats(l.b, &st);
	TCT_EQ_INT((int)st.rejected_port, 1);
	TCT_EQ_INT((int)st.accepted, 0);

	TCT_CASE("the refused connection is reaped");
	TCT_EQ_INT((int)tc_tcp_mux_reap(l.a), 1);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.a), 0);

	TCT_CASE("a reset is never answered with a reset");
	/* Otherwise two stacks that disagree would trade resets forever. */
	uint64_t before = l.counter;
	for (int i = 0; i < 50; i++)
		link_step(&l);
	uint64_t after = l.counter;
	if (after - before > 4)
		TCT_FAILF("%llu packets still flowing after both sides gave up",
		          (unsigned long long)(after - before));
	tct_checks++;

	link_done(&l);
}

/* ---- listeners --------------------------------------------------------- */

static void test_listeners(void)
{
	TCT_CASE("listen, unlisten, and their errors");
	link_t l;
	link_init(&l, 5);

	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 22), TC_OK);
	TCT_TRUE(tc_tcp_mux_is_listening(l.b, 22));
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 22), TC_ERR_EXIST);
	TCT_EQ_INT(tc_tcp_mux_unlisten(l.b, 22), TC_OK);
	TCT_TRUE(!tc_tcp_mux_is_listening(l.b, 22));
	TCT_EQ_INT(tc_tcp_mux_unlisten(l.b, 22), TC_ERR_INVAL);

	TCT_CASE("the listener set is bounded");
	for (int i = 0; i < TC_TCP_MAX_LISTENERS; i++)
		TCT_EQ_INT(tc_tcp_mux_listen(l.b, (uint16_t)(1000 + i)), TC_OK);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 2000), TC_ERR_TOOMANY);

	TCT_CASE("unlistening does not disturb an established connection");
	TCT_EQ_INT(tc_tcp_mux_unlisten(l.b, 1000), TC_OK);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 80), TC_OK);
	tc_tcp_conn *ca = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 80, l.now, &ca), TC_OK);
	for (int i = 0; i < 200 && !tc_tcp_is_established(ca); i++)
		link_step(&l);
	TCT_TRUE(tc_tcp_is_established(ca));
	tc_tcp_conn *cb = tc_tcp_mux_accept(l.b);
	TCT_TRUE(cb != NULL);
	TCT_EQ_INT(tc_tcp_mux_unlisten(l.b, 80), TC_OK);

	uint8_t msg[] = "still here";
	size_t wrote = 0;
	TCT_EQ_INT(tc_tcp_write(ca, msg, sizeof msg, &wrote, l.now), TC_OK);
	for (int i = 0; i < 200 && tc_tcp_readable(cb) < sizeof msg; i++)
		link_step(&l);
	uint8_t got[32];
	size_t n = 0;
	TCT_EQ_INT(tc_tcp_read(cb, got, sizeof got, &n), TC_OK);
	TCT_EQ_INT((int)n, (int)sizeof msg);
	TCT_EQ_MEM(got, msg, sizeof msg);

	link_done(&l);
}

/* ---- limits ------------------------------------------------------------ */

static int sink_out(void *ctx, const uint8_t *p, size_t n)
{
	(void)ctx;
	(void)p;
	(void)n;
	return TC_OK;
}

static void test_table_limit(void)
{
	TCT_CASE("the connection table is bounded");
	tc_tcp_mux *m = tc_tcp_mux_new(kIpA, kIpB, sink_out, NULL);
	TCT_TRUE(m != NULL);

	for (int i = 0; i < TC_TCP_MAX_CONNS; i++) {
		tc_tcp_conn *c = NULL;
		if (tc_tcp_mux_connect(m, 7, 0, &c) != TC_OK || c == NULL)
			TCT_FAILF("dial %d of %d failed", i, TC_TCP_MAX_CONNS);
	}
	tct_checks++;
	TCT_EQ_INT((int)tc_tcp_mux_count(m), TC_TCP_MAX_CONNS);

	tc_tcp_conn *over = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(m, 7, 0, &over), TC_ERR_TOOMANY);
	TCT_TRUE(over == NULL);

	TCT_CASE("closing one makes room again");
	tc_tcp_mux_close(m, tc_tcp_mux_at(m, 0), 0);
	TCT_EQ_INT((int)tc_tcp_mux_count(m), TC_TCP_MAX_CONNS - 1);
	TCT_EQ_INT(tc_tcp_mux_connect(m, 7, 0, &over), TC_OK);

	tc_tcp_mux_free(m);
}

static void test_backlog_limit(void)
{
	TCT_CASE("SYNs past the backlog are refused rather than queued");
	/* An application that stops accepting must not be able to consume the
	 * whole table, and the peers it turns away should learn at once. */
	link_t l;
	link_init(&l, 7);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	tc_tcp_conn *ca[TC_TCP_BACKLOG + 4];
	for (int i = 0; i < TC_TCP_BACKLOG + 4; i++)
		TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &ca[i]), TC_OK);

	/* B never accepts. */
	for (int i = 0; i < 400; i++)
		link_step(&l);

	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), TC_TCP_BACKLOG);

	tc_tcp_mux_stats st;
	tc_tcp_mux_get_stats(l.b, &st);
	TCT_EQ_INT((int)st.accepted, TC_TCP_BACKLOG);
	if (st.rejected_full < 4)
		TCT_FAILF("only %llu SYNs were refused, expected at least 4",
		          (unsigned long long)st.rejected_full);
	tct_checks++;

	TCT_CASE("the refused dialers see a closed connection");
	int closed = 0;
	for (int i = 0; i < TC_TCP_BACKLOG + 4; i++)
		if (tc_tcp_get_state(ca[i]) == TC_TCP_CLOSED)
			closed++;
	TCT_EQ_INT(closed, 4);

	link_done(&l);
}

/* ---- reaping and TIME_WAIT --------------------------------------------- */

static void test_reap_keeps_time_wait(void)
{
	TCT_CASE("reap frees closed connections but keeps TIME_WAIT");
	link_t l;
	link_init(&l, 11);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	tc_tcp_conn *ca = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &ca), TC_OK);
	uint16_t port = tc_tcp_local_port(ca);
	for (int i = 0; i < 200 && !tc_tcp_is_established(ca); i++)
		link_step(&l);
	tc_tcp_conn *cb = tc_tcp_mux_accept(l.b);
	TCT_TRUE(cb != NULL);

	/* Close from A, so A ends in TIME_WAIT. */
	tc_tcp_shutdown_write(ca, l.now);
	for (int i = 0; i < 400; i++) {
		if (tc_tcp_read_closed(cb))
			tc_tcp_shutdown_write(cb, l.now);
		link_step(&l);
		if (tc_tcp_get_state(ca) == TC_TCP_TIME_WAIT)
			break;
	}
	TCT_EQ_INT(tc_tcp_get_state(ca), TC_TCP_TIME_WAIT);

	/* A reap now must not take it: its job is to absorb a late FIN. */
	TCT_EQ_INT((int)tc_tcp_mux_reap(l.a), 0);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.a), 1);

	TCT_CASE("a port held in TIME_WAIT is not handed out again");
	tc_tcp_conn *c2 = NULL;
	for (int i = 0; i < 40; i++) {
		TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &c2), TC_OK);
		if (tc_tcp_local_port(c2) == port)
			TCT_FAILF("reused a port still in TIME_WAIT");
		tc_tcp_mux_close(l.a, c2, l.now);
	}
	tct_checks++;

	TCT_CASE("TIME_WAIT expires and is then reaped");
	uint64_t limit = l.now + 300000;
	while (l.now < limit && tc_tcp_get_state(ca) != TC_TCP_CLOSED)
		link_step(&l);
	TCT_EQ_INT(tc_tcp_get_state(ca), TC_TCP_CLOSED);
	TCT_EQ_INT((int)tc_tcp_mux_reap(l.a), 1);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.a), 0);

	link_done(&l);
}

static void test_dropping_an_unaccepted_connection(void)
{
	TCT_CASE("a connection reset before it is accepted leaves no dangling "
	         "entry in the accept queue");
	/* The window is real: a SYN is queued, the peer resets it, the loop
	 * reaps, and only then does the application get round to accepting. If
	 * reaping does not also unqueue, accept hands back freed memory. */
	link_t l;
	link_init(&l, 23);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	tc_tcp_conn *ca = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &ca), TC_OK);
	for (int i = 0; i < 200 && tc_tcp_mux_pending(l.b) == 0; i++)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 1);

	/* The dialer gives up and resets, without B ever accepting. */
	tc_tcp_mux_close(l.a, ca, l.now);
	for (int i = 0; i < 200; i++) {
		link_step(&l);
		if (tc_tcp_get_state(tc_tcp_mux_at(l.b, 0)) == TC_TCP_CLOSED)
			break;
	}
	TCT_EQ_INT(tc_tcp_get_state(tc_tcp_mux_at(l.b, 0)), TC_TCP_CLOSED);

	TCT_EQ_INT((int)tc_tcp_mux_reap(l.b), 1);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.b), 0);
	/* The reap must have taken it out of the queue as well. */
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 0);
	TCT_TRUE(tc_tcp_mux_accept(l.b) == NULL);

	TCT_CASE("closing an unaccepted connection unqueues it too");
	tc_tcp_conn *ca2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &ca2), TC_OK);
	for (int i = 0; i < 200 && tc_tcp_mux_pending(l.b) == 0; i++)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 1);
	tc_tcp_mux_close(l.b, tc_tcp_mux_at(l.b, 0), l.now);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 0);
	TCT_TRUE(tc_tcp_mux_accept(l.b) == NULL);

	TCT_CASE("freeing the mux with a connection still queued is clean");
	/* ASan checks this one: nothing here may be freed twice. */
	tc_tcp_conn *ca3 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &ca3), TC_OK);
	for (int i = 0; i < 200 && tc_tcp_mux_pending(l.b) == 0; i++)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 1);

	link_done(&l);
}

static void test_time_wait_port_reuse(void)
{
	TCT_CASE("a peer reusing a port pair in TIME_WAIT is let through");
	/* The straggler a TIME_WAIT guards against carries an ACK; a bare SYN is
	 * the peer genuinely reopening. Refusing it would hang the new
	 * connection for the whole TIME_WAIT. */
	link_t l;
	link_init(&l, 13);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	tc_tcp_conn *ca = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect_from(l.a, 50000, 7, l.now, &ca), TC_OK);
	for (int i = 0; i < 200 && !tc_tcp_is_established(ca); i++)
		link_step(&l);
	tc_tcp_conn *cb = tc_tcp_mux_accept(l.b);
	TCT_TRUE(cb != NULL);
	/* A connection is accepted in SYN_RECEIVED, so let its own handshake
	 * finish: tc_tcp_shutdown_write refuses before ESTABLISHED. */
	for (int i = 0; i < 200 && !tc_tcp_is_established(cb); i++)
		link_step(&l);
	TCT_TRUE(tc_tcp_is_established(cb));

	/* Close from B, so B ends in TIME_WAIT holding (7, 50000). */
	TCT_EQ_INT(tc_tcp_shutdown_write(cb, l.now), TC_OK);
	for (int i = 0; i < 400; i++) {
		if (tc_tcp_read_closed(ca))
			tc_tcp_shutdown_write(ca, l.now);
		link_step(&l);
		if (tc_tcp_get_state(cb) == TC_TCP_TIME_WAIT)
			break;
	}
	TCT_EQ_INT(tc_tcp_get_state(cb), TC_TCP_TIME_WAIT);

	/* A is in LAST_ACK at the moment B reaches TIME_WAIT; let it finish so
	 * its own end of the pair is genuinely free. */
	for (int i = 0; i < 200 && tc_tcp_get_state(ca) != TC_TCP_CLOSED; i++)
		link_step(&l);
	TCT_EQ_INT(tc_tcp_get_state(ca), TC_TCP_CLOSED);

	/* A dials the same pair again. */
	TCT_EQ_INT((int)tc_tcp_mux_reap(l.a), 1);
	tc_tcp_conn *ca2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect_from(l.a, 50000, 7, l.now, &ca2), TC_OK);
	for (int i = 0; i < 400 && !tc_tcp_is_established(ca2); i++)
		link_step(&l);
	TCT_TRUE(tc_tcp_is_established(ca2));

	tc_tcp_conn *cb2 = tc_tcp_mux_accept(l.b);
	TCT_TRUE(cb2 != NULL);
	TCT_EQ_INT(tc_tcp_remote_port(cb2), 50000);

	uint8_t msg[] = "second time";
	size_t wrote = 0;
	tc_tcp_write(ca2, msg, sizeof msg, &wrote, l.now);
	for (int i = 0; i < 300 && tc_tcp_readable(cb2) < sizeof msg; i++)
		link_step(&l);
	uint8_t got[32];
	size_t n = 0;
	TCT_EQ_INT(tc_tcp_read(cb2, got, sizeof got, &n), TC_OK);
	TCT_EQ_INT((int)n, (int)sizeof msg);
	TCT_EQ_MEM(got, msg, sizeof msg);

	link_done(&l);
}

/* ---- dispatch details --------------------------------------------------- */

static void test_ignores_foreign_packets(void)
{
	TCT_CASE("a packet from another address is ignored, not reset");
	/* Answering it would send a reset naming an address that is not ours. */
	link_t l;
	link_init(&l, 17);
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 7), TC_OK);

	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN];
	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x60;
	pkt[4] = 0;
	pkt[5] = TC_TCP_HEADER_LEN;
	pkt[6] = 6;
	pkt[7] = 64;
	static const uint8_t kElsewhere[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
		                                    0,    0, 0, 0, 0, 0, 0, 9 };
	memcpy(pkt + 8, kElsewhere, 16);
	memcpy(pkt + 24, kIpB, 16);
	pkt[TC_IPV6_HEADER_LEN + 2] = 0;
	pkt[TC_IPV6_HEADER_LEN + 3] = 7;
	pkt[TC_IPV6_HEADER_LEN + 12] = 5 << 4;
	pkt[TC_IPV6_HEADER_LEN + 13] = 0x02; /* SYN */

	uint64_t before = l.counter;
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, sizeof pkt, l.now), TC_OK);
	TCT_EQ_INT((int)(l.counter - before), 0);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.b), 0);

	TCT_CASE("truncated and non-TCP packets are ignored");
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, 10, l.now), TC_OK);
	memcpy(pkt + 8, kIpA, 16);
	pkt[6] = 17; /* UDP */
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, sizeof pkt, l.now), TC_OK);
	pkt[6] = 6;
	pkt[0] = 0x40; /* IPv4 */
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, sizeof pkt, l.now), TC_OK);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.b), 0);

	TCT_CASE("a SYN-ACK for no connection draws a reset, not an accept");
	/* Only a bare SYN opens a connection: anything else is a stray. */
	pkt[0] = 0x60;
	pkt[TC_IPV6_HEADER_LEN + 13] = 0x12; /* SYN|ACK */
	before = l.counter;
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, sizeof pkt, l.now), TC_OK);
	TCT_EQ_INT((int)(l.counter - before), 1);
	TCT_EQ_INT((int)tc_tcp_mux_count(l.b), 0);

	TCT_CASE("a stray reset is swallowed");
	pkt[TC_IPV6_HEADER_LEN + 13] = 0x04; /* RST */
	before = l.counter;
	TCT_EQ_INT(tc_tcp_mux_input(l.b, pkt, sizeof pkt, l.now), TC_OK);
	TCT_EQ_INT((int)(l.counter - before), 0);

	TCT_CASE("null arguments are refused");
	TCT_EQ_INT(tc_tcp_mux_input(NULL, pkt, sizeof pkt, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_tcp_mux_input(l.b, NULL, 10, 0), TC_ERR_INVAL);
	TCT_TRUE(tc_tcp_mux_accept(NULL) == NULL);
	TCT_TRUE(tc_tcp_mux_at(l.b, 0) == NULL);
	TCT_EQ_INT((int)tc_tcp_mux_reap(NULL), 0);
	TCT_TRUE(tc_tcp_mux_new(NULL, kIpB, sink_out, NULL) == NULL);
	TCT_TRUE(tc_tcp_mux_new(kIpA, kIpB, NULL, NULL) == NULL);
	tc_tcp_mux_free(NULL);

	link_done(&l);
}

static void test_same_port_pair_is_refused(void)
{
	TCT_CASE("two connections may not share a port pair");
	tc_tcp_mux *m = tc_tcp_mux_new(kIpA, kIpB, sink_out, NULL);
	tc_tcp_conn *c1 = NULL, *c2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect_from(m, 50000, 7, 0, &c1), TC_OK);
	TCT_EQ_INT(tc_tcp_mux_connect_from(m, 50000, 7, 0, &c2), TC_ERR_EXIST);
	TCT_TRUE(c2 == NULL);
	TCT_EQ_INT(tc_tcp_mux_connect_from(m, 0, 7, 0, &c2), TC_ERR_INVAL);
	TCT_EQ_INT(tc_tcp_mux_connect_from(m, 50000, 0, 0, &c2), TC_ERR_INVAL);
	TCT_EQ_INT((int)tc_tcp_mux_count(m), 1);
	tc_tcp_mux_free(m);
}

/* ---- the accept filter -------------------------------------------------- */

static bool only_even(void *ctx, uint16_t port)
{
	(void)ctx;
	return (port % 2u) == 0u;
}

static bool accept_everything(void *ctx, uint16_t port)
{
	(void)ctx;
	(void)port;
	return true;
}

static void test_accept_filter(void)
{
	TCT_CASE("a filter can accept ports no listener array could hold");
	/* `serve all` is 65,535 ports. The point of the filter is that the
	 * caller keeps the set in whatever shape suits it. */
	link_t l;
	link_init(&l, 41);
	tc_tcp_mux_set_accept_filter(l.b, accept_everything, NULL);

	tc_tcp_conn *c1 = NULL, *c2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 8080, l.now, &c1), TC_OK);
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 65535, l.now, &c2), TC_OK);
	for (int i = 0; i < 300 && tc_tcp_mux_pending(l.b) < 2; i++)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 2);

	link_done(&l);

	TCT_CASE("a filter that refuses a port draws a reset, as before");
	link_init(&l, 43);
	tc_tcp_mux_set_accept_filter(l.b, only_even, NULL);

	tc_tcp_conn *odd = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 81, l.now, &odd), TC_OK);
	for (int i = 0; i < 300; i++) {
		if (tc_tcp_get_state(odd) == TC_TCP_CLOSED)
			break;
		link_step(&l);
	}
	TCT_EQ_INT(tc_tcp_get_state(odd), TC_TCP_CLOSED);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 0);

	tc_tcp_mux_stats st;
	tc_tcp_mux_get_stats(l.b, &st);
	TCT_EQ_INT((int)st.rejected_port, 1);

	TCT_CASE("an explicit listener still works alongside a filter");
	/* The filter widens; it must never be able to close a port the caller
	 * believes it is listening on. */
	TCT_EQ_INT(tc_tcp_mux_listen(l.b, 81), TC_OK);
	TCT_TRUE(tc_tcp_mux_is_listening(l.b, 81));
	tc_tcp_conn *odd2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 81, l.now, &odd2), TC_OK);
	for (int i = 0; i < 300 && tc_tcp_mux_pending(l.b) == 0; i++)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_mux_pending(l.b), 1);

	TCT_CASE("port 0 is never accepted, whatever the filter says");
	TCT_TRUE(!tc_tcp_mux_is_listening(l.b, 0));

	link_done(&l);
}

int main(void)
{
	test_concurrent_streams(0, 0, 1, "many streams at once on a clean link");
	test_concurrent_streams(0, 20, 2, "many streams at once, reordered");
	test_concurrent_streams(8, 10, 3, "many streams at once, lossy and reordered");
	test_closed_port_is_refused();
	test_listeners();
	test_table_limit();
	test_backlog_limit();
	test_reap_keeps_time_wait();
	test_dropping_an_unaccepted_connection();
	test_time_wait_port_reuse();
	test_ignores_foreign_packets();
	test_same_port_pair_is_refused();
	test_accept_filter();
	return tct_report("tcpmux");
}
