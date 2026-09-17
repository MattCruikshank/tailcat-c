/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Userspace TCP tests.
 *
 * There is no reference implementation to diff against here, so these work a
 * different way: two of our own stacks are connected through a simulated link
 * that can lose, duplicate, reorder and delay packets, and the test asserts
 * that a known byte stream arrives intact regardless. A stack that is subtly
 * wrong about sequence arithmetic, retransmission or reassembly cannot
 * deliver megabytes through a 10%-loss link unchanged.
 *
 * The clock is supplied by the test, so all of this runs in microseconds with
 * no real timers and no network.
 */

#include "tc/tcp.h"

#include "tctest.h"

#include <stdlib.h>

/* ---- simulated link --------------------------------------------------- */

#define LINK_MAXPKT 1400
#define LINK_QUEUE 512

typedef struct {
	uint8_t data[LINK_MAXPKT];
	size_t len;
	bool to_b;     /* direction */
	uint64_t at;   /* delivery time */
	bool used;
	uint64_t seqno; /* for stable ordering of equal times */
} link_pkt;

typedef struct {
	tc_tcp_conn *a, *b;
	link_pkt q[LINK_QUEUE];
	uint64_t now;
	uint64_t counter;

	/* Impairments, as percentages. */
	unsigned loss_pct;
	unsigned dup_pct;
	unsigned reorder_pct;
	uint32_t latency_ms;

	uint64_t rng;
	uint64_t dropped;
	uint64_t delivered;
	bool overflow;
} link_t;

static uint32_t lrand(link_t *l)
{
	/* xorshift64*, so a failing run can be reproduced from its seed. */
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

static void link_enqueue(link_t *l, const uint8_t *p, size_t n, bool to_b,
                         uint64_t delay)
{
	for (size_t i = 0; i < LINK_QUEUE; i++) {
		if (l->q[i].used)
			continue;
		memcpy(l->q[i].data, p, n);
		l->q[i].len = n;
		l->q[i].to_b = to_b;
		l->q[i].at = l->now + delay;
		l->q[i].used = true;
		l->q[i].seqno = l->counter++;
		return;
	}
	l->overflow = true;
}

static int link_out(link_t *l, const uint8_t *p, size_t n, bool to_b)
{
	if (n > LINK_MAXPKT) {
		/* A segment larger than the link can carry is a bug in the stack:
		 * it must never exceed the MSS it was told about. */
		l->overflow = true;
		return TC_OK;
	}
	if (chance(l, l->loss_pct)) {
		l->dropped++;
		return TC_OK;
	}

	uint64_t delay = l->latency_ms;
	if (chance(l, l->reorder_pct))
		delay += 5 + lrand(l) % 25; /* arrive late, behind later packets */

	link_enqueue(l, p, n, to_b, delay);
	if (chance(l, l->dup_pct))
		link_enqueue(l, p, n, to_b, delay + 1);
	return TC_OK;
}

/* The last packet A sent. Its acknowledgement field is A's rcv_nxt, which is
 * how the probe test below learns a sequence number it cannot otherwise see
 * without reaching into the connection. */
static uint8_t last_from_a[LINK_MAXPKT];
static size_t last_from_a_len;

static int out_a(void *ctx, const uint8_t *p, size_t n)
{
	if (n <= sizeof last_from_a) {
		memcpy(last_from_a, p, n);
		last_from_a_len = n;
	}
	return link_out((link_t *)ctx, p, n, true);
}

static int out_b(void *ctx, const uint8_t *p, size_t n)
{
	return link_out((link_t *)ctx, p, n, false);
}

/* link_step advances to the next event and delivers whatever is due. */
static void link_step(link_t *l)
{
	/* The next interesting moment is either a packet arriving or a timer
	 * firing. Jumping straight there keeps a multi-second test instant. */
	uint64_t next = UINT64_MAX;
	for (size_t i = 0; i < LINK_QUEUE; i++)
		if (l->q[i].used && l->q[i].at < next)
			next = l->q[i].at;

	uint64_t da = tc_tcp_next_deadline(l->a);
	uint64_t db = tc_tcp_next_deadline(l->b);
	if (da < next)
		next = da;
	if (db < next)
		next = db;

	if (next == UINT64_MAX)
		next = l->now + 10; /* nothing pending; nudge the clock */
	if (next < l->now)
		next = l->now;
	l->now = next;

	/* Deliver everything due, oldest first so duplicates keep their order. */
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
		l->delivered++;
		tc_tcp_conn *dst = l->q[best].to_b ? l->b : l->a;
		tc_tcp_input(dst, l->q[best].data, l->q[best].len, l->now);
	}

	tc_tcp_tick(l->a, l->now);
	tc_tcp_tick(l->b, l->now);
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
	l->a = tc_tcp_new(kIpA, kIpB, out_a, l);
	l->b = tc_tcp_new(kIpB, kIpA, out_b, l);
}

static void link_done(link_t *l)
{
	tc_tcp_free(l->a);
	tc_tcp_free(l->b);
}

/* establish runs listen/connect to completion. */
static bool establish(link_t *l)
{
	tc_tcp_listen(l->b, 1);
	tc_tcp_connect(l->a, 40000, 1, l->now);
	for (int i = 0; i < 2000; i++) {
		if (tc_tcp_is_established(l->a) && tc_tcp_is_established(l->b))
			return true;
		link_step(l);
	}
	return false;
}

/* ---- tests ------------------------------------------------------------ */

static void test_handshake(void)
{
	TCT_CASE("three-way handshake establishes both ends");
	link_t l;
	link_init(&l, 1);
	TCT_TRUE(establish(&l));
	TCT_EQ_INT(tc_tcp_get_state(l.a), TC_TCP_ESTABLISHED);
	TCT_EQ_INT(tc_tcp_get_state(l.b), TC_TCP_ESTABLISHED);
	link_done(&l);
}

/* transfer sends `total` bytes from `from` to `to` and checks every byte. */
static bool transfer(link_t *l, tc_tcp_conn *from, tc_tcp_conn *to,
                     size_t total, uint32_t pattern_seed)
{
	size_t sent = 0, got = 0;
	uint32_t wr = pattern_seed, rd = pattern_seed;
	bool mismatch = false;

	for (int step = 0; step < 400000 && got < total; step++) {
		/* Write as much as the send buffer will take. */
		while (sent < total) {
			uint8_t chunk[4096];
			size_t want = total - sent;
			if (want > sizeof chunk)
				want = sizeof chunk;
			size_t room = tc_tcp_writable(from);
			if (room == 0)
				break;
			if (want > room)
				want = room;
			for (size_t i = 0; i < want; i++) {
				wr = wr * 1664525u + 1013904223u;
				chunk[i] = (uint8_t)(wr >> 24);
			}
			size_t w = 0;
			tc_tcp_write(from, chunk, want, &w, l->now);
			sent += w;
			if (w == 0)
				break;
		}

		/* Drain whatever has arrived, verifying the pattern. */
		for (;;) {
			uint8_t chunk[4096];
			size_t n = 0;
			tc_tcp_read(to, chunk, sizeof chunk, &n);
			if (n == 0)
				break;
			for (size_t i = 0; i < n; i++) {
				rd = rd * 1664525u + 1013904223u;
				if (chunk[i] != (uint8_t)(rd >> 24))
					mismatch = true;
			}
			got += n;
		}

		link_step(l);
	}

	if (mismatch || got != total || l->overflow) {
		tc_tcp_stats sf, st;
		tc_tcp_get_stats(from, &sf);
		tc_tcp_get_stats(to, &st);
		fprintf(stderr,
		        "  transfer: sent=%zu got=%zu/%zu mismatch=%d overflow=%d\n"
		        "    from: %s unacked=%zu writable=%zu segs=%llu rexmit=%llu\n"
		        "    to:   %s readable=%zu segs=%llu ooo_q=%llu ooo_drop=%llu\n",
		        sent, got, total, (int)mismatch, (int)l->overflow,
		        tc_tcp_state_name(tc_tcp_get_state(from)),
		        tc_tcp_send_unacked(from), tc_tcp_writable(from),
		        (unsigned long long)sf.segs_sent,
		        (unsigned long long)sf.retransmits,
		        tc_tcp_state_name(tc_tcp_get_state(to)), tc_tcp_readable(to),
		        (unsigned long long)st.segs_received,
		        (unsigned long long)st.ooo_queued,
		        (unsigned long long)st.ooo_dropped);
		return false;
	}
	return true;
}

static void test_data_both_ways(void)
{
	TCT_CASE("data flows in both directions");
	link_t l;
	link_init(&l, 2);
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 40000, 0xabcd));
	TCT_TRUE(transfer(&l, l.b, l.a, 40000, 0x1234));
	link_done(&l);
}

static void test_large_transfer(void)
{
	TCT_CASE("a transfer larger than the buffers completes");
	/* Exercises the send-buffer ring wrapping and the window opening and
	 * closing repeatedly. */
	link_t l;
	link_init(&l, 3);
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 1u * 1024u * 1024u, 0x5555));
	link_done(&l);
}

static void test_lossy_link(void)
{
	TCT_CASE("10% packet loss still delivers the stream intact");
	link_t l;
	link_init(&l, 4);
	l.loss_pct = 10;
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 256u * 1024u, 0x9999));

	tc_tcp_stats st;
	tc_tcp_get_stats(l.a, &st);
	/* Loss must actually have happened and been recovered from. */
	TCT_TRUE(l.dropped > 0);
	TCT_TRUE(st.retransmits > 0);
	link_done(&l);
}

static void test_reordering(void)
{
	TCT_CASE("reordering is reassembled");
	link_t l;
	link_init(&l, 5);
	l.reorder_pct = 25;
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 256u * 1024u, 0x7777));

	tc_tcp_stats st;
	tc_tcp_get_stats(l.b, &st);
	TCT_TRUE(st.ooo_queued > 0);
	link_done(&l);
}

static void test_duplication(void)
{
	TCT_CASE("duplicated packets do not corrupt the stream");
	link_t l;
	link_init(&l, 6);
	l.dup_pct = 20;
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 128u * 1024u, 0x3333));
	link_done(&l);
}

static void test_hostile_link(void)
{
	TCT_CASE("loss, duplication and reordering together");
	link_t l;
	link_init(&l, 7);
	l.loss_pct = 8;
	l.dup_pct = 8;
	l.reorder_pct = 20;
	l.latency_ms = 20;
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 256u * 1024u, 0x2468));
	link_done(&l);
}

static void test_half_close(void)
{
	TCT_CASE("half close lets the other direction keep flowing");
	/* This is what piping stdin to a peer and then waiting for its reply
	 * needs: our write side closes, theirs does not. */
	link_t l;
	link_init(&l, 8);
	TCT_TRUE(establish(&l));

	static const char kMsg[] = "request";
	size_t w = 0;
	tc_tcp_write(l.a, kMsg, sizeof kMsg - 1, &w, l.now);
	TCT_EQ_INT(w, sizeof kMsg - 1);
	tc_tcp_shutdown_write(l.a, l.now);

	/* B should see the data, then end of stream. */
	char got[64];
	size_t total = 0;
	for (int i = 0; i < 2000 && !tc_tcp_read_closed(l.b); i++) {
		size_t n = 0;
		tc_tcp_read(l.b, got + total, sizeof got - total, &n);
		total += n;
		link_step(&l);
	}
	TCT_TRUE(tc_tcp_read_closed(l.b));
	TCT_EQ_INT(total, sizeof kMsg - 1);
	TCT_EQ_MEM(got, kMsg, sizeof kMsg - 1);

	TCT_CASE("and B can still reply after A has closed its write side");
	TCT_EQ_INT(tc_tcp_get_state(l.b), TC_TCP_CLOSE_WAIT);
	static const char kReply[] = "response";
	tc_tcp_write(l.b, kReply, sizeof kReply - 1, &w, l.now);
	TCT_EQ_INT(w, sizeof kReply - 1);

	char back[64];
	size_t back_total = 0;
	for (int i = 0; i < 2000 && back_total < sizeof kReply - 1; i++) {
		size_t n = 0;
		tc_tcp_read(l.a, back + back_total, sizeof back - back_total, &n);
		back_total += n;
		link_step(&l);
	}
	TCT_EQ_INT(back_total, sizeof kReply - 1);
	TCT_EQ_MEM(back, kReply, sizeof kReply - 1);
	link_done(&l);
}

static void test_full_close(void)
{
	TCT_CASE("both sides close cleanly");
	link_t l;
	link_init(&l, 9);
	TCT_TRUE(establish(&l));

	tc_tcp_shutdown_write(l.a, l.now);
	for (int i = 0; i < 2000 && !tc_tcp_read_closed(l.b); i++)
		link_step(&l);
	TCT_TRUE(tc_tcp_read_closed(l.b));

	tc_tcp_shutdown_write(l.b, l.now);
	for (int i = 0; i < 5000; i++) {
		if (tc_tcp_get_state(l.a) == TC_TCP_CLOSED &&
		    tc_tcp_get_state(l.b) == TC_TCP_CLOSED)
			break;
		link_step(&l);
	}
	TCT_EQ_INT(tc_tcp_get_state(l.b), TC_TCP_CLOSED);
	/* A goes through TIME_WAIT before CLOSED. */
	TCT_TRUE(tc_tcp_get_state(l.a) == TC_TCP_CLOSED ||
	         tc_tcp_get_state(l.a) == TC_TCP_TIME_WAIT);
	link_done(&l);
}

static void test_sequence_wrap(void)
{
	TCT_CASE("a transfer across the sequence wrap is intact");
	/* Sequence numbers wrap at 2^32. Every comparison has to stay correct
	 * across it, and the only way to reach the wrap without moving four
	 * gigabytes is to start just below it. */
	link_t l;
	link_init(&l, 10);
	tc_tcp_force_next_iss(0xfffff000u);
	tc_tcp_listen(l.b, 1);
	tc_tcp_connect(l.a, 40000, 1, l.now);
	for (int i = 0; i < 2000; i++) {
		if (tc_tcp_is_established(l.a) && tc_tcp_is_established(l.b))
			break;
		link_step(&l);
	}
	TCT_TRUE(tc_tcp_is_established(l.a));

	/* Well past 0xffffffff, so the send sequence wraps mid-stream. */
	TCT_TRUE(transfer(&l, l.a, l.b, 256u * 1024u, 0xbeef));
	link_done(&l);
}

static void test_wrap_with_loss(void)
{
	TCT_CASE("the wrap survives retransmission too");
	link_t l;
	link_init(&l, 11);
	l.loss_pct = 10;
	tc_tcp_force_next_iss(0xffffe000u);
	tc_tcp_listen(l.b, 1);
	tc_tcp_connect(l.a, 40000, 1, l.now);
	for (int i = 0; i < 4000; i++) {
		if (tc_tcp_is_established(l.a) && tc_tcp_is_established(l.b))
			break;
		link_step(&l);
	}
	TCT_TRUE(tc_tcp_is_established(l.a));
	TCT_TRUE(transfer(&l, l.a, l.b, 192u * 1024u, 0xf00d));
	link_done(&l);
}

static void test_rejects_bad_packets(void)
{
	link_t l;
	link_init(&l, 12);
	TCT_TRUE(establish(&l));

	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN];
	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x60;
	pkt[4] = 0;
	pkt[5] = TC_TCP_HEADER_LEN;
	pkt[6] = 6;
	pkt[7] = 64;
	memcpy(pkt + 8, kIpB, 16);
	memcpy(pkt + 24, kIpA, 16);
	uint8_t *th = pkt + TC_IPV6_HEADER_LEN;
	th[0] = 0;
	th[1] = 1; /* src port 1 */
	th[2] = (uint8_t)(40000 >> 8);
	th[3] = (uint8_t)40000;
	th[12] = 5 << 4;
	th[13] = 0x10; /* ACK */

	tc_tcp_stats before, after;
	tc_tcp_get_stats(l.a, &before);

	TCT_CASE("a bad checksum is dropped");
	/* The checksum field is left zero, which is essentially never right. */
	tc_tcp_input(l.a, pkt, sizeof pkt, l.now);
	tc_tcp_get_stats(l.a, &after);
	TCT_TRUE(after.segs_dropped_checksum > before.segs_dropped_checksum);

	TCT_CASE("a packet for another address is ignored");
	uint8_t other[TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN];
	memcpy(other, pkt, sizeof other);
	other[8] ^= 0xff; /* wrong source address */
	tc_tcp_get_stats(l.a, &before);
	tc_tcp_input(l.a, other, sizeof other, l.now);
	tc_tcp_get_stats(l.a, &after);
	TCT_EQ_INT(after.segs_received, before.segs_received);

	TCT_CASE("a non-TCP packet is ignored");
	memcpy(other, pkt, sizeof other);
	other[6] = 17; /* UDP */
	tc_tcp_get_stats(l.a, &before);
	tc_tcp_input(l.a, other, sizeof other, l.now);
	tc_tcp_get_stats(l.a, &after);
	TCT_EQ_INT(after.segs_received, before.segs_received);

	TCT_CASE("a truncated packet is ignored");
	TCT_EQ_INT(tc_tcp_input(l.a, pkt, 10, l.now), TC_OK);

	TCT_CASE("the connection still works afterwards");
	TCT_TRUE(transfer(&l, l.a, l.b, 8192, 0x4242));
	link_done(&l);
}

static void test_flow_control(void)
{
	TCT_CASE("a stalled reader stops the sender");
	/* B never reads, so its window closes and A must stop rather than
	 * overrun it. */
	link_t l;
	link_init(&l, 13);
	TCT_TRUE(establish(&l));

	size_t sent = 0;
	static uint8_t chunk[4096];
	memset(chunk, 0x5a, sizeof chunk);
	for (int i = 0; i < 4000; i++) {
		size_t w = 0;
		tc_tcp_write(l.a, chunk, sizeof chunk, &w, l.now);
		sent += w;
		link_step(&l);
	}

	/* Everything A managed to send must be sitting in B's receive buffer,
	 * bounded by it -- not lost, and not unbounded. */
	TCT_TRUE(sent > 0);
	TCT_TRUE(tc_tcp_readable(l.b) <= TC_TCP_RCVBUF);
	TCT_TRUE(!l.overflow);

	TCT_CASE("and it resumes once the reader drains");
	size_t drained = 0;
	for (int i = 0; i < 20000; i++) {
		uint8_t out[4096];
		size_t n = 0;
		tc_tcp_read(l.b, out, sizeof out, &n);
		drained += n;
		size_t w = 0;
		tc_tcp_write(l.a, chunk, sizeof chunk, &w, l.now);
		sent += w;
		link_step(&l);
	}
	TCT_TRUE(drained > TC_TCP_RCVBUF);
	link_done(&l);
}

static void test_reset(void)
{
	TCT_CASE("an abort resets the peer");
	link_t l;
	link_init(&l, 14);
	TCT_TRUE(establish(&l));
	tc_tcp_abort(l.a, l.now);
	TCT_EQ_INT(tc_tcp_get_state(l.a), TC_TCP_CLOSED);
	for (int i = 0; i < 200 && tc_tcp_get_state(l.b) != TC_TCP_CLOSED; i++)
		link_step(&l);
	TCT_EQ_INT(tc_tcp_get_state(l.b), TC_TCP_CLOSED);
	link_done(&l);
}

static void test_segment_size(void)
{
	TCT_CASE("no segment exceeds the link MTU");
	/* The overflow flag is set by the link if a packet is larger than it can
	 * carry, which would mean fragmenting inside the tunnel. */
	link_t l;
	link_init(&l, 15);
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.a, l.b, 128u * 1024u, 0x1111));
	TCT_TRUE(!l.overflow);
	link_done(&l);
}

/* Idle detection.
 *
 * An established connection with nothing to send has no retransmission timer,
 * so nothing at all was watching it: a peer that vanished left this side
 * ESTABLISHED for ever, and with a sixty-four entry table that is a listener
 * that eventually stops answering. The fix probes rather than simply timing
 * out, and both halves of that matter -- so both are checked here. Getting
 * only the second right would be a stack that drops every quiet session.
 *
 * The first case also covers a smaller fix it depends on: a probe carries no
 * new data, and our receive path used to answer only segments that carried
 * some. Without that, every probe goes unanswered and this case fails. */
static void test_idle_detection(void)
{
	TCT_CASE("an idle connection survives while the peer answers");
	link_t l;
	link_init(&l, 99);
	TCT_TRUE(establish(&l));

	/* Many times longer than the whole probe sequence takes to give up, with
	 * the link carrying nothing but what the two stacks generate. */
	uint64_t span = TC_TCP_KEEPALIVE_IDLE_MS +
	                TC_TCP_KEEPALIVE_PROBES * TC_TCP_KEEPALIVE_INTVL_MS;
	uint64_t until = l.now + 10 * span;
	/* Bounded by steps as well as by the clock. A regression that stops the
	 * virtual clock advancing -- a deadline reported but never acted on, say
	 * -- would otherwise hang here instead of failing. */
	int steps = 0;
	while (l.now < until && steps++ < 200000)
		link_step(&l);
	TCT_TRUE(l.now >= until);
	TCT_TRUE(tc_tcp_is_established(l.a));
	TCT_TRUE(tc_tcp_is_established(l.b));

	TCT_CASE("a short silence is not fatal on its own");
	uint64_t vanished = l.now;
	l.loss_pct = 100; /* the peer is gone: nothing more gets through */
	steps = 0;
	while (l.now < vanished + TC_TCP_KEEPALIVE_IDLE_MS && steps++ < 200000)
		link_step(&l);
	TCT_TRUE(tc_tcp_is_established(l.a));

	TCT_CASE("but a peer that never answers is given up on");
	uint64_t giveup = vanished + span + TC_TCP_KEEPALIVE_INTVL_MS;
	steps = 0;
	while (l.now < giveup && tc_tcp_get_state(l.a) != TC_TCP_CLOSED &&
	       steps++ < 200000)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_get_state(l.a), (int)TC_TCP_CLOSED);

	link_done(&l);
}

/* An independent TCP checksum over the IPv6 pseudo-header, so the probe built
 * below does not borrow the implementation's own arithmetic to prove a point
 * about the implementation. */
static uint16_t tcp_ck(const uint8_t *src, const uint8_t *dst,
                       const uint8_t *seg, size_t n)
{
	uint32_t sum = 0;
	for (size_t i = 0; i < 16; i += 2)
		sum += (uint32_t)src[i] << 8 | src[i + 1];
	for (size_t i = 0; i < 16; i += 2)
		sum += (uint32_t)dst[i] << 8 | dst[i + 1];
	sum += (uint32_t)(n >> 16) & 0xffffu;
	sum += (uint32_t)n & 0xffffu;
	sum += 6; /* next header: TCP */
	for (size_t i = 0; i + 1 < n; i += 2)
		sum += (uint32_t)seg[i] << 8 | seg[i + 1];
	if (n & 1)
		sum += (uint32_t)seg[n - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffffu) + (sum >> 16);
	return (uint16_t)~sum;
}

/* A keepalive probe carries a sequence number one before the next, and most
 * stacks -- a Linux kernel at the other end of the tunnel, for one -- send it
 * with no payload at all. RFC 793 calls such a segment unacceptable and asks
 * for an acknowledgement in reply.
 *
 * Our own probes carry a garbage octet, so they are answered by the path that
 * re-acknowledges old *data* and this case never arose in a tailcat-to-tailcat
 * test. A peer that omits the octet got silence, decided we were gone, and
 * reset a working connection. Hence a test that builds the segment by hand.
 */
static void test_answers_a_zero_length_probe(void)
{
	TCT_CASE("a zero-length segment before rcv_nxt draws an acknowledgement");
	link_t l;
	link_init(&l, 77);
	TCT_TRUE(establish(&l));
	TCT_TRUE(transfer(&l, l.b, l.a, 4096, 0x1234));
	for (int i = 0; i < 20; i++)
		link_step(&l);
	TCT_TRUE(last_from_a_len >= TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN);

	/* A's acknowledgement field is its rcv_nxt, which is the one number this
	 * segment has to get right. */
	const uint8_t *ath = last_from_a + TC_IPV6_HEADER_LEN;
	uint32_t rcv_nxt = (uint32_t)ath[8] << 24 | (uint32_t)ath[9] << 16 |
	                   (uint32_t)ath[10] << 8 | ath[11];
	uint16_t a_port = (uint16_t)((uint16_t)ath[0] << 8 | ath[1]);
	uint16_t b_port = (uint16_t)((uint16_t)ath[2] << 8 | ath[3]);
	uint32_t probe_seq = rcv_nxt - 1;

	uint8_t pkt[TC_IPV6_HEADER_LEN + TC_TCP_HEADER_LEN];
	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x60;
	pkt[4] = 0;
	pkt[5] = TC_TCP_HEADER_LEN;
	pkt[6] = 6;
	pkt[7] = 64;
	memcpy(pkt + 8, kIpB, 16);
	memcpy(pkt + 24, kIpA, 16);
	uint8_t *th = pkt + TC_IPV6_HEADER_LEN;
	th[0] = (uint8_t)(b_port >> 8);
	th[1] = (uint8_t)b_port;
	th[2] = (uint8_t)(a_port >> 8);
	th[3] = (uint8_t)a_port;
	th[4] = (uint8_t)(probe_seq >> 24);
	th[5] = (uint8_t)(probe_seq >> 16);
	th[6] = (uint8_t)(probe_seq >> 8);
	th[7] = (uint8_t)probe_seq;
	memcpy(th + 8, ath + 4, 4); /* acknowledge what A last sent */
	th[12] = 5 << 4;
	th[13] = 0x10; /* ACK, no data, no FIN, no SYN */
	th[14] = 0xff;
	th[15] = 0xff;
	uint16_t ck = tcp_ck(kIpB, kIpA, th, TC_TCP_HEADER_LEN);
	th[16] = (uint8_t)(ck >> 8);
	th[17] = (uint8_t)ck;

	tc_tcp_stats before, after;
	tc_tcp_get_stats(l.a, &before);
	TCT_EQ_INT(tc_tcp_input(l.a, pkt, sizeof pkt, l.now), TC_OK);
	tc_tcp_get_stats(l.a, &after);

	/* The segment must be taken as valid at all -- a checksum this test got
	 * wrong would fail the next check for the wrong reason. */
	TCT_TRUE(after.segs_received > before.segs_received);
	TCT_TRUE(after.segs_dropped_checksum == before.segs_dropped_checksum);
	TCT_TRUE(after.segs_sent > before.segs_sent);

	TCT_CASE("and the connection is undisturbed by it");
	TCT_TRUE(tc_tcp_is_established(l.a));
	TCT_TRUE(transfer(&l, l.a, l.b, 4096, 0x5678));
	link_done(&l);
}

/* An event loop sleeps until tc_tcp_next_deadline and then ticks. If that
 * ever reports a time the tick declines to act on, the deadline never
 * advances and the loop stops sleeping: it spins at full speed for as long as
 * the connection exists. That is a worse failure than a wrong answer and a
 * quieter one, because a test that drives the clock itself never notices --
 * it just runs, and the bill arrives on somebody's laptop battery.
 *
 * The idle timer is the deadline that can outlive the states that act on it,
 * because every arriving segment re-arms it whatever state the connection is
 * in. A connection that has finished TIME_WAIT is the plain case: closed,
 * nothing left to do, and an idle deadline still set from the last segment it
 * ever saw.
 */
static void test_a_finished_connection_has_no_deadline(void)
{
	TCT_CASE("a connection that has finished reports no deadline at all");
	link_t l;
	link_init(&l, 55);
	TCT_TRUE(establish(&l));

	tc_tcp_shutdown_write(l.a, l.now);
	int steps = 0;
	while (!tc_tcp_read_closed(l.b) && steps++ < 20000)
		link_step(&l);
	TCT_TRUE(tc_tcp_read_closed(l.b));

	tc_tcp_shutdown_write(l.b, l.now);
	steps = 0;
	while ((tc_tcp_get_state(l.a) != TC_TCP_CLOSED ||
	        tc_tcp_get_state(l.b) != TC_TCP_CLOSED) &&
	       steps++ < 200000)
		link_step(&l);
	TCT_EQ_INT((int)tc_tcp_get_state(l.a), (int)TC_TCP_CLOSED);
	TCT_EQ_INT((int)tc_tcp_get_state(l.b), (int)TC_TCP_CLOSED);

	/* Both are done, so neither has anything to wake a caller for. A
	 * deadline in the past here is the spin: the caller would not sleep, the
	 * tick would change nothing, and round it would go. */
	TCT_TRUE(tc_tcp_next_deadline(l.a) == UINT64_MAX);
	TCT_TRUE(tc_tcp_next_deadline(l.b) == UINT64_MAX);

	TCT_CASE("and no deadline anywhere is ever left in the past");
	/* The general form of the same invariant, over a whole connection's
	 * life: after a tick at now, the next deadline is in the future, or the
	 * tick had something to do and did it. */
	link_t k;
	link_init(&k, 56);
	TCT_TRUE(establish(&k));
	int stale = 0;
	for (int i = 0; i < 4000; i++) {
		link_step(&k);
		uint64_t da = tc_tcp_next_deadline(k.a);
		uint64_t db = tc_tcp_next_deadline(k.b);
		if ((da != UINT64_MAX && da < k.now) ||
		    (db != UINT64_MAX && db < k.now))
			stale++;
	}
	TCT_EQ_INT(stale, 0);
	link_done(&k);
	link_done(&l);
}

int main(void)
{
	test_handshake();
	test_data_both_ways();
	test_large_transfer();
	test_lossy_link();
	test_reordering();
	test_duplication();
	test_hostile_link();
	test_half_close();
	test_full_close();
	test_sequence_wrap();
	test_wrap_with_loss();
	test_rejects_bad_packets();
	test_flow_control();
	test_reset();
	test_segment_size();
	test_idle_detection();
	test_answers_a_zero_length_probe();
	test_a_finished_connection_has_no_deadline();
	return tct_report("tcp");
}
