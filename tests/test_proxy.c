/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Splicing a tunnel connection to a host socket.
 *
 * The copying is the easy half. What these tests are really about is the
 * *closing*: a proxy that only forwards data passes a request-response test
 * and hangs on everything that signals "I have finished" with an EOF, which
 * is most of what anyone would point this at. So every test here checks where
 * the EOF ended up, not just whether the bytes arrived.
 *
 * Real socketpairs on one side, two of our own TCP stacks over a simulated
 * link on the other. No network, and the clock is ours.
 */

#include "tc/proxy.h"
#include "tc/tcpmux.h"

#include "tctest.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- a two-ended tunnel ------------------------------------------------ */

#define LINK_MAXPKT 1400
#define LINK_QUEUE 512

typedef struct {
	uint8_t data[LINK_MAXPKT];
	size_t len;
	bool to_b;
	bool used;
	uint64_t seqno;
} link_pkt;

typedef struct {
	tc_tcp_mux *a, *b;
	link_pkt q[LINK_QUEUE];
	uint64_t now;
	uint64_t counter;
	bool overflow;
} link_t;

static int link_out(link_t *l, const uint8_t *p, size_t n, bool to_b)
{
	if (n > LINK_MAXPKT) {
		l->overflow = true;
		return TC_OK;
	}
	for (size_t i = 0; i < LINK_QUEUE; i++) {
		if (l->q[i].used)
			continue;
		memcpy(l->q[i].data, p, n);
		l->q[i].len = n;
		l->q[i].to_b = to_b;
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

static void link_deliver(link_t *l)
{
	for (;;) {
		size_t best = LINK_QUEUE;
		for (size_t i = 0; i < LINK_QUEUE; i++) {
			if (!l->q[i].used)
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
}

static const uint8_t kIpA[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 1 };
static const uint8_t kIpB[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0,
	                              0,    0,    0,    0,    0,    0,    0, 2 };

static void link_init(link_t *l)
{
	memset(l, 0, sizeof *l);
	l->a = tc_tcp_mux_new(kIpA, kIpB, out_a, l);
	l->b = tc_tcp_mux_new(kIpB, kIpA, out_b, l);
}

static void link_done(link_t *l)
{
	tc_tcp_mux_free(l->a);
	tc_tcp_mux_free(l->b);
}

/* step advances the clock, delivers packets, and pumps the proxy. */
static void step(link_t *l, tc_proxy *p)
{
	l->now += 5;
	link_deliver(l);
	tc_tcp_mux_tick(l->a, l->now);
	tc_tcp_mux_tick(l->b, l->now);
	link_deliver(l);
	if (p != NULL)
		tc_proxy_pump(p, l->now);
	link_deliver(l);
}

/* ---- a fake local service on a socketpair ------------------------------ */

/* establish dials A -> B:port and returns both ends, with B's side handed to
 * the proxy paired with `service_end`'s peer. */
typedef struct {
	link_t l;
	tc_proxy *p;
	tc_tcp_conn *client; /* the A side, standing in for a remote peer */
	int service;         /* what a local service would hold */
} rig;

static bool rig_up(rig *r, uint16_t port)
{
	memset(r, 0, sizeof *r);
	link_init(&r->l);
	r->p = tc_proxy_new(8);
	if (r->p == NULL)
		return false;
	if (tc_tcp_mux_listen(r->l.b, port) != TC_OK)
		return false;
	if (tc_tcp_mux_connect(r->l.a, port, r->l.now, &r->client) != TC_OK)
		return false;

	tc_tcp_conn *served = NULL;
	for (int i = 0; i < 400; i++) {
		step(&r->l, NULL);
		if (served == NULL)
			served = tc_tcp_mux_accept(r->l.b);
		if (served != NULL && tc_tcp_is_established(r->client) &&
		    tc_tcp_is_established(served))
			break;
	}
	if (served == NULL || !tc_tcp_is_established(r->client))
		return false;

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return false;
	r->service = sv[0];
	/* sv[1] is what the proxy dialled; it owns and closes it. */
	return tc_proxy_add(r->p, served, sv[1]) == TC_OK;
}

static void rig_down(rig *r)
{
	tc_proxy_free(r->p);
	link_done(&r->l);
	if (r->service >= 0)
		(void)close(r->service);
}

/* drain_service reads whatever the local service can see right now. */
static size_t drain_service(rig *r, char *buf, size_t cap, bool *saw_eof)
{
	size_t n = 0;
	for (;;) {
		if (n >= cap)
			break;
		ssize_t k = read(r->service, buf + n, cap - n);
		if (k > 0) {
			n += (size_t)k;
			continue;
		}
		if (k == 0) {
			if (saw_eof != NULL)
				*saw_eof = true;
			break;
		}
		if (errno == EINTR)
			continue;
		break; /* EAGAIN */
	}
	return n;
}

static void nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		(void)fcntl(fd, F_SETFL, (int)((unsigned)fl | (unsigned)O_NONBLOCK));
}

/* ---- tests -------------------------------------------------------------- */

static void test_both_directions(void)
{
	TCT_CASE("bytes move from the tunnel to the service and back");
	rig r;
	TCT_TRUE(rig_up(&r, 80));
	nonblock(r.service);

	static const char kReq[] = "GET / HTTP/1.0\r\n\r\n";
	size_t wrote = 0;
	TCT_EQ_INT(tc_tcp_write(r.client, kReq, sizeof kReq - 1, &wrote, r.l.now),
	           TC_OK);
	TCT_EQ_INT((int)wrote, (int)(sizeof kReq - 1));

	char got[256];
	size_t n = 0;
	for (int i = 0; i < 400 && n < sizeof kReq - 1; i++) {
		step(&r.l, r.p);
		n += drain_service(&r, got + n, sizeof got - n, NULL);
	}
	TCT_EQ_INT((int)n, (int)(sizeof kReq - 1));
	TCT_EQ_MEM(got, kReq, sizeof kReq - 1);

	TCT_CASE("and the reply comes back through the tunnel");
	static const char kResp[] = "HTTP/1.0 200 OK\r\n\r\nhello";
	TCT_TRUE(write(r.service, kResp, sizeof kResp - 1) ==
	         (ssize_t)(sizeof kResp - 1));

	char back[256];
	size_t bn = 0;
	for (int i = 0; i < 400 && bn < sizeof kResp - 1; i++) {
		step(&r.l, r.p);
		size_t k = 0;
		if (tc_tcp_read(r.client, back + bn, sizeof back - bn, &k) == TC_OK)
			bn += k;
	}
	TCT_EQ_INT((int)bn, (int)(sizeof kResp - 1));
	TCT_EQ_MEM(back, kResp, sizeof kResp - 1);

	rig_down(&r);
}

static void test_half_close_tunnel_to_service(void)
{
	TCT_CASE("the service sees EOF when the remote peer stops sending");
	/* This is the test that matters. A proxy that only forwards data passes
	 * everything above and hangs here, because the local service is waiting
	 * for an end-of-input that never arrives. */
	rig r;
	TCT_TRUE(rig_up(&r, 80));
	nonblock(r.service);

	static const char kMsg[] = "one line\n";
	size_t wrote = 0;
	tc_tcp_write(r.client, kMsg, sizeof kMsg - 1, &wrote, r.l.now);
	for (int i = 0; i < 200; i++)
		step(&r.l, r.p);
	tc_tcp_shutdown_write(r.client, r.l.now);

	char got[128];
	size_t n = 0;
	bool eof = false;
	for (int i = 0; i < 600 && !eof; i++) {
		step(&r.l, r.p);
		n += drain_service(&r, got + n, sizeof got - n, &eof);
	}
	TCT_TRUE(eof);
	TCT_EQ_INT((int)n, (int)(sizeof kMsg - 1));
	TCT_EQ_MEM(got, kMsg, sizeof kMsg - 1);

	TCT_CASE("and the reply after that EOF still gets through");
	/* Half close, not close: the service may answer after reading EOF, and
	 * shutting the whole socket would lose the answer. */
	static const char kLate[] = "answered after EOF";
	TCT_TRUE(write(r.service, kLate, sizeof kLate - 1) ==
	         (ssize_t)(sizeof kLate - 1));
	char back[128];
	size_t bn = 0;
	for (int i = 0; i < 600 && bn < sizeof kLate - 1; i++) {
		step(&r.l, r.p);
		size_t k = 0;
		if (tc_tcp_read(r.client, back + bn, sizeof back - bn, &k) == TC_OK)
			bn += k;
	}
	TCT_EQ_INT((int)bn, (int)(sizeof kLate - 1));
	TCT_EQ_MEM(back, kLate, sizeof kLate - 1);

	rig_down(&r);
}

static void test_half_close_service_to_tunnel(void)
{
	TCT_CASE("the remote peer sees EOF when the service closes");
	rig r;
	TCT_TRUE(rig_up(&r, 80));
	nonblock(r.service);

	static const char kBody[] = "the whole response";
	TCT_TRUE(write(r.service, kBody, sizeof kBody - 1) ==
	         (ssize_t)(sizeof kBody - 1));
	(void)shutdown(r.service, SHUT_WR);

	char back[128];
	size_t bn = 0;
	bool closed = false;
	for (int i = 0; i < 800; i++) {
		step(&r.l, r.p);
		size_t k = 0;
		if (tc_tcp_read(r.client, back + bn, sizeof back - bn, &k) == TC_OK)
			bn += k;
		if (tc_tcp_read_closed(r.client)) {
			closed = true;
			break;
		}
	}
	TCT_TRUE(closed);
	TCT_EQ_INT((int)bn, (int)(sizeof kBody - 1));
	TCT_EQ_MEM(back, kBody, sizeof kBody - 1);

	rig_down(&r);
}

static void test_full_close_is_reaped(void)
{
	TCT_CASE("a pair both sides have finished with is reaped");
	rig r;
	TCT_TRUE(rig_up(&r, 80));
	nonblock(r.service);

	TCT_EQ_INT((int)tc_proxy_count(r.p), 1);

	tc_tcp_shutdown_write(r.client, r.l.now);
	(void)shutdown(r.service, SHUT_WR);

	size_t reaped = 0;
	for (int i = 0; i < 1000 && reaped == 0; i++) {
		step(&r.l, r.p);
		reaped = tc_proxy_reap(r.p, r.l.now);
	}
	TCT_EQ_INT((int)reaped, 1);
	TCT_EQ_INT((int)tc_proxy_count(r.p), 0);

	tc_proxy_stats st;
	tc_proxy_get_stats(r.p, &st);
	TCT_EQ_INT((int)st.opened, 1);
	TCT_EQ_INT((int)st.closed, 1);
	TCT_EQ_INT((int)st.failed, 0);

	rig_down(&r);
}

static void test_large_transfer(void)
{
	TCT_CASE("a transfer larger than every buffer involved arrives intact");
	/* The staging buffers are 8 KB and the TCP send buffer is 64 KB, so a
	 * quarter-megabyte has to survive short writes, a full send buffer and
	 * a socket that keeps saying EAGAIN. */
	rig r;
	TCT_TRUE(rig_up(&r, 80));
	nonblock(r.service);

	enum { TOTAL = 256 * 1024 };
	static uint8_t sent[TOTAL];
	for (size_t i = 0; i < TOTAL; i++)
		sent[i] = (uint8_t)(i * 31u + (i >> 9) * 7u);

	static uint8_t got[TOTAL + 16];
	size_t off = 0, n = 0;
	bool eof = false;

	for (int i = 0; i < 400000 && (off < TOTAL || !eof); i++) {
		if (off < TOTAL) {
			size_t wrote = 0;
			size_t want = TOTAL - off;
			if (want > 4096)
				want = 4096;
			tc_tcp_write(r.client, sent + off, want, &wrote, r.l.now);
			off += wrote;
			if (off == TOTAL)
				tc_tcp_shutdown_write(r.client, r.l.now);
		}
		step(&r.l, r.p);
		if (n < sizeof got)
			n += drain_service(&r, (char *)got + n, sizeof got - n, &eof);
	}

	TCT_EQ_INT((int)off, TOTAL);
	if (n != TOTAL)
		TCT_FAILF("%zu of %d bytes arrived", n, TOTAL);
	tct_checks++;
	if (memcmp(got, sent, n < TOTAL ? n : TOTAL) != 0)
		TCT_FAILF("the payload differs");
	tct_checks++;
	TCT_TRUE(!r.l.overflow);

	rig_down(&r);
}

static void test_service_hangs_up_early(void)
{
	TCT_CASE("a service that vanishes mid-stream fails the pair, not the loop");
	rig r;
	TCT_TRUE(rig_up(&r, 80));

	/* Close the service end outright while the peer is still talking. */
	(void)close(r.service);
	r.service = -1;

	static const char kMsg[] = "nobody is listening";
	size_t wrote = 0;
	tc_tcp_write(r.client, kMsg, sizeof kMsg - 1, &wrote, r.l.now);

	size_t reaped = 0;
	for (int i = 0; i < 1000 && reaped == 0; i++) {
		step(&r.l, r.p);
		reaped = tc_proxy_reap(r.p, r.l.now);
	}
	TCT_EQ_INT((int)reaped, 1);
	TCT_EQ_INT((int)tc_proxy_count(r.p), 0);

	rig_down(&r);
}

static void test_limits_and_nulls(void)
{
	TCT_CASE("a full proxy refuses without taking the socket");
	/* The caller has to be able to answer politely instead, and it cannot do
	 * that with a descriptor we have already closed. */
	tc_proxy *p = tc_proxy_new(1);
	TCT_TRUE(p != NULL);

	link_t l;
	link_init(&l);
	tc_tcp_conn *c1 = NULL, *c2 = NULL;
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 7, l.now, &c1), TC_OK);
	TCT_EQ_INT(tc_tcp_mux_connect(l.a, 8, l.now, &c2), TC_OK);

	int sv[2], sv2[2];
	TCT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	TCT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2), 0);
	TCT_EQ_INT(tc_proxy_add(p, c1, sv[1]), TC_OK);
	TCT_EQ_INT(tc_proxy_add(p, c2, sv2[1]), TC_ERR_TOOMANY);
	/* Still ours, so still usable. */
	TCT_TRUE(write(sv2[1], "x", 1) == 1);
	(void)close(sv2[0]);
	(void)close(sv2[1]);
	(void)close(sv[0]);

	TCT_CASE("interest reports the socket and what it wants");
	int fd = -1;
	bool rd = false, wr = true;
	TCT_TRUE(tc_proxy_interest(p, 0, &fd, &rd, &wr));
	TCT_EQ_INT(fd, sv[1]);
	TCT_TRUE(rd);
	TCT_TRUE(!wr);
	TCT_TRUE(!tc_proxy_interest(p, 1, &fd, &rd, &wr));
	TCT_TRUE(!tc_proxy_interest(p, 99, &fd, &rd, &wr));

	TCT_CASE("forget drops a pair without touching the connection");
	tc_proxy_forget(p, c1);
	TCT_EQ_INT((int)tc_proxy_count(p), 0);
	tc_proxy_forget(p, c1); /* again, harmlessly */

	TCT_CASE("null arguments are refused");
	TCT_TRUE(tc_proxy_new(0) == NULL);
	TCT_EQ_INT(tc_proxy_add(NULL, c1, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_proxy_add(p, NULL, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_proxy_add(p, c1, -1), TC_ERR_INVAL);
	TCT_EQ_INT((int)tc_proxy_pump(NULL, 0), 0);
	TCT_EQ_INT((int)tc_proxy_reap(NULL, 0), 0);
	TCT_EQ_INT((int)tc_proxy_count(NULL), 0);
	TCT_TRUE(!tc_proxy_interest(NULL, 0, &fd, &rd, &wr));
	tc_proxy_forget(NULL, c1);
	tc_proxy_free(NULL);

	tc_proxy_free(p);
	link_done(&l);
}

int main(void)
{
	test_both_directions();
	test_half_close_tunnel_to_service();
	test_half_close_service_to_tunnel();
	test_full_close_is_reaped();
	test_large_transfer();
	test_service_hangs_up_early();
	test_limits_and_nulls();
	return tct_report("proxy");
}
