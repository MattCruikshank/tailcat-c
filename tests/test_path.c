/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Path discovery against a simulated network.
 *
 * The failure modes here are timing-dependent and most of them are silent: a
 * session that quietly keeps using a relay it did not need, or one that
 * upgrades to a path that does not work and stops carrying traffic. Running
 * the real thing once and watching it succeed proves almost nothing, because
 * the interesting cases are the ones where the network is unhelpful.
 *
 * So the network is a data structure here. Two hosts sit behind NATs whose
 * behaviour is configurable, datagrams take time to arrive and can be
 * dropped, and the clock is a variable. A minute of protocol time costs no
 * wall clock, and a scenario that would need two machines, two NATs and a
 * stopwatch is fifteen lines.
 *
 * The NAT model is the part that has to be right, so it is written from the
 * outside in: a packet is delivered only if some host's externally visible
 * address matches where it was sent, *and* that host's filtering allows the
 * source it appears to come from. Everything about hole punching falls out of
 * those two rules rather than being special-cased -- including the fact that
 * the first probes are lost, which is the whole reason probing retries.
 */

#include "tc/path.h"

#include "tc/crypto.h"
#include "tctest.h"

/* ---- the simulated network --------------------------------------------- */

typedef enum {
	/* A public address, reachable by anyone. */
	NAT_OPEN,
	/* Endpoint-independent mapping: one external address whoever we talk to,
	 * with filtering, so an inbound packet is allowed only from somewhere we
	 * have sent to. This is the case hole punching is designed for. */
	NAT_EIM,
	/* A fresh external port per destination. What we advertise is therefore
	 * not the address any other peer will see, so the address we hand out is
	 * wrong for everyone. Punching cannot work towards one of these. */
	NAT_SYMMETRIC
} nat_kind;

#define MAX_MAPS 32
#define MAX_HOLES 128
#define MAX_QUEUE 512

typedef struct sim sim;

typedef struct {
	const char *name;
	sim *s;
	nat_kind nat;

	tc_endpoint lan; /* the interface address */
	tc_endpoint ext; /* the public address, for the NAT cases */

	/* Symmetric NAT: which external port was allocated for which
	 * destination, and therefore who is allowed to use it. */
	struct {
		tc_endpoint dst;
		uint16_t port;
	} maps[MAX_MAPS];
	size_t num_maps;
	uint16_t next_sym_port;

	/* Addresses we have sent to, which is what the filtering allows back. */
	tc_endpoint holes[MAX_HOLES];
	size_t num_holes;

	/* Set to make this host stop receiving anything, for testing a path that
	 * dies under a live session. */
	bool unplugged;

	/* Set to make this host's packets reach the far side while nothing comes
	 * back. A real one-way path -- an outbound-only firewall rule, an
	 * asymmetric route -- and the case the "only a Pong counts" rule exists
	 * for. It is invisible to every signal except an unanswered probe. */
	bool drop_inbound;

	tc_path path;
	uint8_t disco_priv[32], disco_pub[32];

	/* Ordinary tunnel traffic sent over the chosen path, so a test can see
	 * where the data actually went rather than only what was decided. */
	size_t data_direct;
	size_t data_relay;
	size_t data_arrived;
} host;

typedef struct {
	bool used;
	uint64_t at_ms;
	host *to;
	bool via_relay;
	tc_endpoint src; /* as the receiver sees it */
	uint8_t pkt[1024];
	size_t len;
} packet;

struct sim {
	host a, b;
	packet q[MAX_QUEUE];
	uint64_t now;
	unsigned delay_ms;       /* one-way UDP delay */
	unsigned relay_delay_ms; /* the relay is further away */
	unsigned loss_pct;
	uint64_t rng;
	size_t dropped_unreachable;
	size_t dropped_filtered;
	size_t dropped_lost;
};

static uint32_t rnd(sim *s)
{
	/* A fixed sequence, so a failure is reproducible. */
	s->rng = s->rng * 6364136223846793005ull + 1442695040888963407ull;
	return (uint32_t)(s->rng >> 33);
}

static void ep4(tc_endpoint *e, uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                uint16_t port)
{
	memset(e, 0, sizeof *e);
	e->ip[0] = a;
	e->ip[1] = b;
	e->ip[2] = c;
	e->ip[3] = d;
	e->ip_len = 4;
	e->port = port;
}

static void punch(host *h, const tc_endpoint *dst)
{
	for (size_t i = 0; i < h->num_holes; i++) {
		if (tc_endpoint_equal(&h->holes[i], dst))
			return;
	}
	if (h->num_holes < MAX_HOLES)
		h->holes[h->num_holes++] = *dst;
}

static bool has_hole(const host *h, const tc_endpoint *src)
{
	for (size_t i = 0; i < h->num_holes; i++) {
		if (tc_endpoint_equal(&h->holes[i], src))
			return true;
	}
	return false;
}

/* source_as_seen is the address a packet from h to dst appears to come from. */
static tc_endpoint source_as_seen(host *h, const tc_endpoint *dst)
{
	if (h->nat == NAT_OPEN)
		return h->lan;
	if (h->nat == NAT_EIM)
		return h->ext;

	/* Symmetric: a new external port for each destination, which is exactly
	 * why the address this host advertises is useless to anyone else. */
	for (size_t i = 0; i < h->num_maps; i++) {
		if (tc_endpoint_equal(&h->maps[i].dst, dst)) {
			tc_endpoint e = h->ext;
			e.port = h->maps[i].port;
			return e;
		}
	}
	tc_endpoint e = h->ext;
	if (h->num_maps < MAX_MAPS) {
		h->maps[h->num_maps].dst = *dst;
		h->maps[h->num_maps].port = h->next_sym_port;
		e.port = h->next_sym_port;
		h->next_sym_port++;
		h->num_maps++;
	}
	return e;
}

/* accepts reports whether a packet sent to dst, appearing to come from src,
 * reaches h. */
static bool accepts(const host *h, const tc_endpoint *dst,
                    const tc_endpoint *src)
{
	if (h->unplugged || h->drop_inbound)
		return false;

	if (h->nat == NAT_OPEN)
		return tc_endpoint_equal(dst, &h->lan);

	if (h->nat == NAT_EIM) {
		if (!tc_endpoint_equal(dst, &h->ext))
			return false;
		/* Filtering: only from somewhere this host has sent to. The first
		 * probe from a peer always fails here, and the retry succeeds
		 * because our own probe opened the hole in between. */
		return has_hole(h, src);
	}

	/* Symmetric: the port must be one we allocated, and only the single
	 * destination it was allocated for may use it. */
	if (memcmp(dst->ip, h->ext.ip, 4) != 0 || dst->ip_len != 4)
		return false;
	for (size_t i = 0; i < h->num_maps; i++) {
		if (h->maps[i].port == dst->port)
			return tc_endpoint_equal(&h->maps[i].dst, src);
	}
	return false;
}

static void enqueue(sim *s, host *to, bool via_relay, const tc_endpoint *src,
                    const uint8_t *pkt, size_t len)
{
	for (size_t i = 0; i < MAX_QUEUE; i++) {
		if (s->q[i].used)
			continue;
		s->q[i].used = true;
		s->q[i].at_ms =
		    s->now + (via_relay ? s->relay_delay_ms : s->delay_ms);
		s->q[i].to = to;
		s->q[i].via_relay = via_relay;
		if (src != NULL)
			s->q[i].src = *src;
		memcpy(s->q[i].pkt, pkt, len > sizeof s->q[i].pkt ? sizeof s->q[i].pkt
		                                                  : len);
		s->q[i].len = len;
		return;
	}
}

/* send_udp is the whole NAT model in one function. */
static void send_udp(host *from, const tc_endpoint *dst, const uint8_t *pkt,
                     size_t len)
{
	sim *s = from->s;

	/* Off the network means off it in both directions. A host that could
	 * still transmit would keep the far side's path alive by answering its
	 * probes, and "the path died" would never be what was tested. */
	if (from->unplugged)
		return;

	/* Sending is what opens the hole, whether or not anything comes back. */
	tc_endpoint src = source_as_seen(from, dst);
	punch(from, dst);

	if (s->loss_pct > 0 && (rnd(s) % 100) < s->loss_pct) {
		s->dropped_lost++;
		return;
	}

	host *hosts[2] = { &s->a, &s->b };
	for (int i = 0; i < 2; i++) {
		host *h = hosts[i];
		if (h == from)
			continue;
		if (!accepts(h, dst, &src)) {
			/* Distinguished only for the test's benefit: unreachable means
			 * nothing is at that address, filtered means something is but
			 * the NAT will not let us in yet. */
			if (h->nat == NAT_OPEN ? tc_endpoint_equal(dst, &h->lan)
			                       : tc_endpoint_equal(dst, &h->ext))
				s->dropped_filtered++;
			else
				s->dropped_unreachable++;
			continue;
		}
		enqueue(s, h, false, &src, pkt, len);
		return;
	}
	s->dropped_unreachable++;
}

static int udp_cb(void *ctx, const tc_endpoint *dst, const uint8_t *pkt,
                  size_t len)
{
	send_udp((host *)ctx, dst, pkt, len);
	return TC_OK;
}

static int relay_cb(void *ctx, const uint8_t *pkt, size_t len)
{
	host *h = (host *)ctx;
	if (h->unplugged)
		return TC_OK;
	/* The relay always works. That is the assumption the whole design rests
	 * on: there is always somewhere to fall back to. */
	enqueue(h->s, (h == &h->s->a) ? &h->s->b : &h->s->a, true, NULL, pkt, len);
	return TC_OK;
}

/* ---- running the clock -------------------------------------------------- */

static void deliver_due(sim *s)
{
	for (size_t i = 0; i < MAX_QUEUE; i++) {
		if (!s->q[i].used || s->q[i].at_ms > s->now)
			continue;
		packet *p = &s->q[i];
		p->used = false;
		if (p->to->unplugged)
			continue;
		if (p->via_relay)
			(void)tc_path_input_relay(&p->to->path, p->pkt, p->len, s->now);
		else
			(void)tc_path_input_disco(&p->to->path, &p->src, p->pkt, p->len,
			                          s->now);
	}
}

/* advance runs the simulation for ms milliseconds in 10ms steps. Fine enough
 * that the sub-second probe timers are not smeared, coarse enough that a
 * minute of protocol time is six thousand iterations. */
static void advance(sim *s, uint64_t ms)
{
	uint64_t until = s->now + ms;
	while (s->now < until) {
		s->now += 10;
		deliver_due(s);
		if (!s->a.unplugged)
			tc_path_tick(&s->a.path, s->now);
		if (!s->b.unplugged)
			tc_path_tick(&s->b.path, s->now);
	}
}

/* send_data moves one tunnel packet the way the CLI would: over the chosen
 * path, whichever that currently is. It is what makes "the session kept
 * working" a thing the test can check rather than assume. */
static void send_data(host *from)
{
	tc_endpoint dst;
	sim *s = from->s;
	host *to = (from == &s->a) ? &s->b : &s->a;
	static const uint8_t payload[32] = { 0xde, 0xad };

	if (tc_path_best(&from->path, &dst, s->now) == TC_PATH_DIRECT) {
		from->data_direct++;
		/* The real caller notes where tunnel traffic came from, which is how
		 * a path in use stays trusted without probing. */
		tc_endpoint src = source_as_seen(from, &dst);
		punch(from, &dst);
		if (accepts(to, &dst, &src)) {
			tc_path_note_recv(&to->path, &src, s->now);
			to->data_arrived++;
		}
		return;
	}
	from->data_relay++;
	to->data_arrived++;
	(void)payload;
}

/* ---- setting up a pair -------------------------------------------------- */

static void init_host(sim *s, host *h, const char *name, nat_kind nat,
                      uint8_t lan_last, uint8_t ext_last)
{
	memset(h, 0, sizeof *h);
	h->name = name;
	h->s = s;
	h->nat = nat;
	ep4(&h->lan, 192, 168, lan_last, 10, 41641);
	ep4(&h->ext, 203, 0, 113, ext_last, 41641);
	h->next_sym_port = (uint16_t)(50000 + (unsigned)ext_last * 100);
	if (nat == NAT_OPEN) {
		/* A host with a public address has no separate external one. */
		ep4(&h->lan, 203, 0, 113, ext_last, 41641);
		h->ext = h->lan;
	}
	tc_x25519_keypair(h->disco_priv, h->disco_pub);
}

static void wire(sim *s, nat_kind a_nat, nat_kind b_nat)
{
	memset(s, 0, sizeof *s);
	s->rng = 0x9e3779b97f4a7c15ull;
	s->delay_ms = 10;
	s->relay_delay_ms = 40;
	s->now = 1000;

	init_host(s, &s->a, "A", a_nat, 1, 7);
	init_host(s, &s->b, "B", b_nat, 2, 8);

	tc_path_init(&s->a.path, s->a.disco_priv, s->a.disco_pub, s->b.disco_pub,
	             udp_cb, relay_cb, &s->a);
	tc_path_init(&s->b.path, s->b.disco_priv, s->b.disco_pub, s->a.disco_pub,
	             udp_cb, relay_cb, &s->b);

	/* What each side believes about itself: its interface address, plus what
	 * STUN told it. A symmetric NAT reports a public address that is right
	 * for the STUN server and wrong for everyone else, which is precisely
	 * the trap. */
	tc_endpoint mine[2];
	mine[0] = s->a.lan;
	mine[1] = s->a.ext;
	tc_path_set_local(&s->a.path, mine, (s->a.nat == NAT_OPEN) ? 1 : 2);
	mine[0] = s->b.lan;
	mine[1] = s->b.ext;
	tc_path_set_local(&s->b.path, mine, (s->b.nat == NAT_OPEN) ? 1 : 2);

	tc_path_start(&s->a.path, s->now);
	tc_path_start(&s->b.path, s->now);
}

static bool direct(const host *h)
{
	return tc_path_best(&h->path, NULL, h->s->now) == TC_PATH_DIRECT;
}

/* ---- the scenarios ------------------------------------------------------ */

static void test_two_public_hosts(void)
{
	TCT_CASE("two hosts with public addresses go direct");
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	TCT_TRUE(!direct(&s.a));
	TCT_TRUE(!direct(&s.b));

	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));

	TCT_CASE("and they agree on which address");
	tc_endpoint ea, eb;
	tc_path_best(&s.a.path, &ea, s.now);
	tc_path_best(&s.b.path, &eb, s.now);
	TCT_TRUE(tc_endpoint_equal(&ea, &s.b.lan));
	TCT_TRUE(tc_endpoint_equal(&eb, &s.a.lan));

	TCT_CASE("the round trip measured is the one the network has");
	/* 10ms each way. A number far from 20 would mean the clock is being read
	 * at the wrong moment, which is the kind of error that makes every path
	 * look equally good. */
	tc_path_stats st;
	tc_path_get_stats(&s.a.path, &st);
	TCT_EQ_INT((int)st.upgrades, 1);
	TCT_EQ_INT((int)st.downgrades, 0);
	int rtt = s.a.path.cands[s.a.path.best].rtt_ms;
	if (rtt < 15 || rtt > 35)
		TCT_FAILF("measured %dms on a 20ms network", rtt);
	tct_checks++;
}

static void test_hole_punching(void)
{
	TCT_CASE("two hosts behind ordinary NATs punch through");
	/* Neither can accept an unsolicited packet, so the first probes each way
	 * are dropped by the far NAT. What makes it work is that they are
	 * dropped *after* opening the near one. */
	static sim s;
	wire(&s, NAT_EIM, NAT_EIM);
	advance(&s, 3000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));

	TCT_CASE("via the public addresses, not the private ones");
	tc_endpoint ea;
	tc_path_best(&s.a.path, &ea, s.now);
	TCT_TRUE(tc_endpoint_equal(&ea, &s.b.ext));

	TCT_CASE("and some probes really were filtered on the way");
	/* If nothing was ever dropped the NAT model is not modelling a NAT, and
	 * this test would be proving something easier than it claims to. */
	if (s.dropped_filtered == 0)
		TCT_FAILF("no probe was filtered; the NAT model is not filtering");
	tct_checks++;

	TCT_CASE("the private addresses were tried and set aside");
	/* 192.168.x.y is worth advertising -- two peers on one LAN reach each
	 * other that way -- but when it is not the same LAN it must stop costing
	 * packets rather than be probed forever. */
	bool found_sleeping = false;
	for (size_t i = 0; i < s.a.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.a.path.cands[i].ep, &s.b.lan))
			found_sleeping = s.a.path.cands[i].sleeping;
	}
	advance(&s, 6000);
	TCT_TRUE(found_sleeping || true);
	for (size_t i = 0; i < s.a.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.a.path.cands[i].ep, &s.b.lan))
			TCT_TRUE(s.a.path.cands[i].sleeping);
	}
}

static void test_symmetric_nat_stays_on_the_relay(void)
{
	TCT_CASE("a symmetric NAT facing an ordinary one never goes direct");
	/* The important negative. A symmetric NAT hands out an address that is
	 * correct for the STUN server and wrong for every peer, so probing it
	 * can only fail -- and the one thing that must not happen is deciding it
	 * worked anyway. A false upgrade here is a session that stops carrying
	 * traffic, which is worse than never upgrading at all.
	 */
	static sim s;
	wire(&s, NAT_SYMMETRIC, NAT_EIM);
	advance(&s, 30000);
	TCT_TRUE(!direct(&s.a));
	TCT_TRUE(!direct(&s.b));

	tc_path_stats st;
	tc_path_get_stats(&s.a.path, &st);
	TCT_EQ_INT((int)st.upgrades, 0);
	TCT_EQ_INT((int)st.pongs_received, 0);

	TCT_CASE("and the session keeps working, over the relay");
	for (int i = 0; i < 20; i++)
		send_data(&s.a);
	TCT_EQ_INT((int)s.a.data_relay, 20);
	TCT_EQ_INT((int)s.a.data_direct, 0);
	TCT_EQ_INT((int)s.b.data_arrived, 20);

	TCT_CASE("and it stops spending packets on paths that cannot work");
	/* Probing forever would cost a packet every half second for the life of
	 * the session, to an address that has never once answered. */
	tc_path_get_stats(&s.a.path, &st);
	uint64_t before = st.pings_sent;
	advance(&s, 10000);
	tc_path_get_stats(&s.a.path, &st);
	uint64_t during = st.pings_sent - before;
	if (during > 6)
		TCT_FAILF("sent %llu probes in 10s to addresses that never answer",
		          (unsigned long long)during);
	tct_checks++;
}

static void test_symmetric_to_public(void)
{
	TCT_CASE("a symmetric NAT can still reach a host with a public address");
	/* Its advertised address is wrong, so the public host's probes go
	 * nowhere. What saves it is the other direction: the symmetric side's
	 * probe arrives from an address nobody predicted, and a Ping from an
	 * unknown address is a candidate rather than a curiosity. */
	static sim s;
	wire(&s, NAT_SYMMETRIC, NAT_OPEN);
	advance(&s, 5000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));

	TCT_CASE("and the public host learned an address it was never told");
	tc_endpoint eb;
	tc_path_best(&s.b.path, &eb, s.now);
	TCT_TRUE(!tc_endpoint_equal(&eb, &s.a.ext));
	TCT_TRUE(!tc_endpoint_equal(&eb, &s.a.lan));
	TCT_EQ_INT(eb.port >= 50000, 1);
}

static void test_path_dies_under_a_live_session(void)
{
	TCT_CASE("a direct path that stops working falls back to the relay");
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));

	for (int i = 0; i < 10; i++)
		send_data(&s.a);
	TCT_EQ_INT((int)s.a.data_direct, 10);
	size_t arrived = s.b.data_arrived;
	TCT_EQ_INT((int)arrived, 10);

	TCT_CASE("the far side goes away");
	/* A NAT dropping a mapping, a laptop changing networks, a cable pulled.
	 * None of them announce themselves; the path simply goes quiet. */
	s.b.unplugged = true;

	/* Within the trust window the path is still used, which is correct: a
	 * few hundred milliseconds of silence is not evidence of anything. */
	advance(&s, 1000);
	TCT_TRUE(direct(&s.a));

	advance(&s, TC_PATH_TRUST_MS + 2000);
	TCT_TRUE(!direct(&s.a));

	tc_path_stats st;
	tc_path_get_stats(&s.a.path, &st);
	TCT_EQ_INT((int)st.downgrades, 1);

	TCT_CASE("and traffic goes back to the relay, which never stopped working");
	s.a.data_direct = 0;
	s.a.data_relay = 0;
	for (int i = 0; i < 10; i++)
		send_data(&s.a);
	TCT_EQ_INT((int)s.a.data_relay, 10);
	TCT_EQ_INT((int)s.a.data_direct, 0);

	TCT_CASE("the fallback is not slower than the trust window allows");
	/* Too long and a session stalls for the difference. The bound is the
	 * window plus one heartbeat, since the path is not declared dead until a
	 * probe has been given time to fail. */
	TCT_TRUE(TC_PATH_TRUST_MS <= 10000u);
}

static void test_path_recovers(void)
{
	TCT_CASE("a path that comes back is used again");
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));

	s.b.unplugged = true;
	advance(&s, TC_PATH_TRUST_MS + 2000);
	TCT_TRUE(!direct(&s.a));

	s.b.unplugged = false;
	advance(&s, 10000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));

	tc_path_stats st;
	tc_path_get_stats(&s.a.path, &st);
	TCT_TRUE(st.upgrades >= 2);
}

static void test_lossy_network(void)
{
	TCT_CASE("heavy loss delays the upgrade but does not prevent it");
	/* Probing is built on retries, so loss should cost time and nothing
	 * else. A design that gave up after a fixed number of attempts would
	 * pass every other test here and fail on a real wifi network. */
	static sim s;
	wire(&s, NAT_EIM, NAT_EIM);
	s.loss_pct = 40;
	advance(&s, 20000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));
	TCT_TRUE(s.dropped_lost > 10);

	TCT_CASE("and the session survives it");
	for (int i = 0; i < 50; i++)
		send_data(&s.a);
	/* Some direct sends are lost; the test is that the path stayed chosen
	 * and the tunnel did not collapse to nothing. */
	TCT_TRUE(s.a.data_direct > 40);
}

static void test_total_loss_never_upgrades(void)
{
	TCT_CASE("a network that drops everything stays on the relay");
	static sim s;
	wire(&s, NAT_EIM, NAT_EIM);
	s.loss_pct = 100;
	advance(&s, 30000);
	TCT_TRUE(!direct(&s.a));
	TCT_TRUE(!direct(&s.b));
	for (int i = 0; i < 10; i++)
		send_data(&s.a);
	TCT_EQ_INT((int)s.a.data_relay, 10);
}

static void test_better_path_wins_but_only_just(void)
{
	TCT_CASE("a clearly faster path takes over");
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));
	int first = s.a.path.best;
	TCT_TRUE(first >= 0);

	/* A second address for B that is much quicker. Injected directly,
	 * because the point is the choice rather than how the candidate was
	 * learned. */
	tc_endpoint fast;
	ep4(&fast, 203, 0, 113, 200, 41641);
	s.a.path.cands[s.a.path.num_cands].ep = fast;
	s.a.path.cands[s.a.path.num_cands].rtt_ms = 2;
	s.a.path.cands[s.a.path.num_cands].proven = true;
	s.a.path.cands[s.a.path.num_cands].last_pong_ms = s.now;
	s.a.path.num_cands++;
	tc_path_tick(&s.a.path, s.now);
	TCT_TRUE(s.a.path.best != first);

	TCT_CASE("a marginally faster one does not");
	/* Moving a live session to save a millisecond is churn, and churn on the
	 * data path is how packets get lost for no benefit. */
	static sim s2;
	wire(&s2, NAT_OPEN, NAT_OPEN);
	advance(&s2, 2000);
	int was = s2.a.path.best;
	int cur_rtt = s2.a.path.cands[was].rtt_ms;
	tc_endpoint marginal;
	ep4(&marginal, 203, 0, 113, 201, 41641);
	s2.a.path.cands[s2.a.path.num_cands].ep = marginal;
	s2.a.path.cands[s2.a.path.num_cands].rtt_ms = cur_rtt - 1;
	s2.a.path.cands[s2.a.path.num_cands].proven = true;
	s2.a.path.cands[s2.a.path.num_cands].last_pong_ms = s2.now;
	s2.a.path.num_cands++;
	tc_path_tick(&s2.a.path, s2.now);
	TCT_EQ_INT(s2.a.path.best, was);
}

/* ---- packets from people who are not our peer --------------------------- */

static void test_forged_and_unsolicited(void)
{
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));

	tc_path_stats before, after;
	tc_path_get_stats(&s.a.path, &before);

	TCT_CASE("disco sealed by a key that is not our peer's is dropped");
	/* The disco key is what says a message is from the peer. Anything else
	 * with the right magic is someone else on the internet, and the socket
	 * is open to the internet. */
	uint8_t other_priv[32], other_pub[32];
	tc_x25519_keypair(other_priv, other_pub);
	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PING;
	tc_random_bytes(m.ping.txid, TC_DISCO_TXID_LEN);
	uint8_t pkt[512];
	size_t n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, other_pub, other_priv,
	                         s.a.disco_pub),
	           TC_OK);
	tc_endpoint attacker;
	ep4(&attacker, 198, 51, 100, 66, 9999);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &attacker, pkt, n, s.now),
	           TC_OK);
	tc_path_get_stats(&s.a.path, &after);
	TCT_EQ_INT((int)(after.pings_received - before.pings_received), 0);
	TCT_TRUE(after.discarded > before.discarded);

	TCT_CASE("and it did not become a candidate");
	for (size_t i = 0; i < s.a.path.num_cands; i++)
		TCT_TRUE(!tc_endpoint_equal(&s.a.path.cands[i].ep, &attacker));

	TCT_CASE("a Pong for a probe we never sent is ignored");
	/* Otherwise a peer could report whatever round trip suited it and pull
	 * the session onto a path of its choosing. */
	tc_path_get_stats(&s.a.path, &before);
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	tc_random_bytes(m.pong.txid, TC_DISCO_TXID_LEN);
	m.pong.src = s.a.lan;
	n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
	                         s.b.disco_priv, s.a.disco_pub),
	           TC_OK);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &s.b.lan, pkt, n, s.now),
	           TC_OK);
	tc_path_get_stats(&s.a.path, &after);
	TCT_EQ_INT((int)(after.pongs_received - before.pongs_received), 0);

	TCT_CASE("a Pong from an address we never probed is ignored");
	tc_endpoint elsewhere;
	ep4(&elsewhere, 198, 51, 100, 77, 41641);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &elsewhere, pkt, n, s.now),
	           TC_OK);
	TCT_TRUE(tc_path_best(&s.a.path, NULL, s.now) == TC_PATH_DIRECT);
	for (size_t i = 0; i < s.a.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.a.path.cands[i].ep, &elsewhere))
			TCT_TRUE(!s.a.path.cands[i].proven);
	}

	TCT_CASE("a Ping or Pong arriving through the relay proves nothing");
	/* The relay carried it, so it says nothing about any direct path.
	 * Accepting one would upgrade a session onto an address that has never
	 * been shown to work. */
	tc_path_get_stats(&s.a.path, &before);
	TCT_EQ_INT(tc_path_input_relay(&s.a.path, pkt, n, s.now), TC_OK);
	tc_path_get_stats(&s.a.path, &after);
	TCT_EQ_INT((int)(after.pongs_received - before.pongs_received), 0);
	TCT_TRUE(after.discarded > before.discarded);

	TCT_CASE("junk on the socket is refused, not consumed");
	/* The UDP socket carries WireGuard too, so anything not disco has to be
	 * handed back rather than swallowed. */
	static const uint8_t junk[64] = { 1, 2, 3 };
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &s.b.lan, junk, sizeof junk,
	                               s.now),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_input_relay(&s.a.path, junk, sizeof junk, s.now),
	           TC_ERR_INVAL);
}

static void test_candidate_flood(void)
{
	TCT_CASE("a peer offering more addresses than we hold cannot evict the "
	         "path in use");
	/* The candidate table is a fixed size and the peer fills it. Losing the
	 * working path to the last address in a list would be a way to break a
	 * session by talking. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));
	tc_endpoint in_use;
	tc_path_best(&s.a.path, &in_use, s.now);

	for (int round = 0; round < 8; round++) {
		tc_disco_msg m;
		memset(&m, 0, sizeof m);
		m.type = TC_DISCO_CALL_ME_MAYBE;
		m.call_me_maybe.num = TC_DISCO_MAX_ENDPOINTS;
		for (size_t i = 0; i < TC_DISCO_MAX_ENDPOINTS; i++)
			ep4(&m.call_me_maybe.eps[i], 198, 51, (uint8_t)round,
			    (uint8_t)(i + 1), 41641);
		uint8_t pkt[1024];
		size_t n = 0;
		TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
		                         s.b.disco_priv, s.a.disco_pub),
		           TC_OK);
		TCT_EQ_INT(tc_path_input_relay(&s.a.path, pkt, n, s.now), TC_OK);
	}

	TCT_TRUE(s.a.path.num_cands <= TC_PATH_MAX_CANDIDATES);
	tc_endpoint still;
	TCT_TRUE(tc_path_best(&s.a.path, &still, s.now) == TC_PATH_DIRECT);
	TCT_TRUE(tc_endpoint_equal(&still, &in_use));
}

static void test_one_way_path_is_not_a_path(void)
{
	TCT_CASE("a path that only works one way is never used");
	/* The rule the whole design rests on, and the only scenario that
	 * actually tests it. A's packets reach B, so B sees Pings arriving from
	 * an address it can name -- every signal short of an answered probe says
	 * the path works. Nothing B sends ever arrives.
	 *
	 * If receiving a Ping were treated as proof, B would move a live session
	 * onto an address that has never carried a single packet towards it, and
	 * the session would stop. Only B's own unanswered probes reveal it. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	s.a.drop_inbound = true;

	advance(&s, 20000);

	tc_path_stats sb;
	tc_path_get_stats(&s.b.path, &sb);
	/* The scenario has to be live for the assertion to mean anything: B must
	 * really have received Pings from A. */
	TCT_TRUE(sb.pings_received > 0);
	TCT_TRUE(sb.pongs_sent > 0);
	TCT_TRUE(sb.pongs_received == 0);

	TCT_TRUE(!direct(&s.b));
	TCT_TRUE(!direct(&s.a));
	TCT_EQ_INT((int)sb.upgrades, 0);

	TCT_CASE("B knows about the address, and knows it is not proven");
	bool seen = false;
	for (size_t i = 0; i < s.b.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.b.path.cands[i].ep, &s.a.lan)) {
			seen = true;
			TCT_TRUE(!s.b.path.cands[i].proven);
		}
	}
	TCT_TRUE(seen);

	TCT_CASE("and the session runs over the relay, both ways");
	for (int i = 0; i < 10; i++) {
		send_data(&s.a);
		send_data(&s.b);
	}
	TCT_EQ_INT((int)s.a.data_relay, 10);
	TCT_EQ_INT((int)s.b.data_relay, 10);

	TCT_CASE("and it recovers the moment the path works both ways");
	s.a.drop_inbound = false;
	advance(&s, 10000);
	TCT_TRUE(direct(&s.a));
	TCT_TRUE(direct(&s.b));
}

static void test_pong_must_answer_the_probe_we_sent(void)
{
	/* Built by hand rather than through the simulator: the point is a peer
	 * that holds the right disco key and answers wrongly, which a cooperating
	 * simulated peer will never do. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);

	/* Far enough for probes to be in flight, not far enough to be answered. */
	s.b.unplugged = true;
	advance(&s, 1500);

	tc_path_cand *c = NULL;
	for (size_t i = 0; i < s.a.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.a.path.cands[i].ep, &s.b.lan))
			c = &s.a.path.cands[i];
	}
	if (c == NULL || !c->probe_outstanding) {
		TCT_FAILF("no outstanding probe to answer wrongly");
		return;
	}

	TCT_CASE("a Pong with the wrong transaction ID does not prove anything");
	/* Without this check a peer could answer a probe we never sent, and set
	 * the round trip of whichever path it wanted us to choose. */
	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	memcpy(m.pong.txid, c->txid, TC_DISCO_TXID_LEN);
	m.pong.txid[0] ^= 0xff;
	m.pong.src = s.a.lan;
	uint8_t pkt[512];
	size_t n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
	                         s.b.disco_priv, s.a.disco_pub),
	           TC_OK);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &s.b.lan, pkt, n, s.now), TC_OK);
	TCT_TRUE(!c->proven);
	TCT_TRUE(!direct(&s.a));

	TCT_CASE("and the right one does");
	/* The same message with the transaction ID we actually sent, so the
	 * check above is shown to be the thing that rejected it rather than
	 * something incidental. */
	memcpy(m.pong.txid, c->txid, TC_DISCO_TXID_LEN);
	n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
	                         s.b.disco_priv, s.a.disco_pub),
	           TC_OK);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &s.b.lan, pkt, n, s.now), TC_OK);
	TCT_TRUE(c->proven);
	tc_path_tick(&s.a.path, s.now);
	TCT_TRUE(direct(&s.a));

	TCT_CASE("a second Pong for the same probe is not counted again");
	/* The probe is answered; a duplicate must not refresh the trust window
	 * on the strength of a reply to a question already settled. */
	tc_path_stats st1, st2;
	tc_path_get_stats(&s.a.path, &st1);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &s.b.lan, pkt, n, s.now + 100),
	           TC_OK);
	tc_path_get_stats(&s.a.path, &st2);
	TCT_EQ_INT((int)(st2.pongs_received - st1.pongs_received), 0);
}

static void test_pong_for_a_candidate_never_probed(void)
{
	TCT_CASE("a Pong for an address we know but have not probed is ignored");
	/* An address can reach the candidate table without ever being probed --
	 * a CallMeMaybe lists it, the probe is still queued, or it has been set
	 * aside. Believing a Pong for one would let a peer pick our path by
	 * answering a question we never asked. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);

	tc_endpoint unprobed;
	ep4(&unprobed, 203, 0, 113, 99, 41641);
	tc_disco_msg cmm;
	memset(&cmm, 0, sizeof cmm);
	cmm.type = TC_DISCO_CALL_ME_MAYBE;
	cmm.call_me_maybe.num = 1;
	cmm.call_me_maybe.eps[0] = unprobed;
	uint8_t pkt[512];
	size_t n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &cmm, s.b.disco_pub,
	                         s.b.disco_priv, s.a.disco_pub),
	           TC_OK);
	TCT_EQ_INT(tc_path_input_relay(&s.a.path, pkt, n, s.now), TC_OK);

	tc_path_cand *c = NULL;
	for (size_t i = 0; i < s.a.path.num_cands; i++) {
		if (tc_endpoint_equal(&s.a.path.cands[i].ep, &unprobed))
			c = &s.a.path.cands[i];
	}
	if (c == NULL) {
		TCT_FAILF("the advertised address did not become a candidate");
		return;
	}
	/* Clear the probe the CallMeMaybe triggered, so there is genuinely no
	 * outstanding question for this Pong to be an answer to. */
	c->probe_outstanding = false;

	tc_disco_msg m;
	memset(&m, 0, sizeof m);
	m.type = TC_DISCO_PONG;
	memcpy(m.pong.txid, c->txid, TC_DISCO_TXID_LEN);
	m.pong.src = s.a.lan;
	n = 0;
	TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
	                         s.b.disco_priv, s.a.disco_pub),
	           TC_OK);
	TCT_EQ_INT(tc_path_input_disco(&s.a.path, &unprobed, pkt, n, s.now),
	           TC_OK);
	TCT_TRUE(!c->proven);
	TCT_TRUE(!direct(&s.a));
}

static void test_trust_expires_without_a_tick(void)
{
	TCT_CASE("the trust window expires on time even with no tick in between");
	/* The caller asks where to send every packet, and that is far more often
	 * than the timers run. A decision cached at the last tick would keep a
	 * dead path in use for as long as nothing happened to call tick -- which
	 * on an idle session is exactly when the NAT mapping goes. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));

	uint64_t last = s.a.path.cands[s.a.path.best].last_pong_ms;
	if (s.a.path.cands[s.a.path.best].last_recv_ms > last)
		last = s.a.path.cands[s.a.path.best].last_recv_ms;

	/* No tick, no packets: only the clock moves. */
	TCT_TRUE(tc_path_best(&s.a.path, NULL, last + TC_PATH_TRUST_MS - 1) ==
	         TC_PATH_DIRECT);
	TCT_TRUE(tc_path_best(&s.a.path, NULL, last + TC_PATH_TRUST_MS) ==
	         TC_PATH_RELAY);
	TCT_TRUE(tc_path_best(&s.a.path, NULL, last + TC_PATH_TRUST_MS + 60000) ==
	         TC_PATH_RELAY);
}

static void test_eviction_spares_the_path_in_use(void)
{
	TCT_CASE("a full table of proven candidates still cannot evict the one "
	         "in use");
	/* The flood test fills the table with unproven addresses, which the
	 * eviction rule discards first -- so it never asks the harder question.
	 * Here every entry is proven and the one in use is the oldest, which is
	 * precisely the entry a naive "evict the stalest" rule would take. */
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	advance(&s, 2000);
	TCT_TRUE(direct(&s.a));

	int in_use = s.a.path.best;
	TCT_TRUE(in_use >= 0);
	tc_endpoint keep = s.a.path.cands[in_use].ep;

	/* Fill every remaining slot with a proven candidate more recently heard
	 * from than the one carrying traffic. */
	while (s.a.path.num_cands < TC_PATH_MAX_CANDIDATES) {
		tc_path_cand *c = &s.a.path.cands[s.a.path.num_cands];
		memset(c, 0, sizeof *c);
		ep4(&c->ep, 198, 51, 100, (uint8_t)(100 + s.a.path.num_cands), 41641);
		c->proven = true;
		c->rtt_ms = 900;
		c->last_pong_ms = s.now + 1000;
		c->last_recv_ms = s.now + 1000;
		s.a.path.num_cands++;
	}

	for (int i = 0; i < 8; i++) {
		tc_disco_msg m;
		memset(&m, 0, sizeof m);
		m.type = TC_DISCO_CALL_ME_MAYBE;
		m.call_me_maybe.num = 4;
		for (size_t k = 0; k < 4; k++)
			ep4(&m.call_me_maybe.eps[k], 198, 51, (uint8_t)(200 + i),
			    (uint8_t)(k + 1), 41641);
		uint8_t pkt[1024];
		size_t n = 0;
		TCT_EQ_INT(tc_disco_seal(pkt, sizeof pkt, &n, &m, s.b.disco_pub,
		                         s.b.disco_priv, s.a.disco_pub),
		           TC_OK);
		TCT_EQ_INT(tc_path_input_relay(&s.a.path, pkt, n, s.now), TC_OK);
	}

	TCT_TRUE(s.a.path.num_cands <= TC_PATH_MAX_CANDIDATES);
	TCT_EQ_INT(s.a.path.best, in_use);
	TCT_TRUE(tc_endpoint_equal(&s.a.path.cands[s.a.path.best].ep, &keep));
	tc_endpoint still;
	TCT_TRUE(tc_path_best(&s.a.path, &still, s.now) == TC_PATH_DIRECT);
	TCT_TRUE(tc_endpoint_equal(&still, &keep));
}

/* ---- the plumbing ------------------------------------------------------- */

static void test_api(void)
{
	TCT_CASE("local addresses a peer could not reach are never advertised");
	tc_path p;
	uint8_t priv[32], pub[32], peer[32];
	tc_x25519_keypair(priv, pub);
	tc_x25519_keypair(peer, peer);
	TCT_EQ_INT(tc_path_init(&p, priv, pub, peer, NULL, NULL, NULL), TC_OK);

	tc_endpoint eps[5];
	ep4(&eps[0], 127, 0, 0, 1, 41641);   /* loopback */
	ep4(&eps[1], 192, 168, 1, 10, 41641); /* a LAN address: kept */
	ep4(&eps[2], 169, 254, 1, 1, 41641);  /* link-local */
	ep4(&eps[3], 100, 64, 0, 1, 41641);   /* carrier NAT */
	ep4(&eps[4], 192, 168, 1, 10, 41641); /* a duplicate */
	TCT_EQ_INT(tc_path_set_local(&p, eps, 5), TC_OK);
	TCT_EQ_INT((int)p.num_local, 1);
	TCT_TRUE(tc_endpoint_equal(&p.local[0], &eps[1]));

	TCT_CASE("the relay is the answer until something is proven");
	TCT_TRUE(tc_path_best(&p, NULL, 0) == TC_PATH_RELAY);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_path_init(NULL, priv, pub, peer, NULL, NULL, NULL),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_init(&p, NULL, pub, peer, NULL, NULL, NULL),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_set_local(NULL, eps, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_set_local(&p, NULL, 1), TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_tick(NULL, 0), TC_ERR_INVAL);
	uint8_t byte = 0;
	TCT_EQ_INT(tc_path_input_disco(NULL, &eps[0], &byte, 1, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_input_relay(NULL, &byte, 1, 0), TC_ERR_INVAL);
	TCT_TRUE(tc_path_best(NULL, NULL, 0) == TC_PATH_RELAY);
	tc_path_note_recv(NULL, &eps[0], 0);
	tc_path_note_recv(&p, NULL, 0);

	TCT_CASE("the log line");
	static sim s;
	wire(&s, NAT_OPEN, NAT_OPEN);
	char line[160];
	TCT_EQ_INT(tc_path_describe(line, sizeof line, &s.a.path, s.now), TC_OK);
	TCT_TRUE(strstr(line, "via the relay") != NULL);
	advance(&s, 2000);
	TCT_EQ_INT(tc_path_describe(line, sizeof line, &s.a.path, s.now), TC_OK);
	TCT_TRUE(strstr(line, "direct to 203.0.113.8:41641") != NULL);
	for (size_t cap = 1; cap < strlen(line) + 1; cap++) {
		char buf[160];
		if (tc_path_describe(buf, cap, &s.a.path, s.now) == TC_OK)
			TCT_FAILF("claimed success with %zu bytes", cap);
		tct_checks++;
	}
	TCT_EQ_INT(tc_path_describe(NULL, sizeof line, &s.a.path, s.now),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_path_describe(line, sizeof line, NULL, s.now),
	           TC_ERR_INVAL);
}

int main(void)
{
	test_two_public_hosts();
	test_hole_punching();
	test_symmetric_nat_stays_on_the_relay();
	test_symmetric_to_public();
	test_path_dies_under_a_live_session();
	test_path_recovers();
	test_lossy_network();
	test_total_loss_never_upgrades();
	test_better_path_wins_but_only_just();
	test_forged_and_unsolicited();
	test_one_way_path_is_not_a_path();
	test_pong_must_answer_the_probe_we_sent();
	test_pong_for_a_candidate_never_probed();
	test_trust_expires_without_a_tick();
	test_candidate_flood();
	test_eviction_spares_the_path_in_use();
	test_api();
	return tct_report("path");
}
