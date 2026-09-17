/* SPDX-License-Identifier: BSD-3-Clause
 *
 * netcheck, driven by hand.
 *
 * The clock and the network are both arguments here, so a check with a three
 * second budget, three retransmit rounds and a deadline runs in microseconds
 * and does it the same way every time. That is the reason the scheduling was
 * separated from the socket: none of what follows -- latency ordering,
 * retransmits, answers that arrive after the deadline, a response bearing a
 * transaction ID we never sent, a response from the wrong address -- could be
 * tested at all against live servers, and this project does not put load on
 * Tailscale's infrastructure to check its own arithmetic.
 *
 * tc_netcheck_run, the loop that wires this to a real socket, is exercised
 * separately at the bottom against STUN responders on loopback.
 */

#include "tc/netcheck.h"

#include "tctest.h"

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- a map to probe ---------------------------------------------------- */

/* build_map makes a map of n regions, region IDs 101, 102, ... Each node
 * carries a documentation-range IPv4 address and, when v6 is set, an IPv6
 * one, so a test can control exactly which probes get built. */
/* A monotonic millisecond clock, for the one test that measures duration.
 * CLOCK_MONOTONIC cannot step, which is the entire reason to prefer it here. */
static uint64_t mono_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void build_map(tc_derp_map *m, size_t n, bool v6)
{
	memset(m, 0, sizeof *m);
	for (size_t i = 0; i < n; i++) {
		tc_derp_region *r = &m->regions[i];
		r->region_id = (int64_t)(101 + i);
		snprintf(r->region_code, sizeof r->region_code, "r%zu", i);
		r->num_nodes = 1;
		tc_derp_node *node = &r->nodes[0];
		snprintf(node->name, sizeof node->name, "%zua", i);
		snprintf(node->hostname, sizeof node->hostname, "r%zu.example", i);
		snprintf(node->ipv4, sizeof node->ipv4, "203.0.113.%zu", i + 1);
		if (v6)
			snprintf(node->ipv6, sizeof node->ipv6, "2001:db8::%zu", i + 1);
		node->stun_port = 3478;
		node->region_id = r->region_id;
	}
	m->num_regions = n;
}

/* answer builds the response a server at *from would send for a request,
 * reporting *mapped as where it saw us. */
static size_t answer(uint8_t *out, size_t cap, const uint8_t *req,
                     const tc_endpoint *mapped)
{
	uint8_t txid[TC_STUN_TXID_LEN];
	memcpy(txid, req + 8, TC_STUN_TXID_LEN);
	size_t n = 0;
	if (tc_stun_build_response(out, cap, &n, txid, mapped) != TC_OK)
		return 0;
	return n;
}

static void mapped_v4(tc_endpoint *ep, uint8_t last, uint16_t port)
{
	memset(ep, 0, sizeof *ep);
	ep->ip[0] = 198;
	ep->ip[1] = 51;
	ep->ip[2] = 100;
	ep->ip[3] = last;
	ep->ip_len = 4;
	ep->port = port;
}

/* ---- the core ---------------------------------------------------------- */

static void test_probe_set(void)
{
	TCT_CASE("one probe per family per region");
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 3, true);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 6);
	TCT_EQ_INT((int)nc.report.num_regions, 3);

	TCT_CASE("a map with no IPv6 yields only IPv4 probes");
	build_map(&m, 3, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 3);

	TCT_CASE("max_regions bounds the probing, in map order");
	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.max_regions = 2;
	build_map(&m, 5, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, &o, 1000), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 2);
	TCT_EQ_INT((int)nc.report.num_regions, 2);
	TCT_EQ_INT((int)nc.report.regions[0].region_id, 101);
	TCT_EQ_INT((int)nc.report.regions[1].region_id, 102);

	TCT_CASE("a region with no nodes still appears, with no latency");
	/* Dropping it would renumber the report against the map and make the
	 * region IDs the only safe way to read it. Keeping it is honest: we know
	 * the region exists and we know nothing about its latency. */
	build_map(&m, 3, false);
	m.regions[1].num_nodes = 0;
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 2);
	TCT_EQ_INT((int)nc.report.num_regions, 3);
	TCT_EQ_INT(nc.report.regions[1].rtt_v4_ms, -1);

	TCT_CASE("a map that yields no probe at all is refused");
	memset(&m, 0, sizeof m);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_ERR_INVAL);
	build_map(&m, 2, false);
	m.regions[0].nodes[0].ipv4[0] = '\0';
	m.regions[1].nodes[0].ipv4[0] = '\0';
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_ERR_INVAL);

	TCT_CASE("an unparseable literal is skipped, not fatal");
	build_map(&m, 2, false);
	snprintf(m.regions[0].nodes[0].ipv4, sizeof m.regions[0].nodes[0].ipv4,
	         "not-an-address");
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 1000), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 1);

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_netcheck_begin(NULL, &m, NULL, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_begin(&nc, NULL, NULL, 0), TC_ERR_INVAL);
}

static void test_transaction_ids_differ(void)
{
	TCT_CASE("every probe gets its own transaction ID");
	/* It is the only thing tying an answer to a question on an
	 * unauthenticated exchange. Two probes sharing one would make the first
	 * answer count for both, and the second region's latency would be the
	 * first's. */
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 8, true);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 16);
	for (size_t i = 0; i < nc.num_probes; i++) {
		for (size_t j = i + 1; j < nc.num_probes; j++) {
			if (memcmp(nc.probes[i].txid, nc.probes[j].txid,
			           TC_STUN_TXID_LEN) == 0)
				TCT_FAILF("probes %zu and %zu share a transaction ID", i, j);
			tct_checks++;
		}
	}

	TCT_CASE("and two checks in a row do not reuse them");
	uint8_t first[TC_STUN_TXID_LEN];
	memcpy(first, nc.probes[0].txid, sizeof first);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	TCT_TRUE(memcmp(first, nc.probes[0].txid, sizeof first) != 0);
}

static void test_schedule(void)
{
	TCT_CASE("all probes go out at once, then retransmit in rounds");
	/* Sequential probing would cost regions x timeout; sending everything
	 * and waiting once costs the timeout. That is the whole reason netcheck
	 * is a state machine rather than a loop of blocking round trips. */
	tc_derp_map m;
	tc_netcheck nc;
	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.timeout_ms = 3000; /* three rounds, 1000ms apart */
	build_map(&m, 4, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, &o, 10000), TC_OK);

	tc_endpoint dst;
	uint8_t req[TC_STUN_REQUEST_LEN];
	int wait = 0;

	int sent = 0;
	while (tc_netcheck_next_send(&nc, 10000, &dst, req, &wait) == TC_OK)
		sent++;
	TCT_EQ_INT(sent, 4);

	TCT_CASE("nothing more is due until the next round");
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 10000, &dst, req, &wait),
	           TC_ERR_TIMEOUT);
	TCT_EQ_INT(wait, 1000);

	TCT_CASE("the second round resends the same transaction IDs");
	/* A different ID per retry would mean an answer to the first copy no
	 * longer matched anything -- turning a slow path into a dead one. */
	uint8_t was[4][TC_STUN_TXID_LEN];
	for (size_t i = 0; i < 4; i++)
		memcpy(was[i], nc.probes[i].txid, TC_STUN_TXID_LEN);
	sent = 0;
	while (tc_netcheck_next_send(&nc, 11000, &dst, req, &wait) == TC_OK)
		sent++;
	TCT_EQ_INT(sent, 4);
	for (size_t i = 0; i < 4; i++)
		TCT_EQ_MEM(nc.probes[i].txid, was[i], TC_STUN_TXID_LEN);

	TCT_CASE("a third round, and then no sends left");
	sent = 0;
	while (tc_netcheck_next_send(&nc, 12000, &dst, req, &wait) == TC_OK)
		sent++;
	TCT_EQ_INT(sent, 4);

	/* Out of sends but not out of time: still waiting, because a late answer
	 * is a real measurement and giving up early would discard it. */
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 12100, &dst, req, &wait),
	           TC_ERR_TIMEOUT);
	TCT_EQ_INT(wait, 900);

	TCT_CASE("and the deadline ends it");
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 13000, &dst, req, &wait),
	           TC_ERR_DONE);
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 99999, &dst, req, &wait),
	           TC_ERR_DONE);
}

static void test_early_exit(void)
{
	TCT_CASE("a check ends as soon as every probe is answered");
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 3, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);

	tc_endpoint dst[3];
	uint8_t req[3][TC_STUN_REQUEST_LEN];
	int wait = 0;
	for (size_t i = 0; i < 3; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);

	tc_endpoint mapped;
	mapped_v4(&mapped, 5, 41641);
	for (size_t i = 0; i < 3; i++) {
		uint8_t rsp[256];
		size_t n = answer(rsp, sizeof rsp, req[i], &mapped);
		TCT_TRUE(n > 0);
		TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[i], rsp, n, 20), TC_OK);
	}

	/* No waiting out the remaining budget when there is nothing to wait for. */
	tc_endpoint d;
	uint8_t r[TC_STUN_REQUEST_LEN];
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 20, &d, r, &wait), TC_ERR_DONE);
}

static void test_latency_and_preference(void)
{
	TCT_CASE("the quickest region to answer is the preferred one");
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 4, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);

	tc_endpoint dst[4];
	uint8_t req[4][TC_STUN_REQUEST_LEN];
	int wait = 0;
	for (size_t i = 0; i < 4; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);

	tc_endpoint mapped;
	mapped_v4(&mapped, 5, 41641);
	static const int kRtt[4] = { 90, 12, 250, 40 };
	for (size_t i = 0; i < 4; i++) {
		uint8_t rsp[256];
		size_t n = answer(rsp, sizeof rsp, req[i], &mapped);
		TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[i], rsp, n,
		                              (uint64_t)kRtt[i]),
		           TC_OK);
	}

	tc_netcheck_report rep;
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, 90);
	TCT_EQ_INT(rep.regions[1].rtt_v4_ms, 12);
	TCT_EQ_INT(rep.regions[2].rtt_v4_ms, 250);
	TCT_EQ_INT(rep.regions[3].rtt_v4_ms, 40);
	TCT_EQ_INT((int)rep.preferred_region, 102);
	TCT_TRUE(rep.udp);
	TCT_TRUE(rep.ipv4);
	TCT_TRUE(!rep.ipv6);

	TCT_CASE("a region that never answers is not preferred");
	build_map(&m, 3, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	tc_endpoint d2[3];
	uint8_t r2[3][TC_STUN_REQUEST_LEN];
	for (size_t i = 0; i < 3; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &d2[i], r2[i], &wait), TC_OK);
	uint8_t rsp[256];
	size_t n = answer(rsp, sizeof rsp, r2[2], &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &d2[2], rsp, n, 300), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT((int)rep.preferred_region, 103);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, -1);

	TCT_CASE("nothing answered means no preference, which is not an error");
	/* Reporting region zero lets the caller keep whatever it would have
	 * used; inventing a preference from no data would be worse than the
	 * heuristic this replaces. */
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT((int)rep.preferred_region, 0);
	TCT_TRUE(!rep.udp);

	TCT_CASE("a tie goes to the earlier region, so the choice is stable");
	build_map(&m, 3, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	for (size_t i = 0; i < 3; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &d2[i], r2[i], &wait), TC_OK);
	for (size_t i = 0; i < 3; i++) {
		n = answer(rsp, sizeof rsp, r2[i], &mapped);
		TCT_EQ_INT(tc_netcheck_handle(&nc, &d2[i], rsp, n, 25), TC_OK);
	}
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT((int)rep.preferred_region, 101);
}

static void test_families(void)
{
	TCT_CASE("a region reachable on either family uses the better one");
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 2, true);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	TCT_EQ_INT((int)nc.num_probes, 4);

	tc_endpoint dst[4];
	uint8_t req[4][TC_STUN_REQUEST_LEN];
	int wait = 0;
	for (size_t i = 0; i < 4; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);

	/* Probes are built v4 then v6 per region: r101-v4, r101-v6, r102-v4,
	 * r102-v6. Region 101 is slow over v4 and quick over v6; region 102 is
	 * middling over v4 and unreachable over v6. */
	tc_endpoint m4, m6;
	mapped_v4(&m4, 5, 41641);
	memset(&m6, 0, sizeof m6);
	m6.ip[0] = 0x20;
	m6.ip[1] = 0x01;
	m6.ip[2] = 0x0d;
	m6.ip[3] = 0xb8;
	m6.ip[15] = 0x09;
	m6.ip_len = 16;
	m6.port = 41641;

	uint8_t rsp[256];
	size_t n;
	n = answer(rsp, sizeof rsp, req[0], &m4);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 200), TC_OK);
	n = answer(rsp, sizeof rsp, req[1], &m6);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], rsp, n, 15), TC_OK);
	n = answer(rsp, sizeof rsp, req[2], &m4);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[2], rsp, n, 50), TC_OK);

	tc_netcheck_report rep;
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, 200);
	TCT_EQ_INT(rep.regions[0].rtt_v6_ms, 15);
	TCT_EQ_INT(rep.regions[1].rtt_v4_ms, 50);
	TCT_EQ_INT(rep.regions[1].rtt_v6_ms, -1);
	TCT_EQ_INT((int)rep.preferred_region, 101);
	TCT_TRUE(rep.ipv4);
	TCT_TRUE(rep.ipv6);

	TCT_CASE("and each family's mapped address is reported separately");
	TCT_EQ_INT(rep.global_v4.ip_len, 4);
	TCT_EQ_INT(rep.global_v6.ip_len, 16);
	char s[80];
	TCT_EQ_INT(tc_endpoint_format(s, sizeof s, &rep.global_v6), TC_OK);
	TCT_EQ_STR(s, "[2001:db8::9]:41641");
}

static void test_mapping_varies(void)
{
	tc_derp_map m;
	tc_netcheck nc;
	tc_endpoint dst[3];
	uint8_t req[3][TC_STUN_REQUEST_LEN], rsp[256];
	int wait = 0;
	size_t n;
	tc_netcheck_report rep;

	TCT_CASE("one answer says nothing about whether the mapping varies");
	/* It takes two servers to notice a difference. Reporting "stable" from a
	 * single observation would have us advertise an address that only works
	 * for the one server that told us about it. */
	build_map(&m, 3, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	for (size_t i = 0; i < 3; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);
	tc_endpoint a;
	mapped_v4(&a, 5, 41641);
	n = answer(rsp, sizeof rsp, req[0], &a);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 10), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_TRUE(!rep.mapping_varies_known);

	TCT_CASE("two servers agreeing means an endpoint-independent mapping");
	n = answer(rsp, sizeof rsp, req[1], &a);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], rsp, n, 20), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_TRUE(rep.mapping_varies_known);
	TCT_TRUE(!rep.mapping_varies);

	TCT_CASE("a third that disagrees flips it, and it stays flipped");
	/* Once two servers have reported different addresses, a later pair that
	 * happen to agree does not undo the pair that did not. */
	tc_endpoint b;
	mapped_v4(&b, 5, 51000); /* same IP, different port: still symmetric */
	n = answer(rsp, sizeof rsp, req[2], &b);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[2], rsp, n, 30), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_TRUE(rep.mapping_varies_known);
	TCT_TRUE(rep.mapping_varies);

	TCT_CASE("a different IP counts too, not just a different port");
	build_map(&m, 2, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	for (size_t i = 0; i < 2; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);
	n = answer(rsp, sizeof rsp, req[0], &a);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 10), TC_OK);
	tc_endpoint c;
	mapped_v4(&c, 200, 41641);
	n = answer(rsp, sizeof rsp, req[1], &c);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], rsp, n, 20), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_TRUE(rep.mapping_varies);

	TCT_CASE("the first address seen is the one reported");
	TCT_EQ_INT(rep.global_v4.ip_len, 4);
	TCT_TRUE(tc_endpoint_equal(&rep.global_v4, &a));
}

static void test_rejects(void)
{
	tc_derp_map m;
	tc_netcheck nc;
	tc_endpoint dst[2];
	uint8_t req[2][TC_STUN_REQUEST_LEN], rsp[256];
	int wait = 0;
	size_t n;

	build_map(&m, 2, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);
	for (size_t i = 0; i < 2; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);
	tc_endpoint mapped;
	mapped_v4(&mapped, 5, 41641);

	TCT_CASE("a response bearing a transaction ID we never sent is ignored");
	uint8_t fake[TC_STUN_REQUEST_LEN];
	memcpy(fake, req[0], sizeof fake);
	fake[8] ^= 0xff;
	n = answer(rsp, sizeof rsp, fake, &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 10), TC_ERR_INVAL);

	TCT_CASE("a correct transaction ID from the wrong address is ignored");
	/* Guessing 96 bits is hard; guessing them and also sourcing from the
	 * relay's address is harder, and this check costs one comparison. An
	 * off-path forgery here would set our idea of our own public address,
	 * which is what we then hand to peers. */
	n = answer(rsp, sizeof rsp, req[0], &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], rsp, n, 10), TC_ERR_INVAL);

	TCT_CASE("and from the right address it counts");
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 10), TC_OK);

	TCT_CASE("a duplicate answer does not count twice");
	/* Retransmits mean duplicates are expected, not suspicious. Counting one
	 * would overwrite a measured round trip with a later one. */
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 500), TC_ERR_INVAL);
	tc_netcheck_report rep;
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, 10);

	TCT_CASE("packets that are not STUN at all");
	static const uint8_t junk[64] = { 0 };
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], junk, sizeof junk, 10),
	           TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], req[1], sizeof req[1], 10),
	           TC_ERR_INVAL); /* a request, not a response */

	TCT_CASE("every prefix of a real response is refused");
	for (size_t k = 0; k < n; k++) {
		if (tc_netcheck_handle(&nc, &dst[1], rsp, k, 10) == TC_OK)
			TCT_FAILF("accepted a %zu byte response", k);
		tct_checks++;
	}

	TCT_CASE("null arguments");
	TCT_EQ_INT(tc_netcheck_handle(NULL, &dst[0], rsp, n, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_handle(&nc, NULL, rsp, n, 0), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], NULL, n, 0), TC_ERR_INVAL);
	tc_endpoint d;
	uint8_t r[TC_STUN_REQUEST_LEN];
	TCT_EQ_INT(tc_netcheck_next_send(NULL, 0, &d, r, &wait), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, NULL, r, &wait), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &d, NULL, &wait), TC_ERR_INVAL);
	tc_netcheck_finish(NULL, &rep); /* must not crash */
	tc_netcheck_finish(&nc, NULL);
}

static void test_late_answer(void)
{
	TCT_CASE("an answer arriving after the deadline is still recorded");
	/* The loop stops asking at the deadline, but a packet already in the
	 * buffer is a real measurement and discarding it would be arbitrary. */
	tc_derp_map m;
	tc_netcheck nc;
	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.timeout_ms = 1000;
	build_map(&m, 1, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, &o, 0), TC_OK);

	tc_endpoint dst;
	uint8_t req[TC_STUN_REQUEST_LEN];
	int wait = 0;
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst, req, &wait), TC_OK);
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 5000, &dst, req, &wait),
	           TC_ERR_DONE);

	tc_endpoint mapped;
	mapped_v4(&mapped, 5, 41641);
	uint8_t rsp[256];
	size_t n = answer(rsp, sizeof rsp, req, &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst, rsp, n, 1200), TC_OK);
	tc_netcheck_report rep;
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, 1200);
	TCT_EQ_INT((int)rep.preferred_region, 101);

	TCT_CASE("a clock that goes backwards reports zero, not a huge number");
	/* now is an argument, so nothing here stops a caller passing a value
	 * below sent_ms. An unsigned subtraction would make that half the range
	 * of a uint64 and the fastest region in the world. */
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, &o, 0), TC_OK);
	TCT_EQ_INT(tc_netcheck_next_send(&nc, 500, &dst, req, &wait), TC_OK);
	n = answer(rsp, sizeof rsp, req, &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst, rsp, n, 100), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, 0);
}

static void test_describe(void)
{
	TCT_CASE("the log line, which is the only thing a user sees of this");
	tc_derp_map m;
	tc_netcheck nc;
	build_map(&m, 2, false);
	TCT_EQ_INT(tc_netcheck_begin(&nc, &m, NULL, 0), TC_OK);

	char s[200];
	tc_netcheck_report rep;
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(tc_netcheck_describe(s, sizeof s, &rep, &m), TC_OK);
	TCT_EQ_STR(s, "no STUN answer; UDP looks blocked");

	tc_endpoint dst[2];
	uint8_t req[2][TC_STUN_REQUEST_LEN], rsp[256];
	int wait = 0;
	for (size_t i = 0; i < 2; i++)
		TCT_EQ_INT(tc_netcheck_next_send(&nc, 0, &dst[i], req[i], &wait),
		           TC_OK);
	tc_endpoint mapped;
	mapped_v4(&mapped, 5, 41641);
	size_t n = answer(rsp, sizeof rsp, req[1], &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[1], rsp, n, 24), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(tc_netcheck_describe(s, sizeof s, &rep, &m), TC_OK);
	TCT_EQ_STR(s, "region 102 (r1) 24ms; 198.51.100.5:41641; mapping unknown");

	n = answer(rsp, sizeof rsp, req[0], &mapped);
	TCT_EQ_INT(tc_netcheck_handle(&nc, &dst[0], rsp, n, 80), TC_OK);
	tc_netcheck_finish(&nc, &rep);
	TCT_EQ_INT(tc_netcheck_describe(s, sizeof s, &rep, &m), TC_OK);
	TCT_EQ_STR(s,
	           "region 102 (r1) 24ms; 198.51.100.5:41641; mapping is stable");

	TCT_CASE("a buffer too small is an error, not a truncated line");
	for (size_t cap = 1; cap < strlen(s) + 1; cap++) {
		char buf[200];
		if (tc_netcheck_describe(buf, cap, &rep, &m) == TC_OK)
			TCT_FAILF("claimed success with %zu bytes", cap);
		tct_checks++;
	}
	TCT_EQ_INT(tc_netcheck_describe(NULL, sizeof s, &rep, &m), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_describe(s, sizeof s, NULL, &m), TC_ERR_INVAL);

	TCT_CASE("and it works without a map to name the region");
	TCT_EQ_INT(tc_netcheck_describe(s, sizeof s, &rep, NULL), TC_OK);
	TCT_EQ_STR(s, "region 102 24ms; 198.51.100.5:41641; mapping is stable");
}

/* ---- the loop, against real sockets ------------------------------------ */

/* A STUN responder on loopback, in a child process. Sockets and a fork are
 * cheaper than mocking out tc_udp, and this is the only way to find out
 * whether the loop wired to a real socket does what the state machine says.
 * The responder delays before answering so the latency ordering is ours to
 * choose rather than the kernel's. */
static pid_t spawn_responder(uint16_t *out_port, int delay_ms,
                             const tc_endpoint *mapped)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
		close(fd);
		return -1;
	}
	socklen_t alen = sizeof a;
	if (getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
		close(fd);
		return -1;
	}
	*out_port = ntohs(a.sin_port);

	pid_t pid = fork();
	if (pid < 0) {
		close(fd);
		return -1;
	}
	if (pid > 0) {
		close(fd); /* the child owns it now */
		return pid;
	}

	/* Child. */
	for (;;) {
		uint8_t buf[512];
		struct sockaddr_in from;
		socklen_t flen = sizeof from;
		ssize_t got = recvfrom(fd, buf, sizeof buf, 0,
		                       (struct sockaddr *)&from, &flen);
		if (got < (ssize_t)TC_STUN_REQUEST_LEN)
			continue;
		if (delay_ms > 0) {
			struct timespec ts = { delay_ms / 1000,
				                   (long)(delay_ms % 1000) * 1000000L };
			nanosleep(&ts, NULL);
		}
		uint8_t rsp[256];
		size_t n = answer(rsp, sizeof rsp, buf, mapped);
		if (n > 0)
			sendto(fd, rsp, n, 0, (struct sockaddr *)&from, flen);
	}
	_exit(0);
}

static void test_run_loop(void)
{
	TCT_CASE("the loop, wired to real sockets on loopback");

	tc_endpoint m1, m2;
	mapped_v4(&m1, 5, 41641);
	mapped_v4(&m2, 5, 41641);

	uint16_t p1 = 0, p2 = 0;
	pid_t c1 = spawn_responder(&p1, 120, &m1);
	pid_t c2 = spawn_responder(&p2, 0, &m2);
	if (c1 < 0 || c2 < 0) {
		TCT_FAILF("could not start the responders");
		return;
	}

	tc_derp_map m;
	build_map(&m, 2, false);
	snprintf(m.regions[0].nodes[0].ipv4, sizeof m.regions[0].nodes[0].ipv4,
	         "127.0.0.1");
	snprintf(m.regions[1].nodes[0].ipv4, sizeof m.regions[1].nodes[0].ipv4,
	         "127.0.0.1");
	m.regions[0].nodes[0].stun_port = p1;
	m.regions[1].nodes[0].stun_port = p2;
	m.regions[0].nodes[0].ipv6[0] = '\0';
	m.regions[1].nodes[0].ipv6[0] = '\0';

	tc_udp u;
	if (tc_udp_open(&u, 0) != TC_OK) {
		TCT_FAILF("could not open a UDP socket");
		kill(c1, SIGKILL);
		kill(c2, SIGKILL);
		return;
	}

	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.timeout_ms = 2000;

	tc_netcheck_report rep;
	TCT_EQ_INT(tc_netcheck_run(&rep, &m, &u, &o, NULL, NULL), TC_OK);

	TCT_TRUE(rep.udp);
	TCT_TRUE(rep.ipv4);
	TCT_EQ_INT((int)rep.num_regions, 2);
	TCT_TRUE(rep.regions[0].rtt_v4_ms >= 0);
	TCT_TRUE(rep.regions[1].rtt_v4_ms >= 0);

	/* The delayed responder must be the slower of the two, and the quicker
	 * one must be preferred. Anything else means the loop is measuring
	 * something other than the round trip. */
	if (rep.regions[0].rtt_v4_ms <= rep.regions[1].rtt_v4_ms)
		TCT_FAILF("the delayed region was not slower: %d vs %d",
		          rep.regions[0].rtt_v4_ms, rep.regions[1].rtt_v4_ms);
	tct_checks++;
	TCT_EQ_INT((int)rep.preferred_region, 102);

	/* Both responders report the same mapped address, so the mapping looks
	 * stable -- which is also the true answer for loopback. */
	TCT_TRUE(rep.mapping_varies_known);
	TCT_TRUE(!rep.mapping_varies);
	TCT_EQ_INT(rep.global_v4.ip_len, 4);

	TCT_CASE("a region with nothing listening times out without hanging");
	/* The budget is for the whole check, not per probe, so one dead region
	 * must not cost the timeout on top of everything else. */
	kill(c1, SIGKILL);
	waitpid(c1, NULL, 0);
	/* Monotonic, not time(NULL). The wall clock can step backwards -- WSL
	 * resynchronises to the Windows host, and NTP does it anywhere -- and
	 * this failed about one run in fifteen with an elapsed time of
	 * 18446744073709551615, which is what a one-second step back looks like
	 * after an unsigned subtraction. A flake in a test whose whole subject
	 * is elapsed time is worse than useless: it trains you to rerun it. */
	uint64_t t0 = mono_ms();
	TCT_EQ_INT(tc_netcheck_run(&rep, &m, &u, &o, NULL, NULL), TC_OK);
	uint64_t t1 = mono_ms();
	uint64_t elapsed_ms = t1 > t0 ? t1 - t0 : 0;
	if (elapsed_ms > 5000)
		TCT_FAILF("a 2000ms check took %llums",
		          (unsigned long long)elapsed_ms);
	tct_checks++;
	TCT_EQ_INT(rep.regions[0].rtt_v4_ms, -1);
	TCT_TRUE(rep.regions[1].rtt_v4_ms >= 0);
	TCT_EQ_INT((int)rep.preferred_region, 102);

	kill(c2, SIGKILL);
	waitpid(c2, NULL, 0);
	tc_udp_close(&u);

	TCT_CASE("and with nothing listening anywhere, UDP is reported blocked");
	build_map(&m, 1, false);
	snprintf(m.regions[0].nodes[0].ipv4, sizeof m.regions[0].nodes[0].ipv4,
	         "127.0.0.1");
	m.regions[0].nodes[0].ipv6[0] = '\0';
	m.regions[0].nodes[0].stun_port = p1; /* the port we just killed */
	TCT_EQ_INT(tc_udp_open(&u, 0), TC_OK);
	o.timeout_ms = 300;
	TCT_EQ_INT(tc_netcheck_run(&rep, &m, &u, &o, NULL, NULL), TC_OK);
	TCT_TRUE(!rep.udp);
	TCT_EQ_INT((int)rep.preferred_region, 0);
	tc_udp_close(&u);

	TCT_CASE("null arguments to the loop");
	TCT_EQ_INT(tc_netcheck_run(NULL, &m, &u, &o, NULL, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_run(&rep, NULL, &u, &o, NULL, NULL), TC_ERR_INVAL);
	TCT_EQ_INT(tc_netcheck_run(&rep, &m, NULL, &o, NULL, NULL), TC_ERR_INVAL);
}

int main(void)
{
	/* A responder that outlives us would hold a port; a child that dies
	 * while we are writing to it must not take us with it. */
	signal(SIGPIPE, SIG_IGN);

	test_probe_set();
	test_transaction_ids_differ();
	test_schedule();
	test_early_exit();
	test_latency_and_preference();
	test_families();
	test_mapping_varies();
	test_rejects();
	test_late_answer();
	test_describe();
	test_run_loop();
	return tct_report("netcheck");
}
