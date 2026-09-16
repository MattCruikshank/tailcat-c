/* SPDX-License-Identifier: BSD-3-Clause
 *
 * See netcheck.h.
 */

#include "tc/netcheck.h"

#include "tc/crypto.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---- building the probe set -------------------------------------------- */

static uint16_t stun_port_for(const tc_derp_node *n,
                              const tc_netcheck_opts *opts)
{
	if (n->stun_port > 0 && n->stun_port <= 65535)
		return (uint16_t)n->stun_port;
	if (opts->stun_port != 0)
		return opts->stun_port;
	return TC_NETCHECK_DEFAULT_STUN_PORT;
}

/* resolve_one looks a hostname up. Off unless asked for: the published map
 * carries literal addresses for every node, and a blocking DNS lookup inside
 * what is meant to be a bounded measurement would make the budget a lie. */
static int resolve_one(tc_endpoint *out, const char *host, uint16_t port,
                       bool want_v6)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = want_v6 ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo *res = NULL;
	if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL)
		return TC_ERR_INVAL;

	int rc = TC_ERR_INVAL;
	if (res->ai_family == AF_INET && res->ai_addrlen >= sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)res->ai_addr;
		memset(out, 0, sizeof *out);
		memcpy(out->ip, &s4->sin_addr, 4);
		out->ip_len = 4;
		out->port = port;
		rc = TC_OK;
	} else if (res->ai_family == AF_INET6 &&
	           res->ai_addrlen >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *s6 =
		    (const struct sockaddr_in6 *)res->ai_addr;
		uint8_t raw[16];
		memcpy(raw, &s6->sin6_addr, 16);
		tc_endpoint_from16(out, raw, port);
		rc = TC_OK;
	}
	freeaddrinfo(res);
	return rc;
}

static int add_probe(tc_netcheck *nc, const tc_endpoint *dst,
                     size_t region_idx, bool v6, uint64_t now)
{
	if (nc->num_probes >= TC_NETCHECK_MAX_PROBES)
		return TC_ERR_TOOMANY;
	tc_netcheck_probe *p = &nc->probes[nc->num_probes];
	memset(p, 0, sizeof *p);
	/* From the CSPRNG, because on an unauthenticated UDP exchange the
	 * transaction ID is the only thing tying an answer to a question. A probe
	 * we cannot name is one whose answer we could not trust, so this fails the
	 * check rather than falling back to something weaker. */
	if (tc_random_bytes(p->txid, TC_STUN_TXID_LEN) != TC_OK)
		return TC_ERR_INVAL;
	p->dst = *dst;
	p->region_idx = region_idx;
	p->v6 = v6;
	p->sends_left = TC_NETCHECK_SENDS;
	p->due_ms = now;
	nc->num_probes++;
	return TC_OK;
}

int tc_netcheck_begin(tc_netcheck *nc, const tc_derp_map *m,
                      const tc_netcheck_opts *opts, uint64_t now_ms_)
{
	if (nc == NULL || m == NULL)
		return TC_ERR_INVAL;

	tc_netcheck_opts defaults;
	if (opts == NULL) {
		memset(&defaults, 0, sizeof defaults);
		opts = &defaults;
	}

	memset(nc, 0, sizeof *nc);
	nc->timeout_ms = (opts->timeout_ms > 0) ? opts->timeout_ms
	                                        : TC_NETCHECK_DEFAULT_TIMEOUT_MS;
	nc->start_ms = now_ms_;
	nc->deadline_ms = now_ms_ + (uint64_t)nc->timeout_ms;

	size_t limit = m->num_regions;
	if (opts->max_regions > 0 && opts->max_regions < limit)
		limit = opts->max_regions;
	if (limit > TC_DERPMAP_MAX_REGIONS)
		limit = TC_DERPMAP_MAX_REGIONS;

	for (size_t i = 0; i < limit; i++) {
		const tc_derp_region *reg = &m->regions[i];
		tc_netcheck_region *rr = &nc->report.regions[nc->report.num_regions];
		rr->region_id = reg->region_id;
		rr->rtt_v4_ms = -1;
		rr->rtt_v6_ms = -1;
		size_t idx = nc->report.num_regions;
		nc->report.num_regions++;

		if (reg->num_nodes == 0)
			continue;
		/* One node per region. Probing every node would measure the relays
		 * against each other, which is a question for whoever runs them; what
		 * a client needs is which region is closest. */
		const tc_derp_node *n = &reg->nodes[0];
		uint16_t port = stun_port_for(n, opts);

		/* Both families, from one loop rather than two spellings of the
		 * same eight lines. */
		for (int fam = 0; fam < 2; fam++) {
			bool v6 = (fam == 1);
			const char *lit = v6 ? n->ipv6 : n->ipv4;
			tc_endpoint ep;
			if (lit[0] != '\0') {
				if (tc_endpoint_parse(&ep, lit, port) != TC_OK)
					continue;
			} else if (opts->resolve_hostnames && n->hostname[0] != '\0') {
				if (resolve_one(&ep, n->hostname, port, v6) != TC_OK)
					continue;
			} else {
				continue;
			}
			int rc = add_probe(nc, &ep, idx, v6, now_ms_);
			if (rc == TC_ERR_INVAL)
				return rc; /* no randomness to name a probe with */
		}
	}

	return (nc->num_probes > 0) ? TC_OK : TC_ERR_INVAL;
}

/* ---- scheduling -------------------------------------------------------- */

int tc_netcheck_next_send(tc_netcheck *nc, uint64_t now, tc_endpoint *dst,
                          uint8_t out[TC_STUN_REQUEST_LEN], int *wait_ms)
{
	if (nc == NULL || dst == NULL || out == NULL)
		return TC_ERR_INVAL;
	if (wait_ms != NULL)
		*wait_ms = 0;

	bool any_outstanding = false;
	size_t best = nc->num_probes;
	uint64_t best_due = UINT64_MAX;

	for (size_t i = 0; i < nc->num_probes; i++) {
		tc_netcheck_probe *p = &nc->probes[i];
		if (p->answered)
			continue;
		any_outstanding = true;
		if (p->sends_left <= 0)
			continue;
		if (p->due_ms < best_due) {
			best_due = p->due_ms;
			best = i;
		}
	}

	/* Every probe answered: done early, which is the common case on a good
	 * network and the reason the timeout is a ceiling rather than a cost. */
	if (!any_outstanding)
		return TC_ERR_DONE;
	if (now >= nc->deadline_ms)
		return TC_ERR_DONE;

	if (best < nc->num_probes && best_due <= now) {
		tc_netcheck_probe *p = &nc->probes[best];
		if (tc_stun_build_request_with_txid(out, p->txid) != TC_OK)
			return TC_ERR_INVAL;
		*dst = p->dst;
		p->sends_left--;
		p->sent_ms = now;
		/* Spread the retries across the budget rather than bunching them: a
		 * burst of three tests one moment of the network three times. */
		p->due_ms = now + (uint64_t)(nc->timeout_ms / TC_NETCHECK_SENDS);
		return TC_OK;
	}

	/* Nothing due. Wait for the earlier of the next send and the deadline --
	 * probes with no sends left are still worth waiting on, since a late
	 * answer is a real measurement. */
	uint64_t until = nc->deadline_ms;
	if (best < nc->num_probes && best_due < until)
		until = best_due;
	if (wait_ms != NULL)
		*wait_ms = (until > now) ? (int)(until - now) : 0;
	return TC_ERR_TIMEOUT;
}

/* ---- accounting -------------------------------------------------------- */

static void note_mapped(tc_netcheck_report *r, const tc_endpoint *mapped)
{
	if (mapped->ip_len == 16) {
		if (r->global_v6.ip_len == 0)
			r->global_v6 = *mapped;
		return;
	}
	if (mapped->ip_len != 4)
		return;

	if (r->global_v4.ip_len == 0) {
		r->global_v4 = *mapped;
		return;
	}
	/* Two servers, two answers. Agreement means the NAT keeps one mapping
	 * for this socket whoever it is talking to, and the address is worth
	 * telling a peer. Disagreement means it does not, and it is not.
	 *
	 * Once seen to vary it stays varying: a later coincidence of two servers
	 * agreeing does not undo the pair that did not. */
	if (!tc_endpoint_equal(&r->global_v4, mapped))
		r->mapping_varies = true;
	r->mapping_varies_known = true;
}

int tc_netcheck_handle(tc_netcheck *nc, const tc_endpoint *src,
                       const uint8_t *pkt, size_t len, uint64_t now)
{
	if (nc == NULL || src == NULL || pkt == NULL)
		return TC_ERR_INVAL;
	if (!tc_stun_is(pkt, len))
		return TC_ERR_INVAL;

	uint8_t txid[TC_STUN_TXID_LEN];
	tc_endpoint mapped;
	if (tc_stun_parse_response(pkt, len, txid, &mapped) != TC_OK)
		return TC_ERR_INVAL;

	for (size_t i = 0; i < nc->num_probes; i++) {
		tc_netcheck_probe *p = &nc->probes[i];
		if (!tc_ct_equal(p->txid, txid, TC_STUN_TXID_LEN))
			continue;
		if (p->answered)
			return TC_ERR_INVAL; /* a retransmit's twin; already counted */
		/* The answer has to come from where the question went. Guessing a
		 * transaction ID is hard; doing it and also sourcing from the
		 * relay's address is harder, and this costs one comparison. */
		if (!tc_endpoint_equal(&p->dst, src))
			return TC_ERR_INVAL;

		p->answered = true;
		int rtt = (now > p->sent_ms) ? (int)(now - p->sent_ms) : 0;

		tc_netcheck_region *rr = &nc->report.regions[p->region_idx];
		if (p->v6)
			rr->rtt_v6_ms = rtt;
		else
			rr->rtt_v4_ms = rtt;

		nc->report.udp = true;
		if (p->v6)
			nc->report.ipv6 = true;
		else
			nc->report.ipv4 = true;

		note_mapped(&nc->report, &mapped);
		return TC_OK;
	}
	return TC_ERR_INVAL;
}

void tc_netcheck_finish(tc_netcheck *nc, tc_netcheck_report *out)
{
	if (nc == NULL)
		return;

	int best = -1;
	int64_t best_region = 0;
	for (size_t i = 0; i < nc->report.num_regions; i++) {
		const tc_netcheck_region *r = &nc->report.regions[i];
		/* The better of the two families: a region reachable quickly over
		 * either one is a region reachable quickly. */
		int rtt = -1;
		if (r->rtt_v4_ms >= 0)
			rtt = r->rtt_v4_ms;
		if (r->rtt_v6_ms >= 0 && (rtt < 0 || r->rtt_v6_ms < rtt))
			rtt = r->rtt_v6_ms;
		if (rtt < 0)
			continue;
		/* Strictly less, so a tie goes to the earlier region and the same
		 * network chooses the same relay twice running. */
		if (best < 0 || rtt < best) {
			best = rtt;
			best_region = r->region_id;
		}
	}
	nc->report.preferred_region = best_region;

	if (out != NULL)
		*out = nc->report;
}

/* ---- the loop ---------------------------------------------------------- */

int tc_netcheck_run(tc_netcheck_report *out, const tc_derp_map *m, tc_udp *u,
                    const tc_netcheck_opts *opts, tc_netcheck_other_fn other,
                    void *ctx)
{
	if (out == NULL || m == NULL || u == NULL)
		return TC_ERR_INVAL;

	tc_netcheck nc;
	int rc = tc_netcheck_begin(&nc, m, opts, now_ms());
	if (rc != TC_OK)
		return rc;

	for (;;) {
		uint64_t t = now_ms();
		tc_endpoint dst;
		uint8_t req[TC_STUN_REQUEST_LEN];
		int wait = 0;

		rc = tc_netcheck_next_send(&nc, t, &dst, req, &wait);
		if (rc == TC_ERR_DONE)
			break;
		if (rc == TC_OK) {
			/* A send that fails is a family this host cannot reach, not a
			 * failed check: an IPv4-only machine probing a v6 address is
			 * ordinary, and the probe simply goes unanswered. */
			(void)tc_udp_send(u, &dst, req, sizeof req);
			continue;
		}
		if (rc != TC_ERR_TIMEOUT)
			break;

		/* Bounded so a clock that jumps cannot park us here. */
		if (wait <= 0)
			wait = 1;
		if (wait > 250)
			wait = 250;

		tc_endpoint src;
		uint8_t buf[1500];
		size_t n = 0;
		if (tc_udp_recv(u, &src, buf, sizeof buf, &n, wait) != TC_OK)
			continue;
		if (tc_netcheck_handle(&nc, &src, buf, n, now_ms()) != TC_OK &&
		    other != NULL)
			other(ctx, &src, buf, n);
	}

	tc_netcheck_finish(&nc, out);
	return TC_OK;
}

/* ---- reporting --------------------------------------------------------- */

int tc_netcheck_describe(char *out, size_t cap, const tc_netcheck_report *r,
                         const tc_derp_map *m)
{
	if (out == NULL || cap == 0 || r == NULL)
		return TC_ERR_INVAL;
	out[0] = '\0';

	if (!r->udp) {
		int n = snprintf(out, cap, "no STUN answer; UDP looks blocked");
		return (n > 0 && (size_t)n < cap) ? TC_OK : TC_ERR_NOSPACE;
	}

	char region[96] = "no region answered";
	if (r->preferred_region != 0) {
		int rtt = -1;
		for (size_t i = 0; i < r->num_regions; i++) {
			if (r->regions[i].region_id != r->preferred_region)
				continue;
			rtt = r->regions[i].rtt_v4_ms;
			if (r->regions[i].rtt_v6_ms >= 0 &&
			    (rtt < 0 || r->regions[i].rtt_v6_ms < rtt))
				rtt = r->regions[i].rtt_v6_ms;
			break;
		}
		const tc_derp_region *reg =
		    (m != NULL) ? tc_derpmap_find(m, r->preferred_region) : NULL;
		if (reg != NULL && reg->region_code[0] != '\0')
			snprintf(region, sizeof region, "region %lld (%s) %dms",
			         (long long)r->preferred_region, reg->region_code, rtt);
		else
			snprintf(region, sizeof region, "region %lld %dms",
			         (long long)r->preferred_region, rtt);
	}

	char addr[80] = "no mapped address";
	if (r->global_v4.ip_len != 0)
		tc_endpoint_format(addr, sizeof addr, &r->global_v4);
	else if (r->global_v6.ip_len != 0)
		tc_endpoint_format(addr, sizeof addr, &r->global_v6);

	const char *mapping = "mapping unknown";
	if (r->mapping_varies_known)
		mapping = r->mapping_varies ? "mapping varies by destination"
		                            : "mapping is stable";

	int n = snprintf(out, cap, "%s; %s; %s", region, addr, mapping);
	return (n > 0 && (size_t)n < cap) ? TC_OK : TC_ERR_NOSPACE;
}
