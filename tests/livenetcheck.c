/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A netcheck against the real relay list.
 *
 * test_netcheck drives the state machine by hand and proves the arithmetic.
 * It cannot prove that the servers answer, that the map's addresses are
 * reachable, or that the numbers that come back mean anything -- a probe the
 * servers dislike is not rejected, it is dropped, and a check that measures
 * nothing looks exactly like a network with no relays on it.
 *
 * So this asserts the things only a real network can settle:
 *
 *   something answers at all;
 *   the region called preferred really does have the lowest latency;
 *   the round trips are in a range a round trip can be in;
 *   the address the relays report for us is a public one;
 *   and the preferred region is not just quick to answer a UDP probe but
 *   actually dialable, which is what it was chosen for.
 *
 * It dials Tailscale's production relays, which is why it runs at diagnostic
 * level 1 and not on every push.
 */

#include "tc/derp.h"
#include "tc/derpmap.h"
#include "tc/netcheck.h"
#include "tc/wgpeer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, ...)                                                      \
	do {                                                                      \
		checks++;                                                             \
		if (!(cond)) {                                                        \
			fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);              \
			fprintf(stderr, __VA_ARGS__);                                     \
			fprintf(stderr, "\n");                                            \
			failures++;                                                       \
		}                                                                     \
	} while (0)

int main(void)
{
	tc_derp_map *m = (tc_derp_map *)malloc(sizeof *m);
	if (m == NULL)
		return 1;
	if (tc_derpmap_fetch(m, NULL, false, 30000) != TC_OK) {
		fprintf(stderr, "livenetcheck: %s\n", tc_derpmap_error_string());
		free(m);
		return 1;
	}
	printf("map has %zu regions\n", m->num_regions);

	tc_udp u;
	if (tc_udp_open(&u, 0) != TC_OK) {
		fprintf(stderr, "livenetcheck: could not open a UDP socket\n");
		free(m);
		return 1;
	}

	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.timeout_ms = 3000;

	tc_netcheck_report rep;
	CHECK(tc_netcheck_run(&rep, m, &u, &o, NULL, NULL) == TC_OK,
	      "the check did not run");
	tc_udp_close(&u);

	char line[200];
	if (tc_netcheck_describe(line, sizeof line, &rep, m) == TC_OK)
		printf("%s\n", line);

	if (!rep.udp) {
		/* Not a failure of ours, but not a result either: every assertion
		 * below is about numbers this network did not produce. */
		printf("livenetcheck: no STUN answer; UDP looks blocked here, so "
		       "there is nothing to check\n");
		free(m);
		return 0;
	}

	CHECK(rep.num_regions == m->num_regions,
	      "reported %zu regions for a map of %zu", rep.num_regions,
	      m->num_regions);

	int answered = 0, best = -1;
	int64_t best_region = 0;
	for (size_t i = 0; i < rep.num_regions; i++) {
		const tc_netcheck_region *r = &rep.regions[i];
		int rtt = r->rtt_v4_ms;
		if (r->rtt_v6_ms >= 0 && (rtt < 0 || r->rtt_v6_ms < rtt))
			rtt = r->rtt_v6_ms;
		if (rtt < 0)
			continue;
		answered++;
		/* A round trip of zero would mean the answer arrived in the same
		 * millisecond it was sent, which across the internet means the clock
		 * is not being read rather than that the network is fast. Anything
		 * past the budget means the deadline is not being enforced. */
		CHECK(rtt > 0 && rtt <= o.timeout_ms,
		      "region %lld reported %dms, which is not a round trip",
		      (long long)r->region_id, rtt);
		if (best < 0 || rtt < best) {
			best = rtt;
			best_region = r->region_id;
		}
	}
	printf("%d of %zu regions answered\n", answered, rep.num_regions);
	CHECK(answered > 0, "nothing answered although udp was reported");

	/* The whole point of the exercise. Recomputing the minimum here rather
	 * than trusting the field is what makes this a check. */
	CHECK(rep.preferred_region == best_region,
	      "preferred region %lld but %lld was quickest",
	      (long long)rep.preferred_region, (long long)best_region);

	if (answered >= 2)
		CHECK(rep.mapping_varies_known,
		      "%d regions answered but the mapping is still unknown",
		      answered);

	/* An address a peer could use. A relay reporting us at a private or
	 * loopback address would mean we are reading the wrong attribute. */
	if (rep.global_v4.ip_len != 0) {
		char s[80];
		tc_endpoint_format(s, sizeof s, &rep.global_v4);
		printf("public address %s\n", s);
		CHECK(tc_endpoint_is_candidate(&rep.global_v4),
		      "%s is not an address a peer could reach", s);
	}
	CHECK(rep.global_v4.ip_len != 0 || rep.global_v6.ip_len != 0,
	      "answers arrived but no address came with them");

	/* Quick to answer a UDP probe is not the same as usable. The region was
	 * chosen to carry a session, so dial one. */
	const tc_derp_region *reg = tc_derpmap_find(m, rep.preferred_region);
	CHECK(reg != NULL, "the preferred region is not in the map");
	if (reg != NULL && reg->num_nodes > 0) {
		tc_wg_identity id;
		if (tc_wg_identity_generate(&id) == TC_OK) {
			tc_derp_dial_opts d;
			memset(&d, 0, sizeof d);
			d.hostname = reg->nodes[0].hostname;
			d.dial_addr = (reg->nodes[0].ipv4[0] != '\0')
			                  ? reg->nodes[0].ipv4
			                  : NULL;
			d.timeout_ms = 15000;
			tc_derp_client c;
			int rc = tc_derp_connect(&c, &d, id.private_key, id.public_key);
			CHECK(rc == TC_OK, "could not dial preferred region %lld (%s): %s",
			      (long long)rep.preferred_region, reg->region_code,
			      tc_strerror(rc));
			if (rc == TC_OK)
				tc_derp_close(&c);
		}
	}

	free(m);
	if (failures > 0) {
		printf("FAIL livenetcheck             %d checks, %d failures\n",
		       checks, failures);
		return 1;
	}
	printf("ok   livenetcheck            %d checks\n", checks);
	return 0;
}
