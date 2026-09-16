/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A real STUN binding exchange against Tailscale's DERP servers.
 *
 * The unit tests prove our request is byte-identical to the one
 * tailscale.com/net/stun builds. This proves the servers agree: a request
 * they dislike is not rejected, it is dropped, so the only way to know is to
 * send one and see whether anything comes back.
 *
 * It asks two different regions and compares the answers, which is the
 * cheapest useful NAT observation available: the same mapped port from both
 * means an endpoint-independent mapping, and a direct path has a chance;
 * different ports mean the mapping is per-destination, and it does not.
 * Phase 4.5 will turn that into a real classification.
 */

#include "tc/derpmap.h"
#include "tc/stun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* stun_once sends one binding request and waits for its answer. */
static int stun_once(int fd, const char *ip, uint16_t port, tc_endpoint *out,
                     int timeout_ms)
{
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof dst);
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1)
		return -1;

	uint8_t req[TC_STUN_REQUEST_LEN], txid[TC_STUN_TXID_LEN];
	if (tc_stun_build_request(req, txid) != TC_OK)
		return -1;

	/* One retry: UDP, and a single lost datagram should not be reported as a
	 * server that does not speak STUN. */
	for (int attempt = 0; attempt < 2; attempt++) {
		if (sendto(fd, req, sizeof req, 0, (struct sockaddr *)&dst,
		           sizeof dst) < 0)
			return -1;

		uint64_t waited = 0;
		while (waited < (uint64_t)timeout_ms) {
			struct pollfd pf = { fd, POLLIN, 0 };
			int r = poll(&pf, 1, 200);
			waited += 200;
			if (r <= 0)
				continue;

			uint8_t buf[512];
			ssize_t n = recv(fd, buf, sizeof buf, 0);
			if (n <= 0)
				continue;

			uint8_t got_txid[TC_STUN_TXID_LEN];
			if (tc_stun_parse_response(buf, (size_t)n, got_txid, out) != TC_OK)
				continue;
			/* The transaction ID is the only thing tying this reply to our
			 * request, so anything else is somebody else's traffic. */
			if (memcmp(got_txid, txid, TC_STUN_TXID_LEN) != 0)
				continue;
			return 0;
		}
	}
	return -1;
}

int main(void)
{
	static tc_derp_map m;
	printf("[1] fetching the DERP map for its STUN servers\n");
	if (tc_derpmap_fetch(&m, NULL, false, 15000) != TC_OK) {
		fprintf(stderr, "FAIL: %s\n", tc_derpmap_error_string());
		return 1;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "FAIL: no UDP socket: %s\n", strerror(errno));
		return 1;
	}

	tc_endpoint seen[2];
	const char *where[2] = { NULL, NULL };
	size_t got = 0;

	for (size_t i = 0; i < m.num_regions && got < 2; i++) {
		const tc_derp_region *r = &m.regions[i];
		if (r->num_nodes == 0)
			continue;
		const tc_derp_node *n = &r->nodes[0];
		if (n->ipv4[0] == '\0')
			continue;
		uint16_t sp = (n->stun_port > 0) ? (uint16_t)n->stun_port : 3478;

		printf("[%zu] asking %s (%s) on UDP %u\n", got + 2, n->hostname,
		       r->region_code, (unsigned)sp);
		if (stun_once(fd, n->ipv4, sp, &seen[got], 3000) != 0) {
			printf("     no answer; trying another region\n");
			continue;
		}
		char s[64];
		tc_endpoint_format(s, sizeof s, &seen[got]);
		printf("     it sees us at %s\n", s);
		where[got] = r->region_code;
		got++;
	}
	(void)close(fd);

	if (got == 0) {
		fprintf(stderr, "FAIL: no STUN server answered. Either every region "
		                "is unreachable, or our request is malformed in a "
		                "way servers drop silently.\n");
		return 1;
	}
	if (seen[0].ip_len != 4 || seen[0].port == 0) {
		fprintf(stderr, "FAIL: the mapped address makes no sense\n");
		return 1;
	}

	if (got == 2) {
		char a[64], b[64];
		tc_endpoint_format(a, sizeof a, &seen[0]);
		tc_endpoint_format(b, sizeof b, &seen[1]);
		printf("\n[4] two regions, two answers\n");
		printf("     %-4s %s\n", where[0], a);
		printf("     %-4s %s\n", where[1], b);
		if (tc_endpoint_equal(&seen[0], &seen[1]))
			printf("     same address and port: the NAT mapping does not "
			       "depend on\n     the destination, so a direct path is "
			       "plausible\n");
		else
			printf("     different: the mapping is per-destination, so a "
			       "direct path\n     would need more than STUN alone\n");
	}

	printf("\nok   livestun                 a real STUN server answered our\n");
	printf("                              binding request\n");
	return 0;
}
