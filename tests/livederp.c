/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Live interoperability test against a real DERP relay.
 *
 * This is the test that actually proves M3: unit tests can only show we are
 * self-consistent, whereas this shows a production Tailscale relay accepts
 * our TLS, our HTTP upgrade, our NaCl-boxed client-info, and then relays a
 * packet between two of our clients.
 *
 * It needs the network, so it is NOT part of `make test`, which must work
 * offline. Run it with `make live`.
 *
 * Usage: livederp [hostname] [--insecure]
 */

#include "tc/crypto.h"
#include "tc/derp.h"

#include <stdio.h>
#include <string.h>

static void hexdump(const char *label, const uint8_t *p, size_t n)
{
	printf("%s", label);
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	/* A node from tailcat's published relay map (https://tailcat.dev/derpmap.json). */
	const char *host = "tc303a.ipn.dev";
	bool insecure = false;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--insecure") == 0)
			insecure = true;
		else
			host = argv[i];
	}

	printf("relay: %s\n", host);
	printf("roots: %zu compiled-in CA certificates\n", tc_ca_bundle_count);

	uint8_t a_sk[32], a_pk[32], b_sk[32], b_pk[32];
	if (tc_x25519_keypair(a_sk, a_pk) != TC_OK ||
	    tc_x25519_keypair(b_sk, b_pk) != TC_OK) {
		fprintf(stderr, "FAIL: could not generate keypairs\n");
		return 1;
	}
	hexdump("  A public key: ", a_pk, 32);
	hexdump("  B public key: ", b_pk, 32);

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = host;
	opts.insecure_skip_verify = insecure;
	opts.timeout_ms = 15000;

	tc_derp_client a, b;

	printf("\n[1] connecting client A (TCP, TLS, HTTP upgrade, key exchange)\n");
	if (tc_derp_connect(&a, &opts, a_sk, a_pk) != TC_OK) {
		fprintf(stderr, "FAIL: client A: %s\n", tc_derp_error_string());
		return 1;
	}
	printf("     connected\n");
	hexdump("     relay public key: ", a.server_key, 32);

	printf("\n[2] connecting client B\n");
	if (tc_derp_connect(&b, &opts, b_sk, b_pk) != TC_OK) {
		fprintf(stderr, "FAIL: client B: %s\n", tc_derp_error_string());
		tc_derp_close(&a);
		return 1;
	}
	printf("     connected\n");

	/* Both clients reached the same region, so they should agree on the
	 * relay's key. (Not guaranteed if the hostname is load-balanced across
	 * several nodes, so this is a note rather than a failure.) */
	if (memcmp(a.server_key, b.server_key, 32) != 0)
		printf("     note: the two connections landed on different relay nodes\n");

	printf("\n[3] relaying a packet from A to B\n");
	static const char kMsg[] = "hello from tailcat-c";
	if (tc_derp_send(&a, b_pk, kMsg, sizeof kMsg - 1) != TC_OK) {
		fprintf(stderr, "FAIL: send: %s\n", tc_derp_error_string());
		goto fail;
	}
	printf("     sent %zu bytes to B's public key\n", sizeof kMsg - 1);

	uint8_t src[32];
	uint8_t buf[2048];
	size_t got = 0;
	if (tc_derp_recv(&b, src, buf, sizeof buf, &got) != TC_OK) {
		fprintf(stderr, "FAIL: recv: %s\n", tc_derp_error_string());
		goto fail;
	}
	printf("     B received %zu bytes\n", got);

	if (got != sizeof kMsg - 1 || memcmp(buf, kMsg, got) != 0) {
		fprintf(stderr, "FAIL: payload differs\n");
		goto fail;
	}
	if (memcmp(src, a_pk, 32) != 0) {
		fprintf(stderr, "FAIL: source key is not A\n");
		hexdump("  got:  ", src, 32);
		hexdump("  want: ", a_pk, 32);
		goto fail;
	}
	printf("     payload and source key both match A\n");

	printf("\n[4] relaying back from B to A\n");
	static const char kReply[] = "and back again";
	if (tc_derp_send(&b, a_pk, kReply, sizeof kReply - 1) != TC_OK) {
		fprintf(stderr, "FAIL: reply send: %s\n", tc_derp_error_string());
		goto fail;
	}
	if (tc_derp_recv(&a, src, buf, sizeof buf, &got) != TC_OK) {
		fprintf(stderr, "FAIL: reply recv: %s\n", tc_derp_error_string());
		goto fail;
	}
	if (got != sizeof kReply - 1 || memcmp(buf, kReply, got) != 0 ||
	    memcmp(src, b_pk, 32) != 0) {
		fprintf(stderr, "FAIL: reply differs\n");
		goto fail;
	}
	printf("     round trip complete\n");

	printf("\n[5] reconnecting A and relaying again\n");
	/* A reconnection has to come back under the same identity: DERP addresses
	 * peers by public key, so a new one would make A a different node and B
	 * would be sending to someone who no longer exists. This is the only
	 * check that exercises the redial against a real relay -- the unit tests
	 * can drive the frame loop but cannot dial anything. */
	if (tc_derp_reconnect(&a) != TC_OK) {
		fprintf(stderr, "FAIL: reconnect: %s\n", tc_derp_error_string());
		goto fail;
	}
	printf("     A reconnected (count=%u)\n", tc_derp_reconnect_count(&a));

	static const char kAfter[] = "after the reconnection";
	if (tc_derp_send(&a, b_pk, kAfter, sizeof kAfter - 1) != TC_OK) {
		fprintf(stderr, "FAIL: post-reconnect send: %s\n",
		        tc_derp_error_string());
		goto fail;
	}
	if (tc_derp_recv(&b, src, buf, sizeof buf, &got) != TC_OK) {
		fprintf(stderr, "FAIL: post-reconnect recv: %s\n",
		        tc_derp_error_string());
		goto fail;
	}
	if (got != sizeof kAfter - 1 || memcmp(buf, kAfter, got) != 0) {
		fprintf(stderr, "FAIL: post-reconnect payload differs\n");
		goto fail;
	}
	if (memcmp(src, a_pk, 32) != 0) {
		fprintf(stderr, "FAIL: A came back under a different key\n");
		hexdump("  got:  ", src, 32);
		hexdump("  want: ", a_pk, 32);
		goto fail;
	}
	printf("     B still sees the same A, and the payload matches\n");

	tc_derp_close(&a);
	tc_derp_close(&b);
	printf("\nok   livederp                 relayed both directions via %s,\n",
	       host);
	printf("                              and again after a reconnection\n");
	return 0;

fail:
	tc_derp_close(&a);
	tc_derp_close(&b);
	return 1;
}
