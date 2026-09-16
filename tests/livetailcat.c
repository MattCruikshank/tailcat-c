/* SPDX-License-Identifier: BSD-3-Clause
 *
 * End-to-end interoperability against a real tailcat server.
 *
 * This is the test that exercises every milestone at once, against the actual
 * Go implementation rather than against ourselves:
 *
 *   M1  parse the server's tailcat address
 *   M3  connect to the DERP relay it names, over TLS
 *   M5  introduce ourselves with a meow ping and wait to be meowed
 *   M4  complete a WireGuard handshake with the server, through the relay
 *
 *   M6  open a TCP connection to port 1 inside the tunnel and send a line
 *
 * Getting a verified handshake response means the real tailcat server added
 * us as a peer on the strength of our meow, agreed the same Noise transcript,
 * and folded in the pre-shared key carried inside its own address. The server
 * then printing our line to its own stdout means the TCP segments survived
 * the whole path and gvisor's netstack accepted them.
 *
 * Only our send direction is exercised here: tailcat's pipe mode writes what
 * it receives to stdout but does not forward its own stdin back, so there is
 * nothing to read. The real Go client sees the same nothing, so this is
 * upstream's behaviour rather than a gap. The receive path is covered
 * thoroughly by tests/test_tcp.c, in both directions and over a lossy link.
 *
 * Run via `make live-tailcat`, which starts a real server and feeds us its
 * address.
 */

#include "tc/addr.h"
#include "tc/crypto.h"
#include "tc/derp.h"
#include "tc/noise.h"
#include "tc/tailcat.h"
#include "tc/tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
	printf("%s", label);
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

/* pump carries one direction of the tunnel: an IPv6 packet from the TCP
 * stack gets WireGuard-encrypted and handed to the relay. */
typedef struct {
	tc_derp_client *derp;
	tc_wg_session *sess;
	uint8_t server_key[32];
} pump;

static int tcp_out(void *vctx, const uint8_t *ip_pkt, size_t len)
{
	pump *p = (pump *)vctx;
	uint8_t wg[TC_DERP_MAX_PACKET_SIZE];
	size_t wg_len = 0;

	if (tc_wg_encrypt(wg, sizeof wg, &wg_len, p->sess, ip_pkt, len) != TC_OK)
		return TC_ERR_INVAL;
	/* A failed relay send is just packet loss; TCP will retransmit. */
	(void)tc_derp_send(p->derp, p->server_key, wg, wg_len);
	return TC_OK;
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static double now_seconds(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0.0;
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: livetailcat <resolved-tailcat-address>\n");
		return 2;
	}
	const char *addr_str = argv[1];

	/* ---- M1: the address ---------------------------------------------- */

	static tc_conn_info ci; /* several KB; keep it off the stack */
	int rc = tc_addr_parse(&ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "FAIL: parsing the address: %s\n", tc_strerror(rc));
		return 1;
	}
	printf("[1] parsed the server's tailcat address\n");
	print_hex("    server node key:  ", ci.server_public, 32);
	if (ci.has_disco_public)
		print_hex("    server disco key: ", ci.server_disco_public, 32);
	printf("    pre-shared key:   %s\n",
	       ci.has_preshared_key ? "present" : "absent");

	if (ci.num_regions == 0 || ci.regions[0].num_nodes == 0) {
		fprintf(stderr, "FAIL: the address embeds no relay; resolve it first "
		                "with `tailcat resolve`\n");
		return 1;
	}
	const tc_derp_region *reg = &ci.regions[0];
	const tc_derp_node *node = &reg->nodes[0];
	printf("    relay:            %s (region %lld, %s)\n", node->hostname,
	       (long long)reg->region_id, reg->region_code);

	uint8_t server_tunnel[TC_TUNNEL_ADDR_LEN];
	char server_tunnel_str[64];
	tc_tunnel_addr_for_key(server_tunnel, ci.server_public);
	if (tc_tunnel_addr_format(server_tunnel_str, sizeof server_tunnel_str,
	                          server_tunnel) == TC_OK)
		printf("    server tunnel IP: %s\n", server_tunnel_str);

	/* ---- our identity -------------------------------------------------- */

	tc_wg_identity me;
	if (tc_wg_identity_generate(&me) != TC_OK) {
		fprintf(stderr, "FAIL: generating our keypair\n");
		return 1;
	}
	uint8_t disco_pub[32];
	if (tc_disco_key_for_node(NULL, disco_pub, me.private_key) != TC_OK) {
		fprintf(stderr, "FAIL: deriving our disco key\n");
		return 1;
	}
	printf("\n[2] our identity\n");
	print_hex("    node key:         ", me.public_key, 32);
	print_hex("    disco key:        ", disco_pub, 32);

	uint8_t our_tunnel[TC_TUNNEL_ADDR_LEN];
	char our_tunnel_str[64];
	tc_tunnel_addr_for_key(our_tunnel, me.public_key);
	if (tc_tunnel_addr_format(our_tunnel_str, sizeof our_tunnel_str,
	                          our_tunnel) == TC_OK)
		printf("    tunnel IP:        %s\n", our_tunnel_str);

	/* ---- M3: the relay ------------------------------------------------- */

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = node->hostname;
	opts.dial_addr = (node->ipv4[0] != '\0') ? node->ipv4 : NULL;
	opts.port = (node->derp_port > 0) ? (uint16_t)node->derp_port : 0;
	opts.insecure_skip_verify = node->insecure_for_tests;
	opts.timeout_ms = 15000;

	printf("\n[3] connecting to the relay\n");
	tc_derp_client derp;
	rc = tc_derp_connect(&derp, &opts, me.private_key, me.public_key);
	if (rc != TC_OK) {
		fprintf(stderr, "FAIL: %s\n", tc_derp_error_string());
		return 1;
	}
	print_hex("    relay key:        ", derp.server_key, 32);

	/* One second, so the meow ping can be resent while we wait. DERP
	 * delivery is best effort and drops packets addressed to a key that is
	 * not connected yet. */
	if (tc_derp_set_read_timeout(&derp, 1000) != TC_OK) {
		fprintf(stderr, "FAIL: could not set a read timeout\n");
		tc_derp_close(&derp);
		return 1;
	}

	/* ---- M5: meow ------------------------------------------------------ */

	printf("\n[4] introducing ourselves (meow)\n");
	uint8_t ping[TC_MEOW_PING_LEN];
	size_t ping_len = 0;
	if (tc_meow_encode_ping(ping, sizeof ping, &ping_len, me.public_key,
	                        disco_pub) != TC_OK) {
		fprintf(stderr, "FAIL: encoding the meow ping\n");
		goto fail;
	}

	double t0 = now_seconds();
	bool meowed = false;
	int pings_sent = 0;

	while (!meowed && now_seconds() - t0 < 20.0) {
		if (tc_derp_send(&derp, ci.server_public, ping, ping_len) != TC_OK) {
			fprintf(stderr, "FAIL: sending the meow ping\n");
			goto fail;
		}
		pings_sent++;

		/* Drain whatever arrives until the ack shows up or we time out and
		 * resend. */
		for (;;) {
			uint8_t src[32];
			static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
			size_t len = 0;
			rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
			if (rc == TC_ERR_TIMEOUT)
				break; /* resend */
			if (rc != TC_OK) {
				fprintf(stderr, "FAIL: relay read: %s (%s)\n", tc_strerror(rc),
				        tc_derp_error_string());
				goto fail;
			}
			if (memcmp(src, ci.server_public, 32) != 0)
				continue; /* not from our server */
			if (tc_meow_is_meowed(buf, len)) {
				meowed = true;
				break;
			}
		}
	}

	if (!meowed) {
		fprintf(stderr, "FAIL: no meowed acknowledgment after %d pings\n",
		        pings_sent);
		goto fail;
	}
	printf("    meowed after %d ping%s in %.2fs -- the server has added us as "
	       "a peer\n",
	       pings_sent, pings_sent == 1 ? "" : "s", now_seconds() - t0);

	/* ---- M4: the tunnel ------------------------------------------------ */

	printf("\n[5] WireGuard handshake through the relay\n");
	tc_wg_handshake hs;
	rc = tc_wg_handshake_init(&hs, &me, ci.server_public,
	                          ci.has_preshared_key ? ci.preshared_key : NULL);
	if (rc != TC_OK) {
		fprintf(stderr, "FAIL: handshake init: %s\n", tc_strerror(rc));
		goto fail;
	}

	uint8_t init[TC_WG_INITIATION_SIZE];
	if (tc_wg_create_initiation(init, &hs, &me, 0) != TC_OK) {
		fprintf(stderr, "FAIL: creating the initiation\n");
		goto fail;
	}

	t0 = now_seconds();
	bool got_response = false;
	int inits_sent = 0;

	while (!got_response && now_seconds() - t0 < 20.0) {
		if (tc_derp_send(&derp, ci.server_public, init, sizeof init) != TC_OK) {
			fprintf(stderr, "FAIL: sending the initiation\n");
			goto fail;
		}
		inits_sent++;

		for (;;) {
			uint8_t src[32];
			static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
			size_t len = 0;
			rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
			if (rc == TC_ERR_TIMEOUT)
				break;
			if (rc != TC_OK) {
				fprintf(stderr, "FAIL: relay read: %s\n", tc_strerror(rc));
				goto fail;
			}
			if (memcmp(src, ci.server_public, 32) != 0)
				continue;
			if (tc_meow_is_packet(buf, len))
				continue; /* a duplicate ack from our resends */
			if (len != TC_WG_RESPONSE_SIZE || buf[0] != TC_WG_MSG_RESPONSE)
				continue;

			if (tc_wg_consume_response(&hs, &me, buf) != TC_OK) {
				fprintf(stderr, "FAIL: the handshake response did not "
				                "verify\n");
				goto fail;
			}
			got_response = true;
			break;
		}
	}

	if (!got_response) {
		fprintf(stderr, "FAIL: no handshake response after %d attempts\n",
		        inits_sent);
		goto fail;
	}

	tc_wg_session sess;
	if (tc_wg_begin_session(&sess, &hs) != TC_OK) {
		fprintf(stderr, "FAIL: deriving the session keys\n");
		goto fail;
	}

	printf("    response verified in %.2fs after %d attempt%s\n",
	       now_seconds() - t0, inits_sent, inits_sent == 1 ? "" : "s");
	printf("    session established: we are the initiator, indices %u/%u\n",
	       sess.local_index, sess.remote_index);

	/* ---- M6: TCP inside the tunnel ------------------------------------ */

	printf("\n[6] opening a TCP connection to port 1 through the tunnel\n");

	pump ctx;
	ctx.derp = &derp;
	ctx.sess = &sess;
	memcpy(ctx.server_key, ci.server_public, 32);

	tc_tcp_conn *tcp = tc_tcp_new(our_tunnel, server_tunnel, tcp_out, &ctx);
	if (tcp == NULL) {
		fprintf(stderr, "FAIL: allocating the TCP connection\n");
		goto fail;
	}

	uint64_t t_ms = now_ms();
	/* An ephemeral local port; the server's pipe mode listens on 1. */
	if (tc_tcp_connect(tcp, 49152, 1, t_ms) != TC_OK) {
		fprintf(stderr, "FAIL: starting the TCP connection\n");
		tc_tcp_free(tcp);
		goto fail;
	}

	/* 100ms reads, so the retransmission timers still get to run. */
	tc_derp_set_read_timeout(&derp, 100);

	static const char kLine[] = "hello from tailcat-c\n";
	bool wrote = false, half_closed = false;
	size_t reply_len = 0;
	static char reply[4096];
	uint64_t start = now_ms();

	while (now_ms() - start < 30000) {
		t_ms = now_ms();
		tc_tcp_tick(tcp, t_ms);

		if (!wrote && tc_tcp_is_established(tcp)) {
			size_t w = 0;
			tc_tcp_write(tcp, kLine, sizeof kLine - 1, &w, t_ms);
			if (w == sizeof kLine - 1) {
				wrote = true;
				printf("    connected; sent %zu bytes to port 1\n", w);
			}
		}

		/* Close our write side once the data is acknowledged, which is what
		 * makes the server's pipe see end of input. */
		if (wrote && !half_closed && tc_tcp_send_unacked(tcp) == 0) {
			tc_tcp_shutdown_write(tcp, t_ms);
			half_closed = true;
			printf("    payload acknowledged; half-closed our write side\n");
		}

		size_t n = 0;
		if (tc_tcp_readable(tcp) > 0 &&
		    tc_tcp_read(tcp, reply + reply_len, sizeof reply - reply_len - 1,
		                &n) == TC_OK &&
		    n > 0) {
			reply_len += n;
			reply[reply_len] = '\0';
		}

		if (half_closed && tc_tcp_read_closed(tcp))
			break;

		/* Move one relayed packet, if any, into the tunnel. */
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "FAIL: relay read: %s\n", tc_strerror(rc));
			break;
		}
		if (memcmp(src, ci.server_public, 32) != 0 || len == 0)
			continue;
		if (buf[0] != TC_WG_MSG_TRANSPORT)
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_decrypt(inner, sizeof inner, &inner_len, &sess, buf, len) !=
		    TC_OK)
			continue; /* forged, replayed or a rekey we do not handle */
		if (inner_len == 0)
			continue; /* a keepalive */
		tc_tcp_input(tcp, inner, inner_len, now_ms());
	}

	if (!wrote) {
		fprintf(stderr, "FAIL: the TCP connection never established (%s)\n",
		        tc_tcp_state_name(tc_tcp_get_state(tcp)));
		tc_tcp_free(tcp);
		goto fail;
	}

	tc_tcp_stats ts;
	tc_tcp_get_stats(tcp, &ts);
	printf("    tcp: %llu segments out, %llu in, %llu retransmits\n",
	       (unsigned long long)ts.segs_sent,
	       (unsigned long long)ts.segs_received,
	       (unsigned long long)ts.retransmits);
	if (reply_len > 0)
		printf("    server sent back %zu bytes: \"%.*s\"\n", reply_len,
		       (int)reply_len, reply);

	tc_tcp_free(tcp);
	tc_wg_session_clear(&sess);
	tc_derp_close(&derp);

	printf("\nok   livetailcat              TCP stream carried over a "
	       "WireGuard tunnel to a real tailcat server\n");
	printf("     %s <-> %s, relayed via %s\n", our_tunnel_str,
	       server_tunnel_str, node->hostname);
	return 0;

fail:
	tc_derp_close(&derp);
	return 1;
}
