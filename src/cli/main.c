/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The tailcat-c command: netcat over a WireGuard tunnel, relayed through
 * DERP, speaking to a real tailcat server.
 *
 *     tailcat-c <tc-address> [port]      connect and pipe stdin/stdout
 *     tailcat-c serve --relay HOST       listen, printing an address
 *     tailcat-c parse <tc-address>       show what an address contains
 *     tailcat-c version
 *
 * The pipe mode is a single-threaded event loop over two descriptors: the
 * relay socket and standard input. Everything above it -- the TCP stack, the
 * WireGuard session -- is driven from that one loop, so there are no locks
 * and no shared state, which matters because tc_derp_client is not safe for
 * concurrent use.
 *
 * Both roles are here. Serving mints a self-contained address with the relay
 * embedded, which is why it needs --relay: choosing a region by latency would
 * need the DERP map, which is not implemented. The server is the WireGuard
 * responder and the TCP passive opener, and the real Go client interoperates
 * with it.
 */

#include "tc/addr.h"
#include "tc/crypto.h"
#include "tc/derp.h"
#include "tc/derpmap.h"
#include "tc/noise.h"
#include "tc/tailcat.h"
#include "tc/tcp.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TAILCAT_C_VERSION "0.1.0"

static bool g_verbose;

static void vlogf(const char *fmt, ...)
{
	if (!g_verbose)
		return;
	va_list ap;
	va_start(ap, fmt);
	fputs("# ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void usage(FILE *f)
{
	fprintf(f,
	        "tailcat-c " TAILCAT_C_VERSION
	        " -- netcat over Tailscale's data plane, in C\n"
	        "\n"
	        "usage:\n"
	        "  tailcat-c [flags] <tc-address> [port]   pipe stdin/stdout to a "
	        "tailcat server\n"
	        "  tailcat-c serve [port]                  listen and print an "
	        "address\n"
	        "  tailcat-c ping <tc-address>             time the round trip to "
	        "a server\n"
	        "  tailcat-c resolve <tc-address>          embed the relay, for "
	        "offline use\n"
	        "  tailcat-c parse <tc-address>            describe an address\n"
	        "  tailcat-c version\n"
	        "\n"
	        "flags:\n"
	        "  -v, --verbose         report progress on stderr\n"
	        "      --insecure        skip TLS verification of the relay\n"
	        "      --relay HOST      serve through this relay instead of "
	        "choosing one\n"
	        "      --derpmap-url URL where to fetch the relay list\n"
	        "      --timeout SEC     give up after SEC seconds (default 60)\n"
	        "\n"
	        "The port defaults to 1, which is what a bare `tailcat` server "
	        "pipes.\n"
	        "Short addresses work: the relay list is fetched as needed.\n");
}

/* ---- parse subcommand ------------------------------------------------- */

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
	printf("%s", label);
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static int cmd_parse(const char *addr_str)
{
	static tc_conn_info ci;
	int rc = tc_addr_parse(&ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_strerror(rc));
		return 1;
	}

	print_hex("ServerPublic      ", ci.server_public, 32);
	if (ci.has_disco_public)
		print_hex("ServerDiscoPublic ", ci.server_disco_public, 32);
	/* The pre-shared key is a secret: anyone holding it can join the tunnel,
	 * so report its presence and not its value. */
	printf("PresharedKey      %s\n",
	       ci.has_preshared_key ? "present (not shown: it is a secret)"
	                            : "absent");
	if (ci.region_id != 0)
		printf("RegionID          %lld\n", (long long)ci.region_id);

	uint8_t tunnel[TC_TUNNEL_ADDR_LEN];
	char tunnel_str[64];
	tc_tunnel_addr_for_key(tunnel, ci.server_public);
	if (tc_tunnel_addr_format(tunnel_str, sizeof tunnel_str, tunnel) == TC_OK)
		printf("TunnelAddr        %s\n", tunnel_str);

	for (size_t i = 0; i < ci.num_regions; i++) {
		const tc_derp_region *r = &ci.regions[i];
		printf("Region            %lld (%s)\n", (long long)r->region_id,
		       r->region_code);
		for (size_t j = 0; j < r->num_nodes; j++) {
			const tc_derp_node *n = &r->nodes[j];
			printf("  Node            %s", n->hostname);
			if (n->ipv4[0] != '\0')
				printf(" v4=%s", n->ipv4);
			if (n->ipv6[0] != '\0')
				printf(" v6=%s", n->ipv6);
			if (n->derp_port != 0)
				printf(" derp=%d", n->derp_port);
			printf("\n");
		}
	}
	return 0;
}

/* ---- relay resolution ------------------------------------------------- */

/* ensure_relay makes sure ci names a relay we can actually dial.
 *
 * A short address carries only a region number, which means fetching the
 * DERP map to turn it into a hostname. RegionID -1 is upstream's "choose one
 * for me", which we answer by probing. */
static int ensure_relay(tc_conn_info *ci, const char *derpmap_url,
                        bool insecure, int timeout_ms)
{
	if (ci->num_regions > 0 && ci->regions[0].num_nodes > 0)
		return TC_OK; /* already self-contained */

	tc_derp_map *m = (tc_derp_map *)malloc(sizeof *m);
	if (m == NULL)
		return TC_ERR_INVAL;

	vlogf("fetching the DERP map");
	int rc = tc_derpmap_fetch(m, derpmap_url, insecure, timeout_ms);
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_derpmap_error_string());
		free(m);
		return rc;
	}

	const tc_derp_region *reg = NULL;
	if (ci->region_id > 0) {
		reg = tc_derpmap_find(m, ci->region_id);
		if (reg == NULL) {
			fprintf(stderr,
			        "tailcat-c: the DERP map has no region %lld\n",
			        (long long)ci->region_id);
			free(m);
			return TC_ERR_INVAL;
		}
	} else {
		/* Either -1 (choose for me) or absent. */
		vlogf("probing relays to pick one");
		reg = tc_derpmap_pick_fastest(m, 4, timeout_ms, insecure);
		if (reg == NULL) {
			fprintf(stderr, "tailcat-c: no usable relay\n");
			free(m);
			return TC_ERR_INVAL;
		}
	}

	ci->regions[0] = *reg;
	ci->num_regions = 1;
	free(m);
	vlogf("relay region %lld (%s)", (long long)ci->regions[0].region_id,
	      ci->regions[0].region_code);
	return TC_OK;
}

/* ---- resolve subcommand ----------------------------------------------- */

static int cmd_resolve(const char *addr_str, const char *derpmap_url,
                       bool insecure)
{
	static tc_conn_info ci;
	int rc = tc_addr_parse(&ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_strerror(rc));
		return 1;
	}
	rc = ensure_relay(&ci, derpmap_url, insecure, 15000);
	if (rc != TC_OK)
		return 1;

	/* Keep the result short: two relays are enough redundancy, and the
	 * region number is redundant once the region itself is embedded. */
	if (ci.regions[0].num_nodes > 2)
		ci.regions[0].num_nodes = 2;
	ci.region_id = 0;

	char out[TC_ADDR_STR_MAX];
	if (tc_addr_encode(out, sizeof out, &ci, NULL) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not re-encode the address\n");
		return 1;
	}
	printf("%s\n", out);
	return 0;
}

/* ---- ping subcommand --------------------------------------------------- */

/* cmd_ping times the meow round trip: reach the relay, introduce ourselves,
 * and wait to be acknowledged. That is the same exchange the pipe mode does
 * first, so it measures exactly the path a real connection would take. */
static int cmd_ping(const char *addr_str, bool insecure, unsigned timeout_s,
                    const char *derpmap_url)
{
	static tc_conn_info ci;
	int rc = tc_addr_parse(&ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_strerror(rc));
		return 1;
	}
	if (ensure_relay(&ci, derpmap_url, insecure, 15000) != TC_OK)
		return 1;
	const tc_derp_node *node = &ci.regions[0].nodes[0];

	tc_wg_identity me;
	uint8_t disco_pub[32];
	if (tc_wg_identity_generate(&me) != TC_OK ||
	    tc_disco_key_for_node(NULL, disco_pub, me.private_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not generate keys\n");
		return 1;
	}

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = node->hostname;
	opts.dial_addr = (node->ipv4[0] != '\0') ? node->ipv4 : NULL;
	opts.port = (node->derp_port > 0) ? (uint16_t)node->derp_port : 0;
	opts.insecure_skip_verify = insecure || node->insecure_for_tests;
	opts.timeout_ms = 15000;

	uint64_t t_connect = now_ms();
	tc_derp_client derp;
	if (tc_derp_connect(&derp, &opts, me.private_key, me.public_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: relay: %s\n", tc_derp_error_string());
		return 1;
	}
	uint64_t connect_ms = now_ms() - t_connect;
	printf("relay %s: connected in %llu ms\n", node->hostname,
	       (unsigned long long)connect_ms);

	tc_derp_set_read_timeout(&derp, 200);

	uint8_t ping[TC_MEOW_PING_LEN];
	size_t ping_len = 0;
	tc_meow_encode_ping(ping, sizeof ping, &ping_len, me.public_key, disco_pub);

	uint64_t deadline = now_ms() + (uint64_t)timeout_s * 1000u;
	uint64_t next_send = 0, t0 = 0;
	int sent = 0, status = 1;

	while (now_ms() < deadline) {
		if (now_ms() >= next_send) {
			t0 = now_ms();
			if (tc_derp_send(&derp, ci.server_public, ping, ping_len) !=
			    TC_OK) {
				fprintf(stderr, "tailcat-c: relay send failed\n");
				break;
			}
			sent++;
			next_send = now_ms() + 1000;
		}
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			break;
		}
		if (memcmp(src, ci.server_public, 32) == 0 &&
		    tc_meow_is_meowed(buf, len)) {
			printf("meowed in %llu ms (%d ping%s) via %s\n",
			       (unsigned long long)(now_ms() - t0), sent,
			       sent == 1 ? "" : "s", node->hostname);
			status = 0;
			break;
		}
	}

	if (status != 0)
		fprintf(stderr, "tailcat-c: no answer from the server\n");
	tc_derp_close(&derp);
	return status;
}

/* ---- pipe mode -------------------------------------------------------- */

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
	/* A failed relay write is packet loss; TCP will retransmit. */
	(void)tc_derp_send(p->derp, p->server_key, wg, wg_len);
	return TC_OK;
}

/* write_all writes the whole buffer to fd, retrying short writes. */
static bool write_all(int fd, const uint8_t *p, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, p + off, n - off);
		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		return false;
	}
	return true;
}

/* run_pipe is the event loop both roles share: stdin into the tunnel, the
 * tunnel out to stdout, and the relay socket feeding the TCP stack.
 *
 * It is single-threaded on purpose. tc_derp_client is not safe for
 * concurrent use, and a loop over two descriptors needs no locks at all.
 * The caller has already opened or accepted the connection. */
static int run_pipe(tc_derp_client *derp, tc_wg_session *sess,
                    tc_tcp_conn *tcp, const uint8_t peer_key[32],
                    uint64_t deadline)
{
	/* Non-blocking stdin, so the loop never stalls on a slow writer while
	 * the tunnel has work to do. */
	int in_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (in_flags >= 0)
		(void)fcntl(STDIN_FILENO, F_SETFL,
		            (int)((unsigned)in_flags | (unsigned)O_NONBLOCK));

	bool stdin_eof = false, half_closed = false, connected = false;
	int rc;
	tc_derp_set_read_timeout(derp, 20);

	while (now_ms() < deadline) {
		uint64_t t = now_ms();
		tc_tcp_tick(tcp, t);

		if (!connected && tc_tcp_is_established(tcp)) {
			connected = true;
			vlogf("connected");
		}

		/* stdin -> tunnel */
		if (connected && !stdin_eof) {
			size_t room = tc_tcp_writable(tcp);
			if (room > 0) {
				uint8_t buf[16384];
				if (room > sizeof buf)
					room = sizeof buf;
				ssize_t n = read(STDIN_FILENO, buf, room);
				if (n > 0) {
					size_t w = 0;
					tc_tcp_write(tcp, buf, (size_t)n, &w, t);
				} else if (n == 0) {
					stdin_eof = true;
				} else if (errno != EAGAIN && errno != EWOULDBLOCK &&
				           errno != EINTR) {
					stdin_eof = true;
				}
			}
		}

		/* Half close once everything we read has been acknowledged, which is
		 * what tells the server its input has ended. */
		if (stdin_eof && !half_closed && tc_tcp_send_unacked(tcp) == 0) {
			tc_tcp_shutdown_write(tcp, t);
			half_closed = true;
			vlogf("sent everything; closed our write side");
		}

		/* tunnel -> stdout */
		bool progress = false;
		for (;;) {
			uint8_t buf[16384];
			size_t n = 0;
			if (tc_tcp_read(tcp, buf, sizeof buf, &n) != TC_OK || n == 0)
				break;
			if (!write_all(STDOUT_FILENO, buf, n)) {
				fprintf(stderr, "tailcat-c: write to stdout failed\n");
				return 1;
			}
			progress = true;
		}

		if (half_closed && tc_tcp_read_closed(tcp)) {
			return 0;
		}
		if (tc_tcp_get_state(tcp) == TC_TCP_CLOSED) {
			return connected ? 0 : 1;
		}

		/* Wait for whichever comes first: something from the relay, more
		 * stdin, or a TCP timer. Checking has_pending first matters -- a
		 * whole frame may already be decrypted inside the TLS layer with
		 * nothing left on the socket for poll() to see. */
		if (!progress && !tc_derp_has_pending(derp)) {
			struct pollfd pfds[2];
			int nfds = 0;
			int dfd = tc_derp_fd(derp);
			if (dfd >= 0) {
				pfds[nfds].fd = dfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
			if (connected && !stdin_eof && tc_tcp_writable(tcp) > 0) {
				pfds[nfds].fd = STDIN_FILENO;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}

			int wait_ms = 20;
			uint64_t dl = tc_tcp_next_deadline(tcp);
			if (dl != UINT64_MAX) {
				uint64_t nowv = now_ms();
				wait_ms = (dl > nowv) ? (int)(dl - nowv) : 0;
				if (wait_ms > 200)
					wait_ms = 200;
			}
			if (nfds > 0)
				(void)poll(pfds, (nfds_t)nfds, wait_ms);
		}

		/* relay -> tunnel */
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			if (!half_closed)
				fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			return connected ? 0 : 1;
		}
		if (memcmp(src, peer_key, 32) != 0 || len == 0)
			continue;
		if (buf[0] != TC_WG_MSG_TRANSPORT)
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_decrypt(inner, sizeof inner, &inner_len, sess, buf, len) !=
		    TC_OK)
			continue; /* forged, replayed, or a rekey we do not implement */
		if (inner_len == 0)
			continue; /* keepalive */
		tc_tcp_input(tcp, inner, inner_len, now_ms());
	}

	return 1;
}

static int cmd_pipe(const char *addr_str, uint16_t port, bool insecure,
                    unsigned timeout_s, const char *derpmap_url)
{
	static tc_conn_info ci;
	int rc = tc_addr_parse(&ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: bad address: %s\n", tc_strerror(rc));
		return 1;
	}
	/* A short address names its relay by region number; this fetches the map
	 * and turns that into something dialable. */
	if (ensure_relay(&ci, derpmap_url, insecure, 15000) != TC_OK)
		return 1;
	const tc_derp_node *node = &ci.regions[0].nodes[0];

	tc_wg_identity me;
	uint8_t disco_pub[32];
	if (tc_wg_identity_generate(&me) != TC_OK ||
	    tc_disco_key_for_node(NULL, disco_pub, me.private_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not generate keys\n");
		return 1;
	}

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = node->hostname;
	opts.dial_addr = (node->ipv4[0] != '\0') ? node->ipv4 : NULL;
	opts.port = (node->derp_port > 0) ? (uint16_t)node->derp_port : 0;
	opts.insecure_skip_verify = insecure || node->insecure_for_tests;
	opts.timeout_ms = 15000;

	vlogf("relay %s", node->hostname);
	tc_derp_client derp;
	if (tc_derp_connect(&derp, &opts, me.private_key, me.public_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: relay: %s\n", tc_derp_error_string());
		return 1;
	}
	tc_derp_set_read_timeout(&derp, 200);

	int status = 1;
	tc_tcp_conn *tcp = NULL;
	tc_wg_session sess;
	memset(&sess, 0, sizeof sess);

	/* ---- meow: ask the server to add us as a peer ---------------------- */

	uint8_t ping[TC_MEOW_PING_LEN];
	size_t ping_len = 0;
	tc_meow_encode_ping(ping, sizeof ping, &ping_len, me.public_key, disco_pub);

	uint64_t deadline = now_ms() + (uint64_t)timeout_s * 1000u;
	bool meowed = false;
	uint64_t next_send = 0;

	while (!meowed && now_ms() < deadline) {
		if (now_ms() >= next_send) {
			/* DERP drops packets for a key that is not connected yet, so
			 * resend rather than bet everything on the first one. */
			if (tc_derp_send(&derp, ci.server_public, ping, ping_len) != TC_OK) {
				fprintf(stderr, "tailcat-c: relay send failed\n");
				goto out;
			}
			next_send = now_ms() + 1000;
		}
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			goto out;
		}
		if (memcmp(src, ci.server_public, 32) == 0 &&
		    tc_meow_is_meowed(buf, len))
			meowed = true;
	}
	if (!meowed) {
		fprintf(stderr, "tailcat-c: the server never acknowledged us\n");
		goto out;
	}
	vlogf("meowed: the server has added us as a peer");

	/* ---- WireGuard ----------------------------------------------------- */

	tc_wg_handshake hs;
	if (tc_wg_handshake_init(&hs, &me, ci.server_public,
	                         ci.has_preshared_key ? ci.preshared_key : NULL) !=
	    TC_OK) {
		fprintf(stderr, "tailcat-c: handshake setup failed\n");
		goto out;
	}
	uint8_t init[TC_WG_INITIATION_SIZE];
	if (tc_wg_create_initiation(init, &hs, &me, 0) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build the handshake\n");
		goto out;
	}

	bool up = false;
	next_send = 0;
	while (!up && now_ms() < deadline) {
		if (now_ms() >= next_send) {
			if (tc_derp_send(&derp, ci.server_public, init, sizeof init) !=
			    TC_OK) {
				fprintf(stderr, "tailcat-c: relay send failed\n");
				goto out;
			}
			next_send = now_ms() + 1000;
		}
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			goto out;
		}
		if (memcmp(src, ci.server_public, 32) != 0)
			continue;
		if (len != TC_WG_RESPONSE_SIZE || buf[0] != TC_WG_MSG_RESPONSE)
			continue;
		if (tc_wg_consume_response(&hs, &me, buf) != TC_OK) {
			fprintf(stderr, "tailcat-c: the handshake response did not "
			                "verify\n");
			goto out;
		}
		up = true;
	}
	if (!up) {
		fprintf(stderr, "tailcat-c: no handshake response from the server\n");
		goto out;
	}
	if (tc_wg_begin_session(&sess, &hs) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not derive session keys\n");
		goto out;
	}
	vlogf("tunnel up");

	/* ---- TCP inside the tunnel ----------------------------------------- */

	uint8_t our_ip[TC_TUNNEL_ADDR_LEN], their_ip[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(our_ip, me.public_key);
	tc_tunnel_addr_for_key(their_ip, ci.server_public);

	pump ctx;
	ctx.derp = &derp;
	ctx.sess = &sess;
	memcpy(ctx.server_key, ci.server_public, 32);

	tcp = tc_tcp_new(our_ip, their_ip, tcp_out, &ctx);
	if (tcp == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto out;
	}
	/* An ephemeral source port; nothing demultiplexes on it here. */
	if (tc_tcp_connect(tcp, 49152, port, now_ms()) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not start the connection\n");
		goto out;
	}
	vlogf("connecting to port %u", (unsigned)port);

	status = run_pipe(&derp, &sess, tcp, ci.server_public, deadline);

	if (status != 0 && now_ms() >= deadline)
		fprintf(stderr, "tailcat-c: timed out after %u seconds\n", timeout_s);

out:
	if (tcp != NULL)
		tc_tcp_free(tcp);
	tc_wg_session_clear(&sess);
	tc_derp_close(&derp);
	return status;
}

/* ---- serve mode ------------------------------------------------------- */

static int cmd_serve(const char *relay_host, uint16_t port, bool insecure,
                     unsigned timeout_s, const char *derpmap_url)
{
	/* A fresh identity per run, like upstream's default. The pre-shared key
	 * is what stops a relay operator who has watched both public keys go past
	 * from joining the tunnel, so it is always generated. */
	tc_wg_identity me;
	uint8_t disco_pub[32];
	if (tc_wg_identity_generate(&me) != TC_OK ||
	    tc_disco_key_for_node(NULL, disco_pub, me.private_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not generate keys\n");
		return 1;
	}

	static tc_conn_info ci;
	memset(&ci, 0, sizeof ci);
	memcpy(ci.server_public, me.public_key, 32);
	memcpy(ci.server_disco_public, disco_pub, 32);
	ci.has_disco_public = true;
	if (tc_random_bytes(ci.preshared_key, sizeof ci.preshared_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not generate a pre-shared key\n");
		return 1;
	}
	ci.has_preshared_key = true;

	/* Embed the relay rather than naming a region by number, so the address
	 * is self-contained and the other side needs no DERP map either. */
	if (relay_host != NULL) {
		ci.num_regions = 1;
		ci.regions[0].num_nodes = 1;
		if (snprintf(ci.regions[0].nodes[0].hostname, TC_DNS_NAME_MAX, "%s",
		             relay_host) >= TC_DNS_NAME_MAX) {
			fprintf(stderr, "tailcat-c: relay hostname is too long\n");
			return 1;
		}
	} else {
		/* No relay named: fetch the map and probe for a quick one. */
		ci.region_id = -1;
		if (ensure_relay(&ci, derpmap_url, insecure, 15000) != TC_OK)
			return 1;
		ci.region_id = 0;
		if (ci.regions[0].num_nodes > 2)
			ci.regions[0].num_nodes = 2;
		relay_host = ci.regions[0].nodes[0].hostname;
	}

	char addr[TC_ADDR_STR_MAX];
	if (tc_addr_encode(addr, sizeof addr, &ci, NULL) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build an address\n");
		return 1;
	}

	tc_derp_dial_opts opts;
	memset(&opts, 0, sizeof opts);
	opts.hostname = relay_host;
	opts.insecure_skip_verify = insecure;
	opts.timeout_ms = 15000;

	tc_derp_client derp;
	if (tc_derp_connect(&derp, &opts, me.private_key, me.public_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: relay: %s\n", tc_derp_error_string());
		return 1;
	}
	tc_derp_set_read_timeout(&derp, 200);

	/* The address goes to stderr: stdout is the data pipe. */
	fprintf(stderr, "# relay %s\n", relay_host);
	fprintf(stderr, "# listening with new address: %s\n", addr);
	fflush(stderr);

	int status = 1;
	tc_tcp_conn *tcp = NULL;
	tc_wg_session sess;
	memset(&sess, 0, sizeof sess);

	uint64_t deadline = now_ms() + (uint64_t)timeout_s * 1000u;
	uint8_t client_key[32];
	bool have_client = false;
	tc_wg_handshake hs;
	bool up = false;

	/* Wait for a client to introduce itself, then answer its handshake. Both
	 * arrive on the same relay connection, and the client resends each until
	 * acknowledged, so a single loop over both is enough. */
	while (!up && now_ms() < deadline) {
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		int rc = tc_derp_recv(&derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			goto out;
		}

		if (tc_meow_is_packet(buf, len)) {
			uint8_t node[32], disco[32];
			if (tc_meow_parse_ping(buf, len, node, disco) != TC_OK)
				continue;
			if (memcmp(node, src, 32) != 0)
				continue; /* the relay's idea of the sender must agree */
			if (!have_client) {
				memcpy(client_key, node, 32);
				have_client = true;
				vlogf("client introduced itself");
			} else if (memcmp(client_key, node, 32) != 0) {
				continue; /* already serving someone else */
			}
			/* Acknowledge every ping: the client resends until it hears
			 * back, and duplicates are harmless. */
			uint8_t ack[TC_MEOW_MEOWED_LEN];
			size_t ack_len = 0;
			tc_meow_encode_meowed(ack, sizeof ack, &ack_len);
			(void)tc_derp_send(&derp, client_key, ack, ack_len);
			continue;
		}

		if (!have_client || memcmp(src, client_key, 32) != 0)
			continue;
		if (len != TC_WG_INITIATION_SIZE || buf[0] != TC_WG_MSG_INITIATION)
			continue;

		if (tc_wg_handshake_init(&hs, &me, client_key, ci.preshared_key) !=
		    TC_OK)
			continue;
		if (tc_wg_consume_initiation(&hs, &me, buf, NULL, NULL) != TC_OK) {
			vlogf("rejected a handshake initiation");
			continue;
		}
		uint8_t resp[TC_WG_RESPONSE_SIZE];
		if (tc_wg_create_response(resp, &hs, &me, 0) != TC_OK)
			continue;
		if (tc_derp_send(&derp, client_key, resp, sizeof resp) != TC_OK) {
			fprintf(stderr, "tailcat-c: relay send failed\n");
			goto out;
		}
		if (tc_wg_begin_session(&sess, &hs) != TC_OK) {
			fprintf(stderr, "tailcat-c: could not derive session keys\n");
			goto out;
		}
		up = true;
	}

	if (!up) {
		fprintf(stderr, "tailcat-c: no client connected\n");
		goto out;
	}
	vlogf("tunnel up (we are the responder)");

	uint8_t our_ip[TC_TUNNEL_ADDR_LEN], their_ip[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(our_ip, me.public_key);
	tc_tunnel_addr_for_key(their_ip, client_key);

	pump ctx;
	ctx.derp = &derp;
	ctx.sess = &sess;
	memcpy(ctx.server_key, client_key, 32);

	tcp = tc_tcp_new(our_ip, their_ip, tcp_out, &ctx);
	if (tcp == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto out;
	}
	if (tc_tcp_listen(tcp, port) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not listen\n");
		goto out;
	}
	vlogf("listening on port %u inside the tunnel", (unsigned)port);

	status = run_pipe(&derp, &sess, tcp, client_key, deadline);

	if (status != 0 && now_ms() >= deadline)
		fprintf(stderr, "tailcat-c: timed out after %u seconds\n", timeout_s);

out:
	if (tcp != NULL)
		tc_tcp_free(tcp);
	tc_wg_session_clear(&sess);
	tc_derp_close(&derp);
	return status;
}

/* ---- entry ------------------------------------------------------------ */

int main(int argc, char **argv)
{
	bool insecure = false;
	unsigned timeout_s = 60;
	const char *relay = NULL;
	/* NULL means the built-in default; --derpmap-url overrides, matching
	 * upstream's flag of the same name. */
	const char *derpmap_url = NULL;
	const char *args[3] = { NULL, NULL, NULL };
	size_t nargs = 0;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
			g_verbose = true;
		} else if (strcmp(a, "--insecure") == 0) {
			insecure = true;
		} else if (strcmp(a, "--relay") == 0 && i + 1 < argc) {
			relay = argv[++i];
		} else if (strcmp(a, "--derpmap-url") == 0 && i + 1 < argc) {
			derpmap_url = argv[++i];
		} else if (strcmp(a, "--timeout") == 0 && i + 1 < argc) {
			timeout_s = (unsigned)strtoul(argv[++i], NULL, 10);
			if (timeout_s == 0)
				timeout_s = 60;
		} else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			usage(stdout);
			return 0;
		} else if (a[0] == '-' && a[1] != '\0') {
			fprintf(stderr, "tailcat-c: unknown flag %s\n", a);
			usage(stderr);
			return 2;
		} else if (nargs < 3) {
			args[nargs++] = a;
		} else {
			fprintf(stderr, "tailcat-c: too many arguments\n");
			return 2;
		}
	}

	if (nargs == 0) {
		usage(stderr);
		return 2;
	}
	if (strcmp(args[0], "version") == 0) {
		printf("tailcat-c %s\n", TAILCAT_C_VERSION);
		return 0;
	}
	if (strcmp(args[0], "resolve") == 0) {
		if (nargs < 2) {
			fprintf(stderr, "tailcat-c: resolve needs an address\n");
			return 2;
		}
		return cmd_resolve(args[1], derpmap_url, insecure);
	}
	if (strcmp(args[0], "ping") == 0) {
		if (nargs < 2) {
			fprintf(stderr, "tailcat-c: ping needs an address\n");
			return 2;
		}
		return cmd_ping(args[1], insecure, timeout_s, derpmap_url);
	}
	if (strcmp(args[0], "serve") == 0) {
		uint16_t sport = 1;
		if (nargs >= 2) {
			unsigned long p2 = strtoul(args[1], NULL, 10);
			if (p2 == 0 || p2 > 65535) {
				fprintf(stderr, "tailcat-c: bad port %s\n", args[1]);
				return 2;
			}
			sport = (uint16_t)p2;
		}
		return cmd_serve(relay, sport, insecure, timeout_s, derpmap_url);
	}
	if (strcmp(args[0], "parse") == 0) {
		if (nargs < 2) {
			fprintf(stderr, "tailcat-c: parse needs an address\n");
			return 2;
		}
		return cmd_parse(args[1]);
	}

	uint16_t port = 1;
	if (nargs >= 2) {
		unsigned long p = strtoul(args[1], NULL, 10);
		if (p == 0 || p > 65535) {
			fprintf(stderr, "tailcat-c: bad port %s\n", args[1]);
			return 2;
		}
		port = (uint16_t)p;
	}
	return cmd_pipe(args[0], port, insecure, timeout_s, derpmap_url);
}
