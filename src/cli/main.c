/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The tailcat-c command: netcat over a WireGuard tunnel, relayed through
 * DERP, speaking to a real tailcat server.
 *
 *     tailcat-c <tc-address> [port]      connect and pipe stdin/stdout
 *     tailcat-c serve [port]             listen, printing an address
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
 * embedded, choosing a region by measured handshake time unless --relay names
 * one. The server is the WireGuard responder and the TCP passive opener, and
 * the real Go client interoperates with it.
 *
 * Packets reach TCP through the demultiplexer rather than a lone connection.
 * A pipe only ever uses one, but routing it the same way means the dispatch
 * path is exercised by every live run instead of only by its own tests.
 */

#include "tc/addr.h"
#include "tc/crypto.h"
#include "tc/derp.h"
#include "tc/derpmap.h"
#include "tc/wgpeer.h"
#include "tc/tailcat.h"
#include "tc/portset.h"
#include "tc/proxy.h"
#include "tc/tcpmux.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
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
	        "  tailcat-c serve                         accept one connection, "
	        "pipe it to stdout\n"
	        "  tailcat-c serve <ports>                 serve local ports, e.g. "
	        "22,80,8000-8999 or all\n"
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
	        "      --timeout SEC     give up after SEC seconds (default 60; "
	        "0 = never, for serve <ports>)\n"
	        "\n"
	        "The client port defaults to 1, which is what a bare server "
	        "pipes.\n"
	        "`serve <ports>` proxies each port to the same port on localhost "
	        "and stays up.\n"
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
	tc_wg_peer *peer;
	uint8_t server_key[32];
	/* Set when a relay write timed out, which leaves a frame half-written
	 * and the stream unusable. The event loop acts on it; the callback
	 * cannot, since it has no way to report upwards. */
	bool relay_stalled;
} pump;

/* wg_out is how the WireGuard layer reaches the wire: everything it emits --
 * transport packets, handshakes, keepalives -- goes to the relay addressed to
 * the peer's node key. */
static int wg_out(void *vctx, const uint8_t *pkt, size_t len)
{
	pump *p = (pump *)vctx;
	/* A failed relay write is packet loss, which both WireGuard and TCP above
	 * already handle by retrying. A write that *times out* is different: the
	 * frame is half-sent and the stream is no longer parseable, so the loop
	 * is told to rebuild the connection rather than carry on writing into
	 * it. */
	if (tc_derp_send(p->derp, p->server_key, pkt, len) == TC_ERR_TIMEOUT)
		p->relay_stalled = true;
	return TC_OK;
}

static int tcp_out(void *vctx, const uint8_t *ip_pkt, size_t len)
{
	pump *p = (pump *)vctx;
	/* TC_ERR_AGAIN means a rekey is in progress and there is no session to
	 * send under. That is ordinary packet loss as far as TCP is concerned,
	 * and TCP is the thing that knows how to retransmit -- so it is reported
	 * as success and the segment is simply dropped. */
	(void)tc_wg_peer_send(p->peer, ip_pkt, len, now_ms());
	return TC_OK;
}

/* ---- staying connected to the relay ------------------------------------ */

/* relay_recover rebuilds a dead or restarting relay connection, with backoff.
 *
 * Nothing above DERP is disturbed: the WireGuard session is keyed to the two
 * peers rather than to the path, so a tunnel resumes across a reconnection
 * rather than needing a new handshake. What the relay does forget is the
 * introduction, which is why a caller that meowed has to meow again --
 * `reintroduce` is that, and it is NULL for the server, which is introduced
 * to rather than introducing.
 *
 * Returns TC_OK if the relay is usable again, or the last error if the
 * deadline passed first. */
static int relay_recover(tc_derp_client *derp, const uint8_t peer_key[32],
                         const uint8_t *reintroduce, size_t reintroduce_len,
                         uint64_t deadline)
{
	unsigned attempt = 0;
	int rc = TC_ERR_CLOSED;

	while (now_ms() < deadline) {
		/* Exponential backoff, capped: a relay that is restarting comes back
		 * in seconds, and hammering it while it does helps nobody. */
		uint64_t wait = 250ull << (attempt < 5 ? attempt : 5);
		if (wait > 8000)
			wait = 8000;
		if (attempt > 0) {
			uint64_t until = now_ms() + wait;
			if (until > deadline)
				until = deadline;
			while (now_ms() < until)
				poll(NULL, 0, 50);
		}
		attempt++;

		vlogf("reconnecting to the relay (attempt %u)", attempt);
		rc = tc_derp_reconnect(derp);
		if (rc != TC_OK) {
			vlogf("reconnect failed: %s", tc_derp_error_string());
			continue;
		}
		tc_derp_set_read_timeout(derp, 200);
		tc_derp_set_write_timeout(derp, 15000);

		if (reintroduce == NULL || reintroduce_len == 0) {
			vlogf("relay reconnected");
			return TC_OK;
		}

		/* Re-meow. The server answers every ping, so one that is already a
		 * peer simply acknowledges again. */
		uint64_t give_up = now_ms() + 5000;
		if (give_up > deadline)
			give_up = deadline;
		uint64_t next = 0;
		while (now_ms() < give_up) {
			if (now_ms() >= next) {
				if (tc_derp_send(derp, peer_key, reintroduce,
				                 reintroduce_len) != TC_OK)
					break;
				next = now_ms() + 500;
			}
			uint8_t src[32];
			static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
			size_t len = 0;
			int r = tc_derp_recv(derp, src, buf, sizeof buf, &len);
			if (r == TC_ERR_TIMEOUT)
				continue;
			if (r != TC_OK)
				break;
			if (memcmp(src, peer_key, 32) != 0)
				continue;
			if (tc_meow_is_meowed(buf, len)) {
				vlogf("relay reconnected and re-introduced");
				return TC_OK;
			}
			/* Anything else that arrives proves the path works too. */
			vlogf("relay reconnected");
			return TC_OK;
		}
		vlogf("reconnected but the peer did not answer; trying again");
		rc = TC_ERR_TIMEOUT;
	}
	return rc;
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
 *
 * Packets go through the demultiplexer even though a pipe only ever uses one
 * connection. Dialling gives the caller that connection up front and `tcp` is
 * it; serving passes NULL and the loop takes the first connection the
 * listener accepts. Routing a lone connection through the mux costs one array
 * scan per packet and means the dispatch path is the one exercised by every
 * live run, rather than only by its own tests. */
static int run_pipe(tc_derp_client *derp, tc_wg_peer *peer,
                    tc_tcp_mux *mux, tc_tcp_conn *tcp,
                    const uint8_t peer_key[32], const uint8_t *reintroduce,
                    size_t reintroduce_len, bool *stall, uint64_t deadline)
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
		bool progress = false;

		if (stall != NULL && *stall) {
			*stall = false;
			vlogf("a relay write stalled; rebuilding the connection");
			if (relay_recover(derp, peer_key, reintroduce, reintroduce_len,
			                  deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: lost the relay\n");
				return connected ? 0 : 1;
			}
		}

		/* The WireGuard timers run first: a session that has reached its
		 * rekey age must start renewing before TCP tries to send under it. */
		tc_wg_peer_tick(peer, t);
		tc_tcp_mux_tick(mux, t);

		/* Serving: the connection arrives rather than being dialled. Only
		 * the first is taken -- a pipe has one stdin to give it. */
		if (tcp == NULL)
			tcp = tc_tcp_mux_accept(mux);
		if (tcp == NULL)
			goto wait;

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
	wait:
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
			if (connected && !stdin_eof && tcp != NULL &&
			    tc_tcp_writable(tcp) > 0) {
				pfds[nfds].fd = STDIN_FILENO;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}

			int wait_ms = 20;
			uint64_t dl = tc_tcp_mux_next_deadline(mux);
			uint64_t wdl = tc_wg_peer_next_deadline(peer);
			if (wdl < dl)
				dl = wdl;
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
		if (rc == TC_ERR_TIMEOUT) {
			/* A relay that has sent nothing at all, not even a keep-alive,
			 * is gone whether or not the socket has noticed. Without this a
			 * dead relay looks identical to a quiet one and the pipe hangs
			 * until the overall timeout. */
			if (tc_derp_idle_ms(derp) > TC_DERP_DEAD_AFTER_MS) {
				vlogf("no keep-alive for %llus; the relay is gone",
				      (unsigned long long)(tc_derp_idle_ms(derp) / 1000));
				if (relay_recover(derp, peer_key, reintroduce,
				                  reintroduce_len, deadline) != TC_OK) {
					fprintf(stderr, "tailcat-c: lost the relay\n");
					return connected ? 0 : 1;
				}
			}
			continue;
		}
		if (rc == TC_ERR_CLOSED) {
			/* The relay announced a restart or hung up. The tunnel itself is
			 * unaffected -- WireGuard is keyed to the peers, not the path --
			 * so rebuilding the relay resumes it. */
			if (half_closed)
				return 0;
			if (relay_recover(derp, peer_key, reintroduce, reintroduce_len,
			                  deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: relay: %s\n",
				        tc_derp_error_string());
				return connected ? 0 : 1;
			}
			continue;
		}
		if (rc != TC_OK) {
			if (!half_closed)
				fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			return connected ? 0 : 1;
		}
		if (memcmp(src, peer_key, 32) != 0 || len == 0)
			continue;

		/* Every WireGuard message goes here, not just transport packets:
		 * a rekey initiation from the peer arrives on this same path and
		 * has to be answered, or the tunnel dies when the session ages
		 * out. */
		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_peer_input(peer, buf, len, inner, sizeof inner, &inner_len,
		                     now_ms()) != TC_OK)
			continue;
		if (inner_len == 0)
			continue; /* a handshake, a keepalive, or something rejected */
		tc_tcp_mux_input(mux, inner, inner_len, now_ms());
	}

	return 1;
}

/* log_wg_summary reports what the session lifetime machinery actually did.
 * A long-lived run is the only place rekeying is visible, and without this
 * there is no way for a test to tell a tunnel that renewed itself from one
 * the peer renewed on its behalf -- both look like "it still works". */
static void log_wg_summary(const tc_wg_peer *peer)
{
	if (!g_verbose)
		return;
	tc_wg_peer_stats st;
	tc_wg_peer_get_stats(peer, &st);
	vlogf("wg: initiated=%llu responded=%llu rekeys=%llu retried=%llu "
	      "keepalives=%llu on-previous=%llu",
	      (unsigned long long)st.handshakes_initiated,
	      (unsigned long long)st.handshakes_responded,
	      (unsigned long long)st.rekeys,
	      (unsigned long long)st.handshakes_retried,
	      (unsigned long long)st.keepalives_sent,
	      (unsigned long long)st.recv_on_previous);
}

/* ---- serving ports ----------------------------------------------------- */

/* dial_localhost connects to a local service, trying IPv4 then IPv6 loopback.
 *
 * The literal addresses are used rather than resolving "localhost", which
 * upstream also refuses to trust the OS resolver for: on a misconfigured
 * machine that name can point somewhere else entirely, and a proxy that
 * forwards a tunnelled connection to the wrong host is a hole rather than a
 * bug. There is no name here to get wrong.
 *
 * The connect is blocking, which is safe only because loopback either
 * succeeds or is refused immediately -- there is no network in between to
 * time out on. */
static int dial_localhost(uint16_t port)
{
	struct sockaddr_in v4;
	memset(&v4, 0, sizeof v4);
	v4.sin_family = AF_INET;
	v4.sin_port = htons(port);
	v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd >= 0) {
		if (connect(fd, (struct sockaddr *)&v4, sizeof v4) == 0)
			return fd;
		(void)close(fd);
	}

	struct sockaddr_in6 v6;
	memset(&v6, 0, sizeof v6);
	v6.sin6_family = AF_INET6;
	v6.sin6_port = htons(port);
	v6.sin6_addr = in6addr_loopback;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd >= 0) {
		if (connect(fd, (struct sockaddr *)&v6, sizeof v6) == 0)
			return fd;
		(void)close(fd);
	}
	return -1;
}

static bool port_is_served(void *ctx, uint16_t port)
{
	return tc_portset_has((const tc_portset *)ctx, port);
}

/* The one-shot pipe answers on whatever port the client dialled, which is
 * what upstream's argument-free server does. */
static bool accept_any_port(void *ctx, uint16_t port)
{
	(void)ctx;
	(void)port;
	return true;
}

/* run_serve_ports is the event loop for `serve <ports>`: accept inside the
 * tunnel, dial the matching local port, and splice.
 *
 * The ordering in the loop is load-bearing. tc_tcp_mux_reap frees connections
 * the proxy may still hold pointers to, so it runs only after the proxy has
 * had a chance to notice they closed and let go. Reaping the mux first -- the
 * obvious place, at the top -- would be a use-after-free that only appears
 * when a peer hangs up at the wrong moment. */
static int run_serve_ports(tc_derp_client *derp, tc_wg_peer *peer,
                           tc_tcp_mux *mux, tc_proxy *proxy,
                           const uint8_t peer_key[32], bool *stall,
                           uint64_t deadline)
{
	tc_derp_set_read_timeout(derp, 20);

	while (now_ms() < deadline) {
		uint64_t t = now_ms();

		if (stall != NULL && *stall) {
			*stall = false;
			vlogf("a relay write stalled; rebuilding the connection");
			if (relay_recover(derp, peer_key, NULL, 0, deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: lost the relay\n");
				return 1;
			}
		}

		tc_wg_peer_tick(peer, t);
		tc_tcp_mux_tick(mux, t);

		/* Accept whatever arrived and give each one a local socket. */
		tc_tcp_conn *c;
		while ((c = tc_tcp_mux_accept(mux)) != NULL) {
			uint16_t port = tc_tcp_local_port(c);
			int fd = dial_localhost(port);
			if (fd < 0) {
				/* Nothing is listening locally. Resetting says so at once
				 * rather than leaving the client to time out. */
				vlogf("no local service on port %u; refusing", (unsigned)port);
				tc_tcp_mux_close(mux, c, t);
				continue;
			}
			if (tc_proxy_add(proxy, c, fd) != TC_OK) {
				vlogf("too many connections; refusing port %u",
				      (unsigned)port);
				(void)close(fd);
				tc_tcp_mux_close(mux, c, t);
				continue;
			}
			vlogf("accepted a connection to port %u", (unsigned)port);
		}

		bool progress = tc_proxy_pump(proxy, t) > 0;
		tc_proxy_reap(proxy, t);
		/* Only now, once the proxy has dropped anything that finished. */
		tc_tcp_mux_reap(mux);

		if (!progress && !tc_derp_has_pending(derp)) {
			struct pollfd pfds[2 + TC_TCP_MAX_CONNS];
			nfds_t nfds = 0;
			int dfd = tc_derp_fd(derp);
			if (dfd >= 0) {
				pfds[nfds].fd = dfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
			for (size_t i = 0; i < TC_TCP_MAX_CONNS && nfds < 1 + TC_TCP_MAX_CONNS;
			     i++) {
				int pfd = -1;
				bool rd = false, wr = false;
				if (!tc_proxy_interest(proxy, i, &pfd, &rd, &wr))
					continue;
				if (!rd && !wr)
					continue;
				pfds[nfds].fd = pfd;
				pfds[nfds].events = (short)((rd ? POLLIN : 0) |
				                            (wr ? POLLOUT : 0));
				pfds[nfds].revents = 0;
				nfds++;
			}

			int wait_ms = 20;
			uint64_t dl = tc_tcp_mux_next_deadline(mux);
			uint64_t wdl = tc_wg_peer_next_deadline(peer);
			if (wdl < dl)
				dl = wdl;
			if (dl != UINT64_MAX) {
				uint64_t nowv = now_ms();
				wait_ms = (dl > nowv) ? (int)(dl - nowv) : 0;
				if (wait_ms > 200)
					wait_ms = 200;
			}
			if (nfds > 0)
				(void)poll(pfds, nfds, wait_ms);
		}

		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		int rc = tc_derp_recv(derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT) {
			if (tc_derp_idle_ms(derp) > TC_DERP_DEAD_AFTER_MS) {
				vlogf("no keep-alive; the relay is gone");
				if (relay_recover(derp, peer_key, NULL, 0, deadline) != TC_OK) {
					fprintf(stderr, "tailcat-c: lost the relay\n");
					return 1;
				}
			}
			continue;
		}
		if (rc == TC_ERR_CLOSED) {
			if (relay_recover(derp, peer_key, NULL, 0, deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: relay: %s\n",
				        tc_derp_error_string());
				return 1;
			}
			continue;
		}
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			return 1;
		}
		if (memcmp(src, peer_key, 32) != 0 || len == 0)
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_peer_input(peer, buf, len, inner, sizeof inner, &inner_len,
		                     now_ms()) != TC_OK)
			continue;
		if (inner_len == 0)
			continue;
		tc_tcp_mux_input(mux, inner, inner_len, now_ms());
	}
	return 0;
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
	tc_tcp_mux *mux = NULL;
	tc_wg_peer peer;
	memset(&peer, 0, sizeof peer);
	pump ctx;
	memset(&ctx, 0, sizeof ctx);

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

	ctx.derp = &derp;
	memcpy(ctx.server_key, ci.server_public, 32);
	if (tc_wg_peer_init(&peer, &me, ci.server_public,
	                    ci.has_preshared_key ? ci.preshared_key : NULL, wg_out,
	                    &ctx) != TC_OK) {
		fprintf(stderr, "tailcat-c: handshake setup failed\n");
		goto out;
	}
	ctx.peer = &peer;

	if (tc_wg_peer_start_handshake(&peer, now_ms()) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build the handshake\n");
		goto out;
	}

	/* The peer owns the retry schedule from here; this loop only feeds it
	 * packets and the clock. */
	while (!tc_wg_peer_is_up(&peer, now_ms()) && now_ms() < deadline) {
		tc_wg_peer_tick(&peer, now_ms());

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
		size_t ignored = 0;
		static uint8_t scratch[TC_DERP_MAX_PACKET_SIZE];
		(void)tc_wg_peer_input(&peer, buf, len, scratch, sizeof scratch,
		                       &ignored, now_ms());
	}
	if (!tc_wg_peer_is_up(&peer, now_ms())) {
		fprintf(stderr, "tailcat-c: no handshake response from the server\n");
		goto out;
	}
	vlogf("tunnel up");

	/* ---- TCP inside the tunnel ----------------------------------------- */

	uint8_t our_ip[TC_TUNNEL_ADDR_LEN], their_ip[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(our_ip, me.public_key);
	tc_tunnel_addr_for_key(their_ip, ci.server_public);

	mux = tc_tcp_mux_new(our_ip, their_ip, tcp_out, &ctx);
	if (mux == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto out;
	}
	if (tc_tcp_mux_connect(mux, port, now_ms(), &tcp) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not start the connection\n");
		goto out;
	}
	vlogf("connecting to port %u from %u", (unsigned)port,
	      (unsigned)tc_tcp_local_port(tcp));

	tc_derp_set_write_timeout(&derp, 15000);
	status = run_pipe(&derp, &peer, mux, tcp, ci.server_public, ping, ping_len,
	                  &ctx.relay_stalled, deadline);

	if (status != 0 && now_ms() >= deadline)
		fprintf(stderr, "tailcat-c: timed out after %u seconds\n", timeout_s);

out:
	/* The mux owns every connection it handed out. */
	tc_tcp_mux_free(mux);
	log_wg_summary(&peer);
	tc_wg_peer_clear(&peer);
	tc_derp_close(&derp);
	return status;
}

/* ---- serve mode ------------------------------------------------------- */

/* cmd_serve runs a server.
 *
 * With `ports` NULL it is the one-shot pipe: accept a single connection on
 * ANY port, write it to stdout, and exit -- which is what upstream's
 * argument-free `tailcat` does. Accepting on any port rather than on one
 * chosen number matters for compatibility: a client that dials port 80 of a
 * bare server gets through, as it does upstream.
 *
 * With `ports` set it proxies each of those ports to the same port on
 * localhost and stays up. */
static int cmd_serve(const char *relay_host, const tc_portset *ports,
                     bool insecure, unsigned timeout_s,
                     const char *derpmap_url)
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
	tc_tcp_mux *mux = NULL;
	tc_proxy *proxy = NULL;
	tc_wg_peer peer;
	memset(&peer, 0, sizeof peer);
	pump ctx;
	memset(&ctx, 0, sizeof ctx);

	/* Zero means no deadline at all. Expressed as a time that never arrives
	 * rather than as 0, which is a moment that has already passed -- and
	 * which made the meow loop give up before the first client could
	 * answer. */
	uint64_t deadline = (timeout_s == 0)
	                        ? UINT64_MAX
	                        : now_ms() + (uint64_t)timeout_s * 1000u;
	uint8_t client_key[32];
	bool have_client = false;
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

		/* The peer object cannot exist before the meow tells us who the
		 * client is, so it is built on first contact and reused for every
		 * handshake after -- including the rekeys, which is the whole
		 * point of keeping it. */
		if (ctx.peer == NULL) {
			ctx.derp = &derp;
			memcpy(ctx.server_key, client_key, 32);
			if (tc_wg_peer_init(&peer, &me, client_key, ci.preshared_key,
			                    wg_out, &ctx) != TC_OK) {
				fprintf(stderr, "tailcat-c: handshake setup failed\n");
				goto out;
			}
			ctx.peer = &peer;
		}

		size_t ignored = 0;
		static uint8_t scratch[TC_DERP_MAX_PACKET_SIZE];
		(void)tc_wg_peer_input(&peer, buf, len, scratch, sizeof scratch,
		                       &ignored, now_ms());
		/* A responder holds its new keys in `next` until the client sends
		 * data under them, so "up" here means the handshake was answered,
		 * not that we can transmit yet. */
		if (tc_wg_peer_has_keys(&peer, now_ms()))
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

	mux = tc_tcp_mux_new(our_ip, their_ip, tcp_out, &ctx);
	if (mux == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto out;
	}
	/* An accept filter rather than a listener list: `all` is 65,535 ports,
	 * and the one-shot mode accepts on any port at all. Neither fits an
	 * array of sixteen. */
	tc_tcp_mux_set_accept_filter(mux, ports != NULL ? port_is_served
	                                                : accept_any_port,
	                             (void *)(uintptr_t)ports);

	tc_derp_set_write_timeout(&derp, 15000);

	if (ports != NULL) {
		char what[128];
		(void)tc_portset_describe(ports, what, sizeof what);
		fprintf(stderr, "# serving %s to localhost\n", what);

		proxy = tc_proxy_new(TC_TCP_MAX_CONNS);
		if (proxy == NULL) {
			fprintf(stderr, "tailcat-c: out of memory\n");
			goto out;
		}
		/* A port server is meant to stay up, so --timeout only applies if
		 * the user asked for one. */
		status = run_serve_ports(&derp, &peer, mux, proxy, client_key,
		                         &ctx.relay_stalled, deadline);
	} else {
		vlogf("listening on any port inside the tunnel");
		/* The connection is accepted inside the loop, so NULL here. The
		 * server is introduced to rather than introducing, so it has nothing
		 * to re-send after a reconnection: the client re-meows and we
		 * answer. */
		status = run_pipe(&derp, &peer, mux, NULL, client_key, NULL, 0,
		                  &ctx.relay_stalled, deadline);
		if (status != 0 && now_ms() >= deadline)
			fprintf(stderr, "tailcat-c: timed out after %u seconds\n",
			        timeout_s);
	}

out:
	/* Order matters: the proxy refers to connections the mux owns. */
	tc_proxy_free(proxy);
	tc_tcp_mux_free(mux);
	log_wg_summary(&peer);
	tc_wg_peer_clear(&peer);
	tc_derp_close(&derp);
	return status;
}

/* ---- entry ------------------------------------------------------------ */

int main(int argc, char **argv)
{
	bool insecure = false;
	unsigned timeout_s = 60;
	/* A port server is meant to stay up, so it ignores the default deadline
	 * and honours only a --timeout the user actually asked for. Coercing 0
	 * back to 60 would make "run until I stop it" impossible to express. */
	bool timeout_given = false;
	const char *relay = NULL;
	/* NULL means the built-in default; --derpmap-url overrides, matching
	 * upstream's flag of the same name. */
	const char *derpmap_url = NULL;
	/* Room for a subcommand plus several port specs: upstream allows the
	 * list to be spread over arguments, as in `serve 80,443 8000-8999`. */
	const char *args[16];
	size_t nargs = 0;
	memset(args, 0, sizeof args);

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
			timeout_given = true;
		} else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			usage(stdout);
			return 0;
		} else if (a[0] == '-' && a[1] != '\0') {
			fprintf(stderr, "tailcat-c: unknown flag %s\n", a);
			usage(stderr);
			return 2;
		} else if (nargs < sizeof args / sizeof args[0]) {
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
	/* Outside the port server, a deadline of zero would mean "give up at
	 * once", which nobody asks for by typing --timeout 0. */
	if (timeout_s == 0 && strcmp(args[0], "serve") != 0)
		timeout_s = 60;
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
		if (nargs == 1) {
			if (timeout_s == 0)
				timeout_s = 60; /* the one-shot pipe needs a deadline */
			return cmd_serve(relay, NULL, insecure, timeout_s, derpmap_url);
		}

		static tc_portset ports;
		tc_portset_clear(&ports);
		for (size_t i = 1; i < nargs; i++) {
			tc_portset_service svc = TC_PORTSET_SVC_NONE;
			int rc = tc_portset_parse(&ports, args[i], &svc);
			if (rc == TC_ERR_UNSUPPORTED) {
				/* Naming the service beats "bad port list": it is a real
				 * upstream feature, just not one we have. */
				fprintf(stderr,
				        "tailcat-c: the \"%s\" service is not implemented "
				        "here; see the feature table in README.md\n",
				        tc_portset_service_name(svc));
				return 2;
			}
			if (rc != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n",
				        tc_portset_error_string());
				return 2;
			}
		}
		return cmd_serve(relay, &ports, insecure,
		                 timeout_given ? timeout_s : 0, derpmap_url);
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
