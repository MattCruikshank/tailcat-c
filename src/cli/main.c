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
#include "tc/allowlist.h"
#include "tc/crypto.h"
#include "tc/derp.h"
#include "tc/derpmap.h"
#include "tc/wgpeer.h"
#include "tc/tailcat.h"
#include "tc/fwdspec.h"
#include "tc/keyfile.h"
#include "tc/nat64.h"
#include "tc/netcheck.h"
#include "tc/path.h"
#include "tc/udp.h"
#include "tc/portset.h"
#include "tc/shquote.h"
#include "tc/proxy.h"
#include "tc/tcpmux.h"
#include "tc/tls.h"

#include <dirent.h>
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
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
	        "22,80,8000-8999 or all;\n"
	        "                                          add exit-node to "
	        "forward anywhere this machine can reach\n"
	        "  tailcat-c forward <tc-addr> <maps>      forward local ports, "
	        "e.g. 8080, 18080:8080,\n"
	        "                                          or "
	        "13306:192.168.1.10:3306 via an exit node\n"
	        "  tailcat-c socks <tc-addr> [port] [-- cmd...]\n"
	        "                                          SOCKS5 proxy; with a "
	        "command, runs it with\n"
	        "                                          all_proxy set and "
	        "exits when it does\n"
	        "  tailcat-c ssh [-p PORT] [user@]<tc-addr> [cmd...]\n"
	        "  tailcat-c cp [-r] <src>... <dst>        copy via scp, paths as "
	        "<tc-addr>:path\n"
	        "  tailcat-c ping <tc-address>             time the round trip to "
	        "a server\n"
	        "  tailcat-c resolve <tc-address>          embed the relay, for "
	        "offline use\n"
	        "  tailcat-c parse <tc-address>            describe an address\n"
	        "  tailcat-c netcheck                      report UDP, NAT and relay\n"
	        "                                          latency\n"
	        "  tailcat-c genkey --key <name> [--client] [--region N]\n"
	        "  tailcat-c printpub                      the client key that "
	        "would be used\n"
	        "  tailcat-c version\n"
	        "\n"
	        "flags:\n"
	        "  -v, --verbose         report progress on stderr\n"
	        "      --insecure        skip TLS verification of the relay\n"
	        "      --relay HOST      serve through this relay instead of "
	        "choosing one\n"
	        "      --full-address    embed the relay in the address, so "
	        "clients need no map\n"
	        "      --allow KEYS      comma-separated client nodekey: list "
	        "for serve, or \"none\"\n"
	        "      --bind ADDR       listen address for forward and socks "
	        "(default 127.0.0.1)\n"
	        "  -p, PORT              server port for ssh and cp (default 22)\n"
	        "      --key NAME        saved identity to use, or \"new\" for "
	        "an ephemeral one\n"
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

/* ---- netcheck subcommand ---------------------------------------------- */

/* What the network can do, printed rather than guessed at.
 *
 * Every other subcommand acts on the answer; this one just shows it, which is
 * what makes it useful when a direct path is not happening and the question
 * is whether the network or the code is at fault.
 */
static int cmd_netcheck(const char *derpmap_url, bool insecure,
                        unsigned timeout_s)
{
	tc_derp_map *m = (tc_derp_map *)malloc(sizeof *m);
	if (m == NULL)
		return 1;

	int timeout_ms = (timeout_s > 0 && timeout_s < 600) ? (int)timeout_s * 1000
	                                                    : 60000;
	if (tc_derpmap_fetch(m, derpmap_url, insecure, timeout_ms) != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_derpmap_error_string());
		free(m);
		return 1;
	}

	tc_udp u;
	if (tc_udp_open(&u, 0) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not open a UDP socket\n");
		free(m);
		return 1;
	}

	tc_netcheck_opts o;
	memset(&o, 0, sizeof o);
	o.timeout_ms = 3000;

	tc_netcheck_report rep;
	int rc = tc_netcheck_run(&rep, m, &u, &o, NULL, NULL);
	tc_udp_close(&u);
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_strerror(rc));
		free(m);
		return 1;
	}

	printf("UDP:  %s\n", rep.udp ? "yes" : "no (the relay is the only path)");
	printf("IPv4: %s\n", rep.ipv4 ? "yes" : "no");
	printf("IPv6: %s\n", rep.ipv6 ? "yes" : "no");

	char s2[80];
	if (rep.global_v4.ip_len != 0 &&
	    tc_endpoint_format(s2, sizeof s2, &rep.global_v4) == TC_OK)
		printf("public IPv4: %s\n", s2);
	if (rep.global_v6.ip_len != 0 &&
	    tc_endpoint_format(s2, sizeof s2, &rep.global_v6) == TC_OK)
		printf("public IPv6: %s\n", s2);

	if (!rep.mapping_varies_known)
		printf("NAT mapping: unknown (fewer than two relays answered)\n");
	else if (rep.mapping_varies)
		printf("NAT mapping: varies by destination -- direct paths are "
		       "unlikely\n");
	else
		printf("NAT mapping: stable\n");

	printf("\nlatency by region:\n");
	for (size_t i = 0; i < rep.num_regions; i++) {
		const tc_netcheck_region *r = &rep.regions[i];
		const tc_derp_region *reg = tc_derpmap_find(m, r->region_id);
		const char *code = (reg != NULL) ? reg->region_code : "?";
		char v4[16] = "-", v6[16] = "-";
		if (r->rtt_v4_ms >= 0)
			snprintf(v4, sizeof v4, "%dms", r->rtt_v4_ms);
		if (r->rtt_v6_ms >= 0)
			snprintf(v6, sizeof v6, "%dms", r->rtt_v6_ms);
		printf("  %-5lld %-8s v4 %-8s v6 %-8s%s\n", (long long)r->region_id,
		       code, v4, v6,
		       (r->region_id == rep.preferred_region) ? "  <- preferred" : "");
	}
	if (rep.preferred_region == 0)
		printf("  (nothing answered)\n");

	free(m);
	return 0;
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

/* pick_region chooses a relay by STUN round trip.
 *
 * Phase 1.4 timed a DERP connection instead -- TCP, TLS and the relay's key
 * exchange -- and said at the time that it was the cheap version. It probed
 * four regions one after another, so a slow network cost four timeouts;
 * netcheck sends every probe at once and the whole thing costs one.
 *
 * The socket here is a throwaway. The mapped address a netcheck learns
 * belongs to the socket the probes went out on, and this one is closed
 * immediately, so only the latencies are kept. Phase 4.4 will run a netcheck
 * on the socket that carries the session, which is the only way the address
 * is worth anything.
 *
 * Falls back to the old DERP timing if UDP gets nowhere: a network that
 * blocks UDP still relays fine, and refusing to pick a relay because we could
 * not measure one would turn a working setup into no service at all.
 */
static const tc_derp_region *pick_region(const tc_derp_map *m, int timeout_ms,
                                         bool insecure)
{
	tc_udp u;
	if (tc_udp_open(&u, 0) == TC_OK) {
		tc_netcheck_opts o;
		memset(&o, 0, sizeof o);
		/* A ceiling, not a cost: the check ends as soon as every probe is
		 * answered, which on a working network is one round trip. */
		o.timeout_ms = (timeout_ms > 0 && timeout_ms < 3000) ? timeout_ms
		                                                     : 3000;

		tc_netcheck_report rep;
		int rc = tc_netcheck_run(&rep, m, &u, &o, NULL, NULL);
		tc_udp_close(&u);

		if (rc == TC_OK) {
			char line[200];
			if (tc_netcheck_describe(line, sizeof line, &rep, m) == TC_OK)
				vlogf("netcheck: %s", line);
			if (rep.preferred_region != 0) {
				const tc_derp_region *reg =
				    tc_derpmap_find(m, rep.preferred_region);
				if (reg != NULL)
					return reg;
			}
		}
	}

	vlogf("no STUN answer; falling back to timing relay connections");
	return tc_derpmap_pick_fastest(m, 4, timeout_ms, insecure);
}

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
		reg = pick_region(m, timeout_ms, insecure);
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

	/* Path discovery. Both NULL means relay-only, which is what everything
	 * did before Phase 4.4 and what it falls back to whenever a direct path
	 * has not been proven. */
	tc_udp *udp;
	tc_path *path;
	/* So the upgrade and the fallback each get logged once rather than on
	 * every packet. */
	bool was_direct;
} pump;

/* wg_out is how the WireGuard layer reaches the wire: everything it emits --
 * transport packets, handshakes, keepalives -- goes to the relay addressed to
 * the peer's node key. */
static int wg_out(void *vctx, const uint8_t *pkt, size_t len)
{
	pump *p = (pump *)vctx;

	/* The whole of the upgrade, from the data path's point of view: one
	 * question asked per packet, and a different address if the answer has
	 * changed. Nothing is renegotiated and no state moves, because the
	 * WireGuard session does not know or care which way its packets
	 * travelled. */
	if (p->path != NULL && p->udp != NULL) {
		tc_endpoint dst;
		if (tc_path_best(p->path, &dst, now_ms()) == TC_PATH_DIRECT) {
			if (tc_udp_send(p->udp, &dst, pkt, len) == TC_OK)
				return TC_OK;
			/* A send that failed outright -- no route, a dead interface --
			 * is not worth losing the packet over when the relay is sitting
			 * there working. */
		}
	}

	/* A failed relay write is packet loss, which both WireGuard and TCP above
	 * already handle by retrying. A write that *times out* is different: the
	 * frame is half-sent and the stream is no longer parseable, so the loop
	 * is told to rebuild the connection rather than carry on writing into
	 * it. */
	if (tc_derp_send(p->derp, p->server_key, pkt, len) == TC_ERR_TIMEOUT)
		p->relay_stalled = true;
	return TC_OK;
}

/* ---- path discovery ---------------------------------------------------- */

/* Where disco probes go: straight out of the UDP socket, addressed to a
 * candidate. */
static int path_udp_out(void *vctx, const tc_endpoint *dst,
                        const uint8_t *pkt, size_t len)
{
	pump *p = (pump *)vctx;
	if (p->udp == NULL)
		return TC_ERR_INVAL;
	return tc_udp_send(p->udp, dst, pkt, len);
}

/* And where CallMeMaybe goes: through the relay, which is the one path known
 * to work before any other has been proven. */
static int path_relay_out(void *vctx, const uint8_t *pkt, size_t len)
{
	pump *p = (pump *)vctx;
	if (p->derp == NULL)
		return TC_ERR_INVAL;
	return tc_derp_send(p->derp, p->server_key, pkt, len);
}

/* pump_log_path reports an upgrade or a fallback once, rather than on every
 * packet. It is the only outward sign any of this is happening. */
static void pump_log_path(pump *p)
{
	if (p->path == NULL)
		return;
	bool direct = tc_path_best(p->path, NULL, now_ms()) == TC_PATH_DIRECT;
	if (direct == p->was_direct)
		return;
	char line[160];
	if (tc_path_describe(line, sizeof line, p->path, now_ms()) == TC_OK)
		vlogf("path: %s", line);
	p->was_direct = direct;
}

/* pump_service_udp drains whatever has arrived on the UDP socket.
 *
 * Two kinds of thing share it. Disco belongs to the path layer; everything
 * else is tunnel traffic that came directly, and is fed to WireGuard exactly
 * as a relayed packet would be -- the session does not distinguish them.
 *
 * Non-blocking and bounded: this runs inside an event loop that has other
 * work, and a peer sending faster than we drain must not be able to hold the
 * loop here.
 */
static void pump_service_udp(pump *p, tc_tcp_mux *mux)
{
	if (p->udp == NULL || p->path == NULL)
		return;

	for (int i = 0; i < 32; i++) {
		tc_endpoint src;
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t n = 0;
		if (tc_udp_recv(p->udp, &src, buf, sizeof buf, &n, 0) != TC_OK)
			break;

		if (tc_path_input_disco(p->path, &src, buf, n, now_ms()) == TC_OK)
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_peer_input(p->peer, buf, n, inner, sizeof inner, &inner_len,
		                     now_ms()) != TC_OK)
			continue;

		/* Only a payload that actually decrypted counts as proof this path
		 * is alive. tc_wg_peer_input reports success for anything it
		 * declined to act on too -- replays, forgeries, packets for a
		 * keypair we no longer hold -- and treating those as liveness would
		 * let anyone who can guess the address keep a dead path trusted by
		 * spraying noise at it. */
		if (inner_len > 0) {
			tc_path_note_recv(p->path, &src, now_ms());
			if (mux != NULL)
				tc_tcp_mux_input(mux, inner, inner_len, now_ms());
		}
	}

	tc_path_tick(p->path, now_ms());
	pump_log_path(p);
}

/* pump_relay_disco takes a packet that arrived through the relay and gives it
 * to the path layer if that is what it is.
 *
 * Returns true when the packet has been dealt with. CallMeMaybe is the only
 * disco message that belongs on this channel, and path.c enforces that; the
 * job here is only to keep it out of WireGuard's input, where it would be
 * one more malformed packet to discard. */
static bool pump_relay_disco(pump *p, const uint8_t *buf, size_t len)
{
	if (p->path == NULL || !tc_disco_looks_like(buf, len))
		return false;
	(void)tc_path_input_relay(p->path, buf, len, now_ms());
	return true;
}

/* ---- bringing up path discovery ---------------------------------------- */

/* path_bring_up opens the UDP socket a direct path would use, works out what
 * addresses to offer the peer, and starts probing.
 *
 * Everything here is best-effort. A machine with no UDP, a network that
 * blocks it, a peer with no disco key: each means no direct path, and no
 * direct path means the relay, which is what was happening before any of this
 * existed. Nothing in this function can break a session.
 *
 * The netcheck runs on *this* socket rather than a throwaway one. The mapped
 * address a NAT hands out belongs to the socket that earned it, so an address
 * learned on any other socket is an address the peer cannot use.
 */
/* path_local_list works out what addresses to offer a peer: this machine's
 * own, plus whatever a netcheck on this very socket says the world sees.
 *
 * Computed once per socket rather than once per peer -- the answer is a
 * property of the socket, and a server with eight clients should not run
 * eight netchecks to learn the same thing eight times. */
static size_t path_local_list(tc_udp *udp, const tc_derp_map *map,
                              tc_endpoint *eps, size_t cap)
{
	size_t n = tc_udp_local_endpoints(udp, eps, cap);

	if (map != NULL) {
		tc_netcheck_opts o;
		memset(&o, 0, sizeof o);
		o.timeout_ms = 1500;
		o.max_regions = 2; /* enough to learn the mapping; not a survey */
		tc_netcheck_report rep;
		if (tc_netcheck_run(&rep, map, udp, &o, NULL, NULL) == TC_OK) {
			if (rep.global_v4.ip_len != 0 && n < cap)
				eps[n++] = rep.global_v4;
			if (rep.global_v6.ip_len != 0 && n < cap)
				eps[n++] = rep.global_v6;
			if (rep.mapping_varies_known && rep.mapping_varies)
				/* Worth saying once. The address we are about to advertise
				 * is the one the relay's STUN server sees, and a symmetric
				 * NAT gives every destination a different one -- so the
				 * probing that follows will almost certainly fail, and the
				 * relay is where this session is going to stay. */
				vlogf("this NAT maps by destination; a direct path is "
				      "unlikely");
		}
	}
	return n;
}

/* path_attach starts probing for one peer on an already-open socket. */
static bool path_attach(pump *ctx, tc_udp *udp, tc_path *path,
                        const uint8_t our_disco_priv[32],
                        const uint8_t our_disco_pub[32],
                        const uint8_t peer_disco_pub[32],
                        const tc_endpoint *eps, size_t n)
{
	if (tc_path_init(path, our_disco_priv, our_disco_pub, peer_disco_pub,
	                 path_udp_out, path_relay_out, ctx) != TC_OK)
		return false;
	tc_path_set_local(path, eps, n);
	ctx->udp = udp;
	ctx->path = path;
	(void)tc_path_start(path, now_ms());
	vlogf("probing for a direct path (%zu of our addresses offered)", n);
	return true;
}

/* path_bring_up is the single-peer case: open the socket, work out the
 * addresses, start probing.
 *
 * Everything here is best-effort. A machine with no UDP, a network that
 * blocks it, a peer with no disco key: each means no direct path, and no
 * direct path means the relay, which is what was happening before any of this
 * existed. Nothing in this function can break a session. */
static bool path_bring_up(pump *ctx, tc_udp *udp, tc_path *path,
                          const uint8_t our_disco_priv[32],
                          const uint8_t our_disco_pub[32],
                          const uint8_t peer_disco_pub[32],
                          const tc_derp_map *map)
{
	if (tc_udp_open(udp, 0) != TC_OK) {
		vlogf("no UDP socket; staying on the relay");
		return false;
	}
	tc_endpoint eps[TC_PATH_MAX_LOCAL];
	size_t n = path_local_list(udp, map, eps, TC_PATH_MAX_LOCAL);
	if (!path_attach(ctx, udp, path, our_disco_priv, our_disco_pub,
	                 peer_disco_pub, eps, n)) {
		tc_udp_close(udp);
		return false;
	}
	return true;
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
                    size_t reintroduce_len, bool *stall, uint64_t deadline,
                    pump *pm)
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
		if (pm != NULL)
			pump_service_udp(pm, mux);

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
		if (pm != NULL && pump_relay_disco(pm, buf, len))
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
/* dial_endpoint opens a TCP connection to a literal address, which is what an
 * exit node does with the destination its peer named.
 *
 * Nothing here decides *whether* to dial it. That judgement belongs to
 * whoever turned exit-node mode on, and it is a large judgement: a peer can
 * name this machine's own loopback, the rest of its LAN, or a cloud metadata
 * endpoint, and they will all work. */
static int dial_endpoint(const tc_endpoint *ep)
{
	if (ep == NULL || ep->port == 0)
		return -1;

	if (ep->ip_len == 4) {
		struct sockaddr_in a;
		memset(&a, 0, sizeof a);
		a.sin_family = (uint16_t)AF_INET;
		a.sin_port = htons(ep->port);
		memcpy(&a.sin_addr, ep->ip, 4);
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			return -1;
		if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0)
			return fd;
		(void)close(fd);
		return -1;
	}
	if (ep->ip_len != 16)
		return -1;

	struct sockaddr_in6 a;
	memset(&a, 0, sizeof a);
	a.sin6_family = (uint16_t)AF_INET6;
	a.sin6_port = htons(ep->port);
	memcpy(&a.sin6_addr, ep->ip, 16);
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0)
		return fd;
	(void)close(fd);
	return -1;
}

static int dial_localhost(uint16_t port)
{
	struct sockaddr_in v4;
	memset(&v4, 0, sizeof v4);
	v4.sin_family = (uint16_t)AF_INET;
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
	v6.sin6_family = (uint16_t)AF_INET6;
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

/* ---- serving many clients at once -------------------------------------- */

/* Each client is a separate WireGuard peer with its own session keys, its own
 * tunnel address and its own demultiplexer. Nothing is shared between them
 * except the relay connection and the proxy's pool of local sockets, which is
 * the point: one client cannot see another's traffic, because there is no
 * object through which it could.
 */
#ifndef TC_SERVE_MAX_CLIENTS
#define TC_SERVE_MAX_CLIENTS 8
#endif

/* A client that holds no session and no connections and has said nothing for
 * this long is dropped, so a peer that went away does not hold a slot for
 * ever. Longer than REJECT_AFTER_TIME, so a live-but-quiet client whose
 * session is mid-rekey is never mistaken for a dead one. */
#define TC_SERVE_CLIENT_IDLE_MS (5u * 60u * 1000u)

typedef struct {
	bool used;
	uint8_t key[TC_NODE_KEY_LEN];
	uint8_t disco[TC_DISCO_KEY_LEN]; /* from the meow; how disco is demuxed */
	tc_wg_peer peer;
	tc_tcp_mux *mux;
	pump ctx; /* per client: wg_out has to address this peer's node key */
	tc_path path;
	bool has_path;
	uint64_t last_seen_ms;
} serve_client;

typedef struct {
	serve_client c[TC_SERVE_MAX_CLIENTS];
	tc_derp_client *derp;
	tc_wg_identity me;
	uint8_t psk[TC_PSK_LEN];
	const tc_portset *ports;
	tc_proxy *proxy;
	uint64_t refused;
	uint64_t served;

	/* One UDP socket for every client. A socket is a NAT mapping, and one
	 * mapping shared by all peers is both fewer holes to keep open and the
	 * only way the address we advertise means the same thing to each of
	 * them. */
	/* Set by `serve exit-node`. See tc_tcp_mux_set_exit_node for what it
	 * means to turn this on. */
	bool exit_node;

	/* Which clients may connect. Inactive means all of them, which is the
	 * default and what every version before this did. */
	tc_allowlist allow;
	uint64_t refused_by_allow;

	tc_udp udp;
	bool have_udp;
	uint8_t disco_priv[32], disco_pub[32];
	tc_endpoint local[TC_PATH_MAX_LOCAL];
	size_t num_local;
} serve_state;

static size_t client_count(const serve_state *st)
{
	size_t n = 0;
	for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++)
		if (st->c[i].used)
			n++;
	return n;
}

static serve_client *find_client(serve_state *st, const uint8_t key[32])
{
	for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
		if (st->c[i].used && memcmp(st->c[i].key, key, 32) == 0)
			return &st->c[i];
	}
	return NULL;
}

/* drop_client releases everything one client owns.
 *
 * The proxy points at connections this mux owns, so it has to let go before
 * the mux frees them -- the same ordering rule as the main loop, and the same
 * use-after-free if it is got wrong. */
static void drop_client(serve_state *st, serve_client *sc)
{
	if (st->proxy != NULL && sc->mux != NULL) {
		for (size_t i = tc_tcp_mux_count(sc->mux); i-- > 0;)
			tc_proxy_forget(st->proxy, tc_tcp_mux_at(sc->mux, i));
	}
	tc_tcp_mux_free(sc->mux);
	tc_wg_peer_clear(&sc->peer);
	memset(sc, 0, sizeof *sc);
}

static serve_client *add_client(serve_state *st, const uint8_t key[32],
                                const uint8_t disco[32], uint64_t now)
{
	serve_client *sc = NULL;
	for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
		if (!st->c[i].used) {
			sc = &st->c[i];
			break;
		}
	}
	if (sc == NULL) {
		/* Full. The meow goes unanswered, so the client retries and then
		 * gives up -- which is the honest answer, and better than evicting
		 * someone who is mid-transfer to make room. */
		st->refused++;
		return NULL;
	}

	memset(sc, 0, sizeof *sc);
	memcpy(sc->key, key, 32);
	memcpy(sc->disco, disco, 32);
	sc->ctx.derp = st->derp;
	memcpy(sc->ctx.server_key, key, 32);
	if (tc_wg_peer_init(&sc->peer, &st->me, key, st->psk, wg_out, &sc->ctx) !=
	    TC_OK)
		return NULL;
	sc->ctx.peer = &sc->peer;

	uint8_t our_ip[TC_TUNNEL_ADDR_LEN], their_ip[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(our_ip, st->me.public_key);
	tc_tunnel_addr_for_key(their_ip, key);

	sc->mux = tc_tcp_mux_new(our_ip, their_ip, tcp_out, &sc->ctx);
	if (sc->mux == NULL) {
		tc_wg_peer_clear(&sc->peer);
		memset(sc, 0, sizeof *sc);
		return NULL;
	}
	tc_tcp_mux_set_accept_filter(sc->mux, port_is_served,
	                             (void *)(uintptr_t)st->ports);
	tc_tcp_mux_set_exit_node(sc->mux, st->exit_node);

	if (st->have_udp)
		sc->has_path =
		    path_attach(&sc->ctx, &st->udp, &sc->path, st->disco_priv,
		                st->disco_pub, sc->disco, st->local, st->num_local);

	sc->used = true;
	sc->last_seen_ms = now;
	st->served++;
	return sc;
}

/* handle_meow answers an introduction, adding the client if it is new. */
static void handle_meow(serve_state *st, const uint8_t src[32],
                        const uint8_t *buf, size_t len, uint64_t now)
{
	uint8_t node[32], disco[32];
	if (tc_meow_parse_ping(buf, len, node, disco) != TC_OK)
		return;
	/* The relay's idea of the sender must agree with the packet's claim, or
	 * anyone could introduce anyone. */
	if (memcmp(node, src, 32) != 0)
		return;

	/* Checked before anything is allocated or answered. A client that is not
	 * allowed gets silence rather than a refusal: an explicit "no" would
	 * confirm to an unauthorised caller that they had found a real server,
	 * which is the one thing they did not already know. */
	if (!tc_allow_permits(&st->allow, node)) {
		st->refused_by_allow++;
		vlogf("refusing client %02x%02x%02x%02x: not in --allow", node[0],
		      node[1], node[2], node[3]);
		return;
	}

	serve_client *sc = find_client(st, node);
	if (sc == NULL) {
		sc = add_client(st, node, disco, now);
		if (sc == NULL) {
			vlogf("refusing a new client: %d already connected",
			      TC_SERVE_MAX_CLIENTS);
			return;
		}
		vlogf("client %02x%02x%02x%02x introduced itself (%zu connected)",
		      node[0], node[1], node[2], node[3], client_count(st));
	}
	sc->last_seen_ms = now;

	/* Acknowledge every ping: the client resends until it hears back, and a
	 * duplicate acknowledgement costs nothing. */
	uint8_t ack[TC_MEOW_MEOWED_LEN];
	size_t ack_len = 0;
	tc_meow_encode_meowed(ack, sizeof ack, &ack_len);
	(void)tc_derp_send(st->derp, node, ack, ack_len);
}

/* serve_service_udp drains the shared socket and gives each datagram to the
 * client it belongs to.
 *
 * Two different keys, because the two kinds of packet identify themselves
 * differently. Disco names its sender in the clear, so a disco packet is
 * matched on the peer's disco key -- and then opened, which is what proves
 * the claim. Tunnel traffic names nothing, so it is matched on the address it
 * came from, which works because we only ever send directly to a path that
 * has been proven, and therefore only ever receive on one.
 *
 * Not tried against every client in turn: feeding one client's packets to
 * another's WireGuard peer would be eight chances to get a replay counter or
 * a handshake attributed to the wrong session, in exchange for nothing.
 */
static void serve_service_udp(serve_state *st)
{
	if (!st->have_udp)
		return;

	for (int i = 0; i < 64; i++) {
		tc_endpoint src;
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t n = 0;
		if (tc_udp_recv(&st->udp, &src, buf, sizeof buf, &n, 0) != TC_OK)
			break;

		uint8_t claimed[32];
		if (tc_disco_source(buf, n, claimed) == TC_OK) {
			for (size_t k = 0; k < TC_SERVE_MAX_CLIENTS; k++) {
				serve_client *sc = &st->c[k];
				if (!sc->used || !sc->has_path)
					continue;
				if (memcmp(sc->disco, claimed, 32) != 0)
					continue;
				(void)tc_path_input_disco(&sc->path, &src, buf, n, now_ms());
				break;
			}
			continue;
		}

		for (size_t k = 0; k < TC_SERVE_MAX_CLIENTS; k++) {
			serve_client *sc = &st->c[k];
			if (!sc->used || !sc->has_path)
				continue;
			/* Any address we associate with this client, not only the
			 * one we happen to be sending to. The two sides decide
			 * independently and a peer routinely proves the path first, so
			 * requiring agreement here would drop exactly the traffic that
			 * shows the upgrade worked. */
			if (!tc_path_knows(&sc->path, &src))
				continue;

			static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
			size_t inner_len = 0;
			if (tc_wg_peer_input(&sc->peer, buf, n, inner, sizeof inner,
			                     &inner_len, now_ms()) != TC_OK)
				break;
			if (inner_len > 0) {
				tc_path_note_recv(&sc->path, &src, now_ms());
				sc->last_seen_ms = now_ms();
				tc_tcp_mux_input(sc->mux, inner, inner_len, now_ms());
			}
			break;
		}
	}

	for (size_t k = 0; k < TC_SERVE_MAX_CLIENTS; k++) {
		serve_client *sc = &st->c[k];
		if (sc->used && sc->has_path) {
			(void)tc_path_tick(&sc->path, now_ms());
			pump_log_path(&sc->ctx);
		}
	}
}

/* expire_idle drops clients that are gone: no keys, no connections, and
 * silent for long enough that a rekey cannot explain it. */
static void expire_idle(serve_state *st, uint64_t now)
{
	for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
		serve_client *sc = &st->c[i];
		if (!sc->used)
			continue;
		if (tc_wg_peer_has_keys(&sc->peer, now) ||
		    tc_tcp_mux_count(sc->mux) > 0) {
			sc->last_seen_ms = now;
			continue;
		}
		if (now - sc->last_seen_ms < TC_SERVE_CLIENT_IDLE_MS)
			continue;
		vlogf("dropping an idle client");
		drop_client(st, sc);
	}
}

/* run_serve_multi is the event loop for `serve <ports>`.
 *
 * The ordering inside it is load-bearing. tc_tcp_mux_reap frees connections
 * the proxy may still hold pointers to, so it runs only after the proxy has
 * had a chance to notice they closed and let go. Reaping the muxes first --
 * the obvious place, at the top -- is a use-after-free that only appears when
 * a peer hangs up at the wrong moment. */
static int run_serve_multi(serve_state *st, uint64_t deadline)
{
	tc_derp_client *derp = st->derp;
	tc_derp_set_read_timeout(derp, 20);

	while (now_ms() < deadline) {
		uint64_t t = now_ms();
		serve_service_udp(st);

		/* A relay write that timed out leaves a half-written frame, so the
		 * connection has to be rebuilt before anything else uses it. Any
		 * client's send could have been the one that hit it. */
		bool stalled = false;
		for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
			if (st->c[i].used && st->c[i].ctx.relay_stalled) {
				st->c[i].ctx.relay_stalled = false;
				stalled = true;
			}
		}
		if (stalled) {
			vlogf("a relay write stalled; rebuilding the connection");
			if (relay_recover(derp, NULL, NULL, 0, deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: lost the relay\n");
				return 1;
			}
		}

		for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
			serve_client *sc = &st->c[i];
			if (!sc->used)
				continue;
			tc_wg_peer_tick(&sc->peer, t);
			tc_tcp_mux_tick(sc->mux, t);

			tc_tcp_conn *c;
			while ((c = tc_tcp_mux_accept(sc->mux)) != NULL) {
				uint16_t port = tc_tcp_local_port(c);

				/* Where the client addressed the connection decides where it
				 * goes. Our own tunnel address means a local service; any
				 * other address means the client asked us to forward, which
				 * only happens at all because exit-node mode is on. */
				uint8_t want[TC_IPV6_ADDR_LEN];
				tc_tcp_local_addr(c, want);
				uint8_t ours[TC_TUNNEL_ADDR_LEN];
				tc_tunnel_addr_for_key(ours, st->me.public_key);

				int fd;
				if (memcmp(want, ours, TC_IPV6_ADDR_LEN) == 0) {
					fd = dial_localhost(port);
				} else {
					tc_endpoint dst;
					memset(&dst, 0, sizeof dst);
					memcpy(dst.ip, want, 16);
					dst.ip_len = 16;
					dst.port = port;
					/* An IPv4 destination arrived wrapped in the NAT64
					 * prefix, because the tunnel carries nothing else. */
					tc_endpoint v4;
					if (tc_nat64_unwrap(&v4, &dst) == TC_OK)
						dst = v4;
					char where[80];
					(void)tc_endpoint_format(where, sizeof where, &dst);
					fd = dial_endpoint(&dst);
					vlogf("exit node: %s %s", fd < 0 ? "could not reach" :
					                                   "forwarding to",
					      where);
				}
				if (fd < 0) {
					/* Nothing is listening there. Resetting says so at
					 * once rather than leaving the client to time out. */
					vlogf("no service on port %u; refusing", (unsigned)port);
					tc_tcp_mux_close(sc->mux, c, t);
					continue;
				}
				if (tc_proxy_add(st->proxy, c, fd) != TC_OK) {
					vlogf("too many connections; refusing port %u",
					      (unsigned)port);
					(void)close(fd);
					tc_tcp_mux_close(sc->mux, c, t);
					continue;
				}
				vlogf("accepted a connection to port %u", (unsigned)port);
			}
		}

		bool progress = tc_proxy_pump(st->proxy, t) > 0;
		tc_proxy_reap(st->proxy, t);
		/* Only now, once the proxy has dropped anything that finished. */
		for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
			if (st->c[i].used)
				tc_tcp_mux_reap(st->c[i].mux);
		}
		expire_idle(st, t);

		if (!progress && !tc_derp_has_pending(derp)) {
			struct pollfd pfds[1 + TC_TCP_MAX_CONNS];
			nfds_t nfds = 0;
			int dfd = tc_derp_fd(derp);
			if (dfd >= 0) {
				pfds[nfds].fd = dfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
			for (size_t i = 0;
			     i < TC_TCP_MAX_CONNS && nfds < 1 + TC_TCP_MAX_CONNS; i++) {
				int pfd = -1;
				bool rd = false, wr = false;
				if (!tc_proxy_interest(st->proxy, i, &pfd, &rd, &wr))
					continue;
				if (!rd && !wr)
					continue;
				pfds[nfds].fd = pfd;
				pfds[nfds].events =
				    (short)((rd ? POLLIN : 0) | (wr ? POLLOUT : 0));
				pfds[nfds].revents = 0;
				nfds++;
			}

			int wait_ms = 20;
			uint64_t dl = UINT64_MAX;
			for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
				if (!st->c[i].used)
					continue;
				uint64_t a = tc_tcp_mux_next_deadline(st->c[i].mux);
				uint64_t b = tc_wg_peer_next_deadline(&st->c[i].peer);
				if (a < dl)
					dl = a;
				if (b < dl)
					dl = b;
			}
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
				if (relay_recover(derp, NULL, NULL, 0, deadline) != TC_OK) {
					fprintf(stderr, "tailcat-c: lost the relay\n");
					return 1;
				}
			}
			continue;
		}
		if (rc == TC_ERR_CLOSED) {
			if (relay_recover(derp, NULL, NULL, 0, deadline) != TC_OK) {
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
		if (len == 0)
			continue;

		if (tc_meow_is_packet(buf, len)) {
			handle_meow(st, src, buf, len, now_ms());
			continue;
		}

		/* Everything else is WireGuard, and belongs to whichever client the
		 * relay says it came from. A packet from a node that has not
		 * introduced itself is dropped: the meow is how a server learns who
		 * a client is, and answering an unknown one would be inventing a
		 * peer from a packet anybody could send. */
		serve_client *sc = find_client(st, src);
		if (sc == NULL)
			continue;
		sc->last_seen_ms = now_ms();

		if (sc->has_path && pump_relay_disco(&sc->ctx, buf, len))
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_peer_input(&sc->peer, buf, len, inner, sizeof inner,
		                     &inner_len, now_ms()) != TC_OK)
			continue;
		if (inner_len == 0)
			continue;
		tc_tcp_mux_input(sc->mux, inner, inner_len, now_ms());
	}
	return 0;
}

/* ---- saved identities --------------------------------------------------- */

/* config_dir mirrors Go's os.UserConfigDir, because that is where upstream
 * puts its keys and the two implementations have to look in the same place
 * for a key to be shared between them. */
static const char *config_dir(void)
{
	static char buf[768];
	const char *v;

	if ((v = getenv("XDG_CONFIG_HOME")) != NULL && v[0] == '/') {
		(void)snprintf(buf, sizeof buf, "%s", v);
		return buf;
	}
	/* Windows, where an APE may well be running. */
	if ((v = getenv("AppData")) != NULL && v[0] != '\0') {
		(void)snprintf(buf, sizeof buf, "%s", v);
		return buf;
	}
	if ((v = getenv("HOME")) == NULL || v[0] == '\0')
		return NULL;
#ifdef __APPLE__
	(void)snprintf(buf, sizeof buf, "%s/Library/Application Support", v);
#else
	(void)snprintf(buf, sizeof buf, "%s/.config", v);
#endif
	return buf;
}

/* key_is_path distinguishes a name from a path exactly as upstream does: by
 * whether it contains a separator. */
static bool key_is_path(const char *name)
{
	return strchr(name, '/') != NULL || strchr(name, '\\') != NULL;
}

static int key_path(char *out, size_t cap, const char *name)
{
	if (key_is_path(name)) {
		if ((size_t)snprintf(out, cap, "%s", name) >= cap)
			return TC_ERR_NOSPACE;
		return TC_OK;
	}
	const char *cfg = config_dir();
	if (cfg == NULL) {
		fprintf(stderr, "tailcat-c: no config directory; set HOME or give "
		                "a path\n");
		return TC_ERR_INVAL;
	}
	int n = snprintf(out, cap, "%s/tailcat/keys/%s.private.json", cfg, name);
	if (n < 0 || (size_t)n >= cap)
		return TC_ERR_NOSPACE;
	return TC_OK;
}

/* mkdir_p creates a directory and its parents, 0700 -- these hold secrets. */
static int mkdir_p(const char *path)
{
	char buf[1024];
	if ((size_t)snprintf(buf, sizeof buf, "%s", path) >= sizeof buf)
		return TC_ERR_NOSPACE;
	for (char *p = buf + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		(void)mkdir(buf, 0700);
		*p = '/';
	}
	if (mkdir(buf, 0700) != 0 && errno != EEXIST)
		return TC_ERR_INVAL;
	return TC_OK;
}

static int read_file(const char *path, char *out, size_t cap, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (f == NULL)
		return TC_ERR_INVAL;
	size_t n = fread(out, 1, cap - 1, f);
	int bad = ferror(f);
	(void)fclose(f);
	if (bad)
		return TC_ERR_INVAL;
	out[n] = '\0';
	*len = n;
	return TC_OK;
}

/* load_key reads a saved identity.
 *
 * `spec` is "new" for an ephemeral key, a path, or a name. An empty spec means
 * the default for the mode, which is loaded if it exists and otherwise means
 * ephemeral -- so a first run works without any setup, and a later `genkey
 * --key default` changes nothing about how the command is invoked. */
static int load_key(tc_keyfile *k, const char *spec, bool client, bool *found)
{
	*found = false;
	if (spec != NULL && strcmp(spec, "new") == 0)
		return TC_OK;

	char path[1024];
	const char *name = (spec != NULL && spec[0] != '\0')
	                       ? spec
	                       : (client ? "client-default" : "default");
	if (key_path(path, sizeof path, name) != TC_OK)
		return TC_ERR_INVAL;

	static char buf[8192];
	size_t len = 0;
	if (read_file(path, buf, sizeof buf, &len) != TC_OK) {
		if (spec != NULL && spec[0] != '\0') {
			/* An explicitly named key that is missing is an error; the
			 * implicit default simply not existing is not. */
			fprintf(stderr, "tailcat-c: cannot read %s\n", path);
			return TC_ERR_INVAL;
		}
		return TC_OK;
	}
	if (tc_keyfile_parse(k, buf, len) != TC_OK) {
		fprintf(stderr, "tailcat-c: %s: %s\n", path,
		        tc_keyfile_error_string());
		return TC_ERR_INVAL;
	}
	vlogf("using the saved key %s", path);
	*found = true;
	return TC_OK;
}

static int cmd_printpub(const char *key_spec)
{
	static tc_keyfile k;
	bool found = false;
	if (load_key(&k, key_spec, true, &found) != TC_OK)
		return 1;
	if (!found) {
		fprintf(stderr, "tailcat-c: no client key saved; make one with "
		                "`genkey --client --key client-default`\n");
		return 1;
	}
	char s[128];
	if (tc_key_format_hex(s, sizeof s, "nodekey", k.pub.server_public) !=
	    TC_OK)
		return 1;
	printf("%s\n", s);
	return 0;
}

static int list_keys(void)
{
	const char *cfg = config_dir();
	if (cfg == NULL)
		return 1;
	char dir[900];
	(void)snprintf(dir, sizeof dir, "%s/tailcat/keys", cfg);

	DIR *d = opendir(dir);
	if (d == NULL) {
		fprintf(stderr, "# no keys in %s\n", dir);
		return 0;
	}
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		const char *suffix = ".private.json";
		size_t nlen = strlen(e->d_name);
		size_t slen = strlen(suffix);
		if (nlen <= slen || strcmp(e->d_name + nlen - slen, suffix) != 0)
			continue;
		printf("%.*s\n", (int)(nlen - slen), e->d_name);
	}
	(void)closedir(d);
	return 0;
}

static int cmd_genkey(const char *key_spec, bool client, bool force,
                      bool delete_it, bool list, const char *region,
                      bool psk, bool insecure, const char *derpmap_url)
{
	if (list)
		return list_keys();

	if (key_spec == NULL || key_spec[0] == '\0') {
		fprintf(stderr, "tailcat-c: genkey needs --key <name-or-path>\n");
		return 2;
	}

	char path[1024];
	if (key_path(path, sizeof path, key_spec) != TC_OK)
		return 1;

	if (delete_it) {
		if (key_is_path(key_spec)) {
			fprintf(stderr, "tailcat-c: --delete takes a name, not a path\n");
			return 2;
		}
		if (remove(path) != 0) {
			fprintf(stderr, "tailcat-c: cannot delete %s: %s\n", path,
			        strerror(errno));
			return 1;
		}
		fprintf(stderr, "# deleted %s\n", path);
		return 0;
	}

	/* Refusing to overwrite is the whole safety of this command: a key file
	 * is the only copy of an identity, and a server's address is derived
	 * from it. Silently replacing one would strand every client that has the
	 * old address. */
	if (!force && access(path, F_OK) == 0) {
		fprintf(stderr, "tailcat-c: %s already exists; --force to replace "
		                "it (every client with the old address loses "
		                "access)\n",
		        path);
		return 1;
	}

	int64_t region_id = 0;
	if (region != NULL && strcmp(region, "auto") != 0 && !client) {
		if (strcmp(region, "list") == 0) {
			static tc_derp_map m;
			if (tc_derpmap_fetch(&m, derpmap_url, insecure, 15000) != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n",
				        tc_derpmap_error_string());
				return 1;
			}
			for (size_t i = 0; i < m.num_regions; i++)
				printf("%4lld %-6s %s\n", (long long)m.regions[i].region_id,
				       m.regions[i].region_code, m.regions[i].region_name);
			return 0;
		}
		char *end = NULL;
		long v = strtol(region, &end, 10);
		if (end != NULL && *end == '\0' && v > 0 && v < 65536) {
			region_id = v;
		} else {
			/* A code or a substring: look it up rather than guess. */
			static tc_derp_map m;
			if (tc_derpmap_fetch(&m, derpmap_url, insecure, 15000) != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n",
				        tc_derpmap_error_string());
				return 1;
			}
			for (size_t i = 0; i < m.num_regions && region_id == 0; i++) {
				if (strstr(m.regions[i].region_code, region) != NULL ||
				    strstr(m.regions[i].region_name, region) != NULL)
					region_id = m.regions[i].region_id;
			}
			if (region_id == 0) {
				fprintf(stderr, "tailcat-c: no region matching \"%s\"; "
				                "try --region list\n",
				        region);
				return 1;
			}
		}
	}

	static tc_keyfile k;
	if (tc_keyfile_generate(&k, psk, region_id) != TC_OK) {
		fprintf(stderr, "tailcat-c: %s\n", tc_keyfile_error_string());
		return 1;
	}

	static char out[4096];
	size_t out_len = 0;
	if (tc_keyfile_format(out, sizeof out, &out_len, &k) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not format the key\n");
		return 1;
	}

	if (!key_is_path(key_spec)) {
		char dir[900];
		const char *cfg = config_dir();
		(void)snprintf(dir, sizeof dir, "%s/tailcat/keys", cfg);
		if (mkdir_p(dir) != TC_OK) {
			fprintf(stderr, "tailcat-c: cannot create %s\n", dir);
			return 1;
		}
	}

	/* 0600 from the moment it exists, rather than created and then chmod'd:
	 * the whole file is secret, including the pre-shared key that lives
	 * under the misleading name "Public". */
	int fd = open(path, (int)(O_WRONLY | O_CREAT | O_TRUNC), 0600);
	if (fd < 0) {
		fprintf(stderr, "tailcat-c: cannot write %s: %s\n", path,
		        strerror(errno));
		return 1;
	}
	bool ok = write_all(fd, (const uint8_t *)out, out_len);
	(void)close(fd);
	if (!ok) {
		fprintf(stderr, "tailcat-c: could not write %s\n", path);
		return 1;
	}
	fprintf(stderr, "# wrote %s\n", path);

	if (client) {
		/* A client key has no address; its public key is what a server's
		 * allow list would name. */
		char s[128];
		(void)tc_key_format_hex(s, sizeof s, "nodekey", k.pub.server_public);
		printf("%s\n", s);
		return 0;
	}

	char addr[TC_ADDR_STR_MAX];
	if (tc_addr_encode(addr, sizeof addr, &k.pub, NULL) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build the address\n");
		return 1;
	}
	printf("%s\n", addr);
	return 0;
}

/* ---- the client side of a tunnel --------------------------------------- */

/* Three commands dial a tailcat server -- pipe, forward and socks -- and the
 * bring-up is identical for all of them: resolve the address, connect to the
 * relay, introduce ourselves, complete the handshake, and open a
 * demultiplexer. It lives here once so that a change to any step (a rekey
 * rule, a reconnection, an extra round trip) reaches all three. */
typedef struct {
	tc_conn_info ci;
	tc_wg_identity me;
	tc_derp_client derp;
	tc_wg_peer peer;
	pump ctx;
	tc_tcp_mux *mux;
	tc_udp udp;
	tc_path path;
	bool have_udp;
	/* Kept so the relay can be re-introduced to us after a reconnection: the
	 * relay forgets who is talking to whom, the tunnel does not. */
	uint8_t ping[TC_MEOW_PING_LEN];
	size_t ping_len;
	bool up;
} tc_client;

static void client_down(tc_client *cl)
{
	if (cl == NULL)
		return;
	tc_tcp_mux_free(cl->mux);
	cl->mux = NULL;
	if (cl->up)
		log_wg_summary(&cl->peer);
	tc_wg_peer_clear(&cl->peer);
	tc_derp_close(&cl->derp);
	if (cl->have_udp) {
		tc_udp_close(&cl->udp);
		cl->have_udp = false;
	}
	tc_memzero_explicit(&cl->path, sizeof cl->path);
	tc_memzero_explicit(&cl->me, sizeof cl->me);
}

/* client_up brings the tunnel all the way to ready, or reports why not. */
static int client_up(tc_client *cl, const char *addr_str, bool insecure,
                     const char *derpmap_url, const char *key_spec,
                     uint64_t deadline)
{
	memset(cl, 0, sizeof *cl);

	int rc = tc_addr_parse(&cl->ci, addr_str, strlen(addr_str));
	if (rc != TC_OK) {
		fprintf(stderr, "tailcat-c: bad address: %s\n", tc_strerror(rc));
		return 1;
	}
	/* A short address names its relay by region number; this fetches the map
	 * and turns that into something dialable. */
	if (ensure_relay(&cl->ci, derpmap_url, insecure, 15000) != TC_OK)
		return 1;
	const tc_derp_node *node = &cl->ci.regions[0].nodes[0];

	/* A saved client identity if there is one, so a server with an allow
	 * list sees the same public key every time. Otherwise ephemeral, which
	 * is the right default for a client: nothing depends on its address. */
	static tc_keyfile saved;
	bool have_saved = false;
	if (load_key(&saved, key_spec, true, &have_saved) != TC_OK)
		return 1;

	uint8_t disco_pub[32], disco_priv[32];
	if (have_saved) {
		if (tc_wg_identity_from_private(&cl->me, saved.private_key) != TC_OK) {
			fprintf(stderr, "tailcat-c: the saved key is not usable\n");
			return 1;
		}
	} else if (tc_wg_identity_generate(&cl->me) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not generate keys\n");
		return 1;
	}
	if (tc_disco_key_for_node(disco_priv, disco_pub, cl->me.private_key) !=
	    TC_OK) {
		fprintf(stderr, "tailcat-c: could not derive the disco key\n");
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
	if (tc_derp_connect(&cl->derp, &opts, cl->me.private_key,
	                    cl->me.public_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: relay: %s\n", tc_derp_error_string());
		return 1;
	}
	tc_derp_set_read_timeout(&cl->derp, 200);
	vlogf("relay TLS: %s", tc_tls_last_version());

	/* ---- meow: ask the server to add us as a peer ---------------------- */

	tc_meow_encode_ping(cl->ping, sizeof cl->ping, &cl->ping_len,
	                    cl->me.public_key, disco_pub);

	bool meowed = false;
	uint64_t next_send = 0;
	while (!meowed && now_ms() < deadline) {
		if (now_ms() >= next_send) {
			/* DERP drops packets for a key that is not connected yet, so
			 * resend rather than bet everything on the first one. */
			if (tc_derp_send(&cl->derp, cl->ci.server_public, cl->ping,
			                 cl->ping_len) != TC_OK) {
				fprintf(stderr, "tailcat-c: relay send failed\n");
				goto fail;
			}
			next_send = now_ms() + 1000;
		}
		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&cl->derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			goto fail;
		}
		if (memcmp(src, cl->ci.server_public, 32) == 0 &&
		    tc_meow_is_meowed(buf, len))
			meowed = true;
	}
	if (!meowed) {
		fprintf(stderr, "tailcat-c: the server never acknowledged us\n");
		goto fail;
	}
	vlogf("meowed: the server has added us as a peer");

	/* ---- WireGuard ----------------------------------------------------- */

	cl->ctx.derp = &cl->derp;
	memcpy(cl->ctx.server_key, cl->ci.server_public, 32);
	if (tc_wg_peer_init(&cl->peer, &cl->me, cl->ci.server_public,
	                    cl->ci.has_preshared_key ? cl->ci.preshared_key : NULL,
	                    wg_out, &cl->ctx) != TC_OK) {
		fprintf(stderr, "tailcat-c: handshake setup failed\n");
		goto fail;
	}
	cl->ctx.peer = &cl->peer;

	if (tc_wg_peer_start_handshake(&cl->peer, now_ms()) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build the handshake\n");
		goto fail;
	}

	/* The peer owns the retry schedule from here; this loop only feeds it
	 * packets and the clock. */
	while (!tc_wg_peer_is_up(&cl->peer, now_ms()) && now_ms() < deadline) {
		tc_wg_peer_tick(&cl->peer, now_ms());

		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		rc = tc_derp_recv(&cl->derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT)
			continue;
		if (rc != TC_OK) {
			fprintf(stderr, "tailcat-c: relay: %s\n", tc_strerror(rc));
			goto fail;
		}
		if (memcmp(src, cl->ci.server_public, 32) != 0)
			continue;
		size_t ignored = 0;
		static uint8_t scratch[TC_DERP_MAX_PACKET_SIZE];
		(void)tc_wg_peer_input(&cl->peer, buf, len, scratch, sizeof scratch,
		                       &ignored, now_ms());
	}
	if (!tc_wg_peer_is_up(&cl->peer, now_ms())) {
		fprintf(stderr, "tailcat-c: no handshake response from the server\n");
		goto fail;
	}
	vlogf("tunnel up");

	/* The relay carries the session from here whatever happens next; this
	 * only looks for something quicker. It needs the peer's disco key, which
	 * a self-contained address carries and a short one does not always. */
	if (cl->ci.has_disco_public) {
		/* A one-region map holding the relay we are already talking to. Its
		 * STUN server is the one whose answer matters: the mapped address we
		 * advertise should come from the same direction our traffic does. */
		static tc_derp_map one;
		memset(&one, 0, sizeof one);
		if (cl->ci.num_regions > 0) {
			one.regions[0] = cl->ci.regions[0];
			one.num_regions = 1;
		}
		cl->have_udp = path_bring_up(&cl->ctx, &cl->udp, &cl->path, disco_priv,
		                             disco_pub, cl->ci.server_disco_public,
		                             one.num_regions > 0 ? &one : NULL);
	}
	else
		vlogf("the address carries no disco key; staying on the relay");
	tc_memzero_explicit(disco_priv, sizeof disco_priv);

	uint8_t our_ip[TC_TUNNEL_ADDR_LEN], their_ip[TC_TUNNEL_ADDR_LEN];
	tc_tunnel_addr_for_key(our_ip, cl->me.public_key);
	tc_tunnel_addr_for_key(their_ip, cl->ci.server_public);

	cl->mux = tc_tcp_mux_new(our_ip, their_ip, tcp_out, &cl->ctx);
	if (cl->mux == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto fail;
	}
	tc_derp_set_write_timeout(&cl->derp, 15000);
	cl->up = true;
	return TC_OK;

fail:
	client_down(cl);
	return 1;
}

static int cmd_pipe(const char *addr_str, uint16_t port, bool insecure,
                    unsigned timeout_s, const char *derpmap_url,
                    const char *key_spec)
{
	static tc_client cl;
	uint64_t deadline = now_ms() + (uint64_t)timeout_s * 1000u;

	if (client_up(&cl, addr_str, insecure, derpmap_url, key_spec, deadline) != TC_OK)
		return 1;

	tc_tcp_conn *tcp = NULL;
	if (tc_tcp_mux_connect(cl.mux, port, now_ms(), &tcp) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not start the connection\n");
		client_down(&cl);
		return 1;
	}
	vlogf("connecting to port %u from %u", (unsigned)port,
	      (unsigned)tc_tcp_local_port(tcp));

	int status = run_pipe(&cl.derp, &cl.peer, cl.mux, tcp,
	                      cl.ci.server_public, cl.ping, cl.ping_len,
	                      &cl.ctx.relay_stalled, deadline, &cl.ctx);

	if (status != 0 && now_ms() >= deadline)
		fprintf(stderr, "tailcat-c: timed out after %u seconds\n", timeout_s);

	client_down(&cl);
	return status;
}

/* ---- forward and socks ------------------------------------------------- */

/* Both commands listen locally and dial through the tunnel, so they share a
 * loop: accept on a set of local sockets, open a tunnel connection, and hand
 * the pair to the proxy. The only difference is how the remote port is
 * decided -- fixed per listener for `forward`, negotiated per connection for
 * `socks` -- which is why the SOCKS handshake is the one thing below that
 * forward does not use. */

#ifndef TC_MAX_LISTENERS
#define TC_MAX_LISTENERS 16
#endif

typedef struct {
	int fd;
	uint16_t local_port;  /* as bound, so an OS-chosen port is reported */
	uint16_t remote_port; /* 0 for socks: each connection negotiates its own */
	/* Where the traffic goes once through the tunnel. ip_len 0 is the
	 * server itself; anything else asks it to act as an exit node. Already
	 * wrapped for the tunnel, so the dial site needs no special case. */
	tc_endpoint dst;
} local_listener;

/* bind_local opens a listening socket. bind_addr is a literal address --
 * "127.0.0.1" by default, "0.0.0.0" to accept from the network, which is a
 * decision the user has to make explicitly. */
static int bind_local(const char *bind_addr, uint16_t port, uint16_t *bound)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = (uint16_t)AF_INET;
	a.sin_port = htons(port);
	if (inet_pton(AF_INET, bind_addr, &a.sin_addr) != 1) {
		fprintf(stderr, "tailcat-c: \"%s\" is not an IPv4 address\n",
		        bind_addr);
		return -1;
	}

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	int on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 ||
	    listen(fd, 16) != 0) {
		fprintf(stderr, "tailcat-c: cannot listen on %s:%u\n", bind_addr,
		        (unsigned)port);
		(void)close(fd);
		return -1;
	}

	/* Read the port back rather than echoing what was asked for: with 0 the
	 * kernel chose it, and that is the number the user needs printed. */
	struct sockaddr_in got;
	socklen_t glen = sizeof got;
	if (bound != NULL) {
		*bound = port;
		if (getsockname(fd, (struct sockaddr *)&got, &glen) == 0)
			*bound = ntohs(got.sin_port);
	}

	int fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		(void)fcntl(fd, F_SETFL, (int)((unsigned)fl | (unsigned)O_NONBLOCK));
	return fd;
}

/* ---- SOCKS5 ------------------------------------------------------------ */

/* Only what a tailcat client needs: no authentication, CONNECT only, and the
 * destination host is ignored because there is exactly one place to go -- the
 * server at the other end of this tunnel. Only the port is used.
 *
 * The negotiation is done in one blocking-ish pass on a non-blocking socket
 * with a short deadline. A client that has connected to a proxy sends its
 * greeting immediately; one that does not is not worth waiting for. */

#define SOCKS_VERSION 5
#define SOCKS_CMD_CONNECT 1
#define SOCKS_ATYP_IPV4 1
#define SOCKS_ATYP_NAME 3
#define SOCKS_ATYP_IPV6 4

/* read_exact reads n bytes with a deadline, on a non-blocking socket. */
static bool socks_read(int fd, uint8_t *buf, size_t n, uint64_t until)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = recv(fd, buf + off, n - off, 0);
		if (r > 0) {
			off += (size_t)r;
			continue;
		}
		if (r == 0)
			return false;
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return false;
		if (now_ms() >= until)
			return false;
		struct pollfd pf = { fd, POLLIN, 0 };
		(void)poll(&pf, 1, 20);
	}
	return true;
}

static bool socks_write(int fd, const uint8_t *buf, size_t n, uint64_t until)
{
	size_t off = 0;
	while (off < n) {
		ssize_t w = send(fd, buf + off, n - off, 0);
		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
			return false;
		if (now_ms() >= until)
			return false;
		struct pollfd pf = { fd, POLLOUT, 0 };
		(void)poll(&pf, 1, 20);
	}
	return true;
}

/* socks_handshake negotiates and reports the port the client asked for.
 * Returns TC_OK having replied "succeeded", or an error having replied with
 * the appropriate refusal. */
static int socks_handshake(int fd, uint16_t *out_port)
{
	uint64_t until = now_ms() + 10000;
	uint8_t b[262];

	/* Greeting: version, count, methods. */
	if (!socks_read(fd, b, 2, until) || b[0] != SOCKS_VERSION)
		return TC_ERR_INVAL;
	size_t nmethods = b[1];
	if (nmethods > 0 && !socks_read(fd, b, nmethods, until))
		return TC_ERR_INVAL;

	/* We only offer "no authentication". Anything else would be pretending
	 * to a security property the tunnel already provides. */
	bool none_ok = false;
	for (size_t i = 0; i < nmethods; i++)
		if (b[i] == 0x00)
			none_ok = true;
	uint8_t reply[2] = { SOCKS_VERSION, none_ok ? 0x00 : 0xff };
	if (!socks_write(fd, reply, 2, until) || !none_ok)
		return TC_ERR_UNSUPPORTED;

	/* Request: version, command, reserved, address type. */
	if (!socks_read(fd, b, 4, until) || b[0] != SOCKS_VERSION)
		return TC_ERR_INVAL;
	uint8_t cmd = b[1];
	uint8_t atyp = b[3];

	size_t addr_len = 0;
	switch (atyp) {
	case SOCKS_ATYP_IPV4: addr_len = 4; break;
	case SOCKS_ATYP_IPV6: addr_len = 16; break;
	case SOCKS_ATYP_NAME:
		if (!socks_read(fd, b, 1, until))
			return TC_ERR_INVAL;
		addr_len = b[0];
		break;
	default:
		break;
	}
	if (addr_len == 0 && atyp != SOCKS_ATYP_NAME) {
		uint8_t no[10] = { SOCKS_VERSION, 0x08, 0, SOCKS_ATYP_IPV4 };
		(void)socks_write(fd, no, sizeof no, until);
		return TC_ERR_UNSUPPORTED; /* address type not supported */
	}
	/* The destination host is read and discarded: there is exactly one place
	 * this proxy can go, which is the server at the far end of the tunnel.
	 * Routing by hostname is what upstream's socks does with several servers;
	 * with one, only the port means anything. */
	if (addr_len > 0 && !socks_read(fd, b, addr_len, until))
		return TC_ERR_INVAL;
	if (!socks_read(fd, b, 2, until))
		return TC_ERR_INVAL;
	uint16_t port = (uint16_t)((uint16_t)b[0] << 8 | b[1]);

	if (cmd != SOCKS_CMD_CONNECT || port == 0) {
		uint8_t no[10] = { SOCKS_VERSION, 0x07, 0, SOCKS_ATYP_IPV4 };
		(void)socks_write(fd, no, sizeof no, until);
		return TC_ERR_UNSUPPORTED; /* command not supported */
	}

	/* "Succeeded", with a zero bound address: the client has no use for it
	 * and inventing one would be a fiction. */
	uint8_t ok[10] = { SOCKS_VERSION, 0x00, 0, SOCKS_ATYP_IPV4 };
	if (!socks_write(fd, ok, sizeof ok, until))
		return TC_ERR_INVAL;

	*out_port = port;
	return TC_OK;
}

/* ---- the shared listen-and-dial loop ----------------------------------- */

static int run_listeners(tc_client *cl, local_listener *ls, size_t nls,
                         tc_proxy *proxy, bool socks, pid_t child,
                         uint64_t deadline)
{
	tc_derp_set_read_timeout(&cl->derp, 20);

	while (now_ms() < deadline) {
		uint64_t t = now_ms();

		/* With a child command, the proxy exists for its lifetime and no
		 * longer: `socks <addr> -- curl ...` should exit when curl does,
		 * with curl's status, rather than leaving a proxy behind. */
		if (child > 0) {
			int wstatus = 0;
			pid_t got = waitpid(child, &wstatus, WNOHANG);
			if (got == child) {
				if (WIFEXITED(wstatus))
					return WEXITSTATUS(wstatus);
				return 1;
			}
			if (got < 0 && errno != EINTR)
				return 1;
		}

		if (cl->ctx.relay_stalled) {
			cl->ctx.relay_stalled = false;
			vlogf("a relay write stalled; rebuilding the connection");
			if (relay_recover(&cl->derp, cl->ci.server_public, cl->ping,
			                  cl->ping_len, deadline) != TC_OK) {
				fprintf(stderr, "tailcat-c: lost the relay\n");
				return 1;
			}
		}

		tc_wg_peer_tick(&cl->peer, t);
		tc_tcp_mux_tick(cl->mux, t);

		/* Accept whatever is waiting on each local listener. */
		for (size_t i = 0; i < nls; i++) {
			for (;;) {
				int fd = accept(ls[i].fd, NULL, NULL);
				if (fd < 0)
					break;

				uint16_t want = ls[i].remote_port;
				if (socks && socks_handshake(fd, &want) != TC_OK) {
					vlogf("SOCKS negotiation failed");
					(void)close(fd);
					continue;
				}

				tc_tcp_conn *c = NULL;
				int crc = (ls[i].dst.ip_len == 16)
				              ? tc_tcp_mux_connect_to(cl->mux, ls[i].dst.ip,
				                                      want, t, &c)
				              : tc_tcp_mux_connect(cl->mux, want, t, &c);
				if (crc != TC_OK) {
					vlogf("no room for another connection");
					(void)close(fd);
					continue;
				}
				if (tc_proxy_add(proxy, c, fd) != TC_OK) {
					vlogf("no room for another connection");
					(void)close(fd);
					tc_tcp_mux_close(cl->mux, c, t);
					continue;
				}
				if (ls[i].dst.ip_len == 16) {
					char where[80];
					(void)tc_endpoint_format(where, sizeof where,
					                         &ls[i].dst);
					vlogf("forwarding a connection through the server to %s",
					      where);
				} else {
					vlogf("forwarding a connection to the server's port %u",
					      (unsigned)want);
				}
			}
		}

		bool progress = tc_proxy_pump(proxy, t) > 0;
		tc_proxy_reap(proxy, t);
		/* Only now, once the proxy has dropped anything that finished: the
		 * mux is about to free the connections it points at. */
		tc_tcp_mux_reap(cl->mux);

		if (!progress && !tc_derp_has_pending(&cl->derp)) {
			struct pollfd pfds[1 + TC_MAX_LISTENERS + TC_TCP_MAX_CONNS];
			nfds_t nfds = 0;
			int dfd = tc_derp_fd(&cl->derp);
			if (dfd >= 0) {
				pfds[nfds].fd = dfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
			for (size_t i = 0; i < nls; i++) {
				pfds[nfds].fd = ls[i].fd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
			for (size_t i = 0; i < TC_TCP_MAX_CONNS &&
			                   nfds < 1 + TC_MAX_LISTENERS + TC_TCP_MAX_CONNS;
			     i++) {
				int pfd = -1;
				bool rd = false, wr = false;
				if (!tc_proxy_interest(proxy, i, &pfd, &rd, &wr))
					continue;
				if (!rd && !wr)
					continue;
				pfds[nfds].fd = pfd;
				pfds[nfds].events =
				    (short)((rd ? POLLIN : 0) | (wr ? POLLOUT : 0));
				pfds[nfds].revents = 0;
				nfds++;
			}

			int wait_ms = 20;
			uint64_t dl = tc_tcp_mux_next_deadline(cl->mux);
			uint64_t wdl = tc_wg_peer_next_deadline(&cl->peer);
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

		pump_service_udp(&cl->ctx, cl->mux);

		uint8_t src[32];
		static uint8_t buf[TC_DERP_MAX_PACKET_SIZE];
		size_t len = 0;
		int rc = tc_derp_recv(&cl->derp, src, buf, sizeof buf, &len);
		if (rc == TC_ERR_TIMEOUT) {
			if (tc_derp_idle_ms(&cl->derp) > TC_DERP_DEAD_AFTER_MS) {
				vlogf("no keep-alive; the relay is gone");
				if (relay_recover(&cl->derp, cl->ci.server_public, cl->ping,
				                  cl->ping_len, deadline) != TC_OK) {
					fprintf(stderr, "tailcat-c: lost the relay\n");
					return 1;
				}
			}
			continue;
		}
		if (rc == TC_ERR_CLOSED) {
			if (relay_recover(&cl->derp, cl->ci.server_public, cl->ping,
			                  cl->ping_len, deadline) != TC_OK) {
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
		if (memcmp(src, cl->ci.server_public, 32) != 0 || len == 0)
			continue;
		if (pump_relay_disco(&cl->ctx, buf, len))
			continue;

		static uint8_t inner[TC_DERP_MAX_PACKET_SIZE];
		size_t inner_len = 0;
		if (tc_wg_peer_input(&cl->peer, buf, len, inner, sizeof inner,
		                     &inner_len, now_ms()) != TC_OK)
			continue;
		if (inner_len == 0)
			continue;
		tc_tcp_mux_input(cl->mux, inner, inner_len, now_ms());
	}
	return 0;
}

/* cmd_forward_or_socks runs both commands: they differ only in where the
 * listeners come from and whether each connection negotiates its own port. */
/* spawn_with_proxy starts a child with all_proxy pointing at our listener.
 *
 * That environment variable is what curl, and much else, reads to find a
 * SOCKS proxy, so a command run this way goes through the tunnel without
 * knowing anything about tailcat. */
static pid_t spawn_with_proxy(const char *const *argv, const char *bind_addr,
                              uint16_t port)
{
	char proxy[128];
	(void)snprintf(proxy, sizeof proxy, "socks5h://%s:%u", bind_addr,
	               (unsigned)port);

	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		return pid;

	/* Child. Both spellings: tools disagree about the case, and setting one
	 * without the other works until you meet a tool that reads the other. */
	(void)setenv("all_proxy", proxy, 1);
	(void)setenv("ALL_PROXY", proxy, 1);
	execvp(argv[0], (char *const *)(uintptr_t)argv);
	fprintf(stderr, "tailcat-c: could not run %s: %s\n", argv[0],
	        strerror(errno));
	_exit(127);
}

static int cmd_forward_or_socks(const char *addr_str, const char **specs,
                                size_t nspecs, const char *bind_addr,
                                bool socks, const char *const *child_argv,
                                bool insecure, unsigned timeout_s,
                                const char *derpmap_url, const char *key_spec)
{
	static tc_client cl;
	uint64_t deadline = (timeout_s == 0)
	                        ? UINT64_MAX
	                        : now_ms() + (uint64_t)timeout_s * 1000u;

	local_listener ls[TC_MAX_LISTENERS];
	size_t nls = 0;
	memset(ls, 0, sizeof ls);

	/* Bind before dialling out: a port already in use should fail now,
	 * cheaply, rather than after a handshake with a relay. */
	if (socks) {
		uint16_t want = 0;
		if (nspecs > 0) {
			tc_fwd_spec f;
			if (tc_fwd_parse(&f, specs[0]) != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n", tc_fwd_error_string());
				return 2;
			}
			want = f.local_port;
		}
		ls[0].fd = bind_local(bind_addr, want, &ls[0].local_port);
		if (ls[0].fd < 0)
			return 1;
		nls = 1;
	} else {
		if (nspecs == 0) {
			fprintf(stderr, "tailcat-c: forward needs at least one mapping, "
			                "such as 8080 or 18080:8080\n");
			return 2;
		}
		for (size_t i = 0; i < nspecs && i < TC_MAX_LISTENERS; i++) {
			tc_fwd_spec f;
			int rc = tc_fwd_parse(&f, specs[i]);
			if (rc != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n", tc_fwd_error_string());
				for (size_t j = 0; j < nls; j++)
					(void)close(ls[j].fd);
				return 2;
			}
			ls[nls].fd = bind_local(bind_addr, f.local_port,
			                        &ls[nls].local_port);
			if (ls[nls].fd < 0) {
				for (size_t j = 0; j < nls; j++)
					(void)close(ls[j].fd);
				return 1;
			}
			ls[nls].remote_port = f.remote_port;
			/* Wrapped here rather than at the dial site: an IPv4 destination
			 * has to travel inside an IPv6 address because that is all the
			 * tunnel carries, and doing it once means the rest of the code
			 * sees one kind of destination instead of two. */
			memset(&ls[nls].dst, 0, sizeof ls[nls].dst);
			if (f.dst.ip_len == 4)
				(void)tc_nat64_wrap(&ls[nls].dst, &f.dst);
			else if (f.dst.ip_len == 16)
				ls[nls].dst = f.dst;
			nls++;
		}
	}

	for (size_t i = 0; i < nls; i++) {
		if (socks)
			fprintf(stderr, "# SOCKS5 proxy on %s:%u\n", bind_addr,
			        (unsigned)ls[i].local_port);
		else if (ls[i].dst.ip_len == 16) {
			/* Shown as the user typed it, not as it travels. */
			tc_endpoint shown = ls[i].dst, v4;
			if (tc_nat64_unwrap(&v4, &shown) == TC_OK)
				shown = v4;
			char where[80];
			(void)tc_endpoint_format(where, sizeof where, &shown);
			fprintf(stderr, "# %s:%u -> %s, through the server\n", bind_addr,
			        (unsigned)ls[i].local_port, where);
		} else
			fprintf(stderr, "# %s:%u -> the server's port %u\n", bind_addr,
			        (unsigned)ls[i].local_port,
			        (unsigned)ls[i].remote_port);
	}
	fflush(stderr);

	int status = 1;
	pid_t child = 0;
	tc_proxy *proxy = NULL;
	if (client_up(&cl, addr_str, insecure, derpmap_url, key_spec,
	              now_ms() + 60000) != TC_OK)
		goto out;

	proxy = tc_proxy_new(TC_TCP_MAX_CONNS);
	if (proxy == NULL) {
		fprintf(stderr, "tailcat-c: out of memory\n");
		goto out;
	}

	/* The child starts only once the tunnel is up, so it cannot race ahead
	 * and get a connection refused from a proxy that is not ready. */
	if (child_argv != NULL) {
		child = spawn_with_proxy(child_argv, bind_addr, ls[0].local_port);
		if (child < 0) {
			fprintf(stderr, "tailcat-c: could not start the command\n");
			goto out;
		}
	}

	status = run_listeners(&cl, ls, nls, proxy, socks, child, deadline);

	if (child > 0) {
		/* If the loop ended for its own reasons, the child outlives its
		 * proxy and would hang on a connection that can no longer be
		 * served. */
		(void)kill(child, SIGTERM);
		(void)waitpid(child, NULL, 0);
	}

out:

	/* Order matters: the proxy refers to connections the mux owns. */
	tc_proxy_free(proxy);
	client_down(&cl);
	for (size_t i = 0; i < nls; i++)
		(void)close(ls[i].fd);
	return status;
}

/* ---- ssh and cp: handing the connection to a real client --------------- */

/* These do not implement SSH. They exec the system ssh or scp with a
 * ProxyCommand that runs this program in pipe mode, exactly as upstream does,
 * so the real client does the protocol and this only carries the bytes. That
 * is why they are a hundred lines rather than five thousand -- and why they
 * get the user's own ssh configuration, agent, and known_hosts behaviour for
 * free.
 */

/* self_path finds this executable, for naming in the ProxyCommand.
 *
 * argv[0] is not enough on its own: a program found through PATH gets a bare
 * name, and ssh runs the ProxyCommand through a shell whose PATH may differ.
 * /proc/self/exe is exact where it exists; otherwise argv[0] is used, and a
 * bare name is left for the shell to resolve as the user's own PATH would. */
static const char *self_path(const char *argv0)
{
	static char buf[1024];
#ifdef __linux__
	ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
	if (n > 0) {
		buf[n] = '\0';
		return buf;
	}
#endif
	if (argv0 != NULL && argv0[0] != '\0') {
		(void)snprintf(buf, sizeof buf, "%s", argv0);
		return buf;
	}
	return "tailcat-c";
}

/* on_windows reports whether the ProxyCommand will be run by cmd.exe.
 *
 * A fat APE runs on six operating systems from one file, so this cannot be
 * decided at compile time the way upstream's runtime.GOOS is. */
static bool on_windows(void)
{
	/* Windows is the only target where this is set, and Cosmopolitan passes
	 * the host environment through. */
	return getenv("SYSTEMROOT") != NULL || getenv("SystemRoot") != NULL;
}

/* find_in_path resolves a program name the way a shell would. */
static bool find_in_path(const char *name, char *out, size_t cap)
{
	if (strchr(name, '/') != NULL) {
		(void)snprintf(out, cap, "%s", name);
		return access(out, X_OK) == 0;
	}
	const char *path = getenv("PATH");
	if (path == NULL)
		path = "/usr/bin:/bin";
	while (*path != '\0') {
		const char *sep = strchr(path, ':');
		size_t len = (sep != NULL) ? (size_t)(sep - path) : strlen(path);
		if (len > 0 && len < cap) {
			int n = snprintf(out, cap, "%.*s/%s", (int)len, path, name);
			if (n > 0 && (size_t)n < cap && access(out, X_OK) == 0)
				return true;
		}
		if (sep == NULL)
			break;
		path = sep + 1;
	}
	return false;
}

/* build_proxy_command assembles the command ssh will run for us. */
static int build_proxy_command(char *out, size_t cap, const char *self,
                               const char *addr, const char *port,
                               const char *derpmap_url, bool insecure)
{
	const char *args[8];
	size_t n = 0;
	char urlarg[512];

	args[n++] = self;
	if (derpmap_url != NULL) {
		(void)snprintf(urlarg, sizeof urlarg, "--derpmap-url=%s",
		               derpmap_url);
		args[n++] = urlarg;
	}
	if (insecure)
		args[n++] = "--insecure";
	args[n++] = addr;
	args[n++] = port;

	int rc = tc_proxycmd_join(out, cap, args, n, on_windows());
	if (rc == TC_ERR_INVAL)
		fprintf(stderr, "tailcat-c: this program's path cannot be passed "
		                "safely to ssh as a ProxyCommand\n");
	return rc;
}

/* cmd_ssh_or_cp execs the system ssh or scp.
 *
 * Nothing is validated about the extra arguments: they are the user's own,
 * handed to their own ssh, and this process is replaced rather than
 * interpreting them. */
static int cmd_ssh_or_cp(bool is_cp, const char *argv0, const char **args,
                         size_t nargs, const char *port, bool insecure,
                         const char *derpmap_url)
{
	const char *tool = is_cp ? "scp" : "ssh";
	char toolpath[1024];
	if (!find_in_path(tool, toolpath, sizeof toolpath)) {
		fprintf(stderr, "tailcat-c: no %s found in $PATH\n", tool);
		return 1;
	}

	/* The address is the first argument for ssh. For cp it is embedded in
	 * whichever operands look like <addr>:path. */
	const char *addr = NULL;
	if (!is_cp) {
		if (nargs < 1) {
			fprintf(stderr, "tailcat-c: ssh needs an address\n");
			return 2;
		}
		addr = args[0];
	} else {
		for (size_t i = 0; i < nargs && addr == NULL; i++) {
			const char *colon = strchr(args[i], ':');
			if (colon != NULL && colon - args[i] > 2 &&
			    strncmp(args[i], "tc", 2) == 0) {
				static char buf[TC_ADDR_STR_MAX];
				size_t len = (size_t)(colon - args[i]);
				if (len >= sizeof buf) {
					fprintf(stderr, "tailcat-c: address too long\n");
					return 2;
				}
				memcpy(buf, args[i], len);
				buf[len] = '\0';
				addr = buf;
			}
		}
		if (addr == NULL) {
			fprintf(stderr, "tailcat-c: cp needs one operand of the form "
			                "<tc-address>:path\n");
			return 2;
		}
	}

	/* A user@ prefix belongs to ssh, not to the address. */
	const char *user = NULL;
	static char userbuf[256];
	const char *at = strchr(addr, '@');
	if (at != NULL) {
		size_t len = (size_t)(at - addr);
		if (len < sizeof userbuf) {
			memcpy(userbuf, addr, len);
			userbuf[len] = '\0';
			user = userbuf;
		}
		addr = at + 1;
	}

	char dest[64];
	if (tc_ssh_dest_host(dest, sizeof dest, addr) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not name the destination\n");
		return 1;
	}

	char proxy[2048];
	if (build_proxy_command(proxy, sizeof proxy, self_path(argv0), addr, port,
	                        derpmap_url, insecure) != TC_OK)
		return 1;

	char proxyopt[2100];
	(void)snprintf(proxyopt, sizeof proxyopt, "ProxyCommand=%s", proxy);

	/* Host key checking is off because the destination name is a hash of the
	 * address, not a host anyone has a key for, and the address itself
	 * already authenticates the server: reaching it at all required the
	 * pre-shared key and the server's public key. A known_hosts entry keyed
	 * on a synthetic name would add a prompt and no security. */
	const char *fixed[] = {
		toolpath,
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking no",
		"-o", "UserKnownHostsFile /dev/null",
		"-o", "LogLevel ERROR",
		"-o", proxyopt,
	};

	char *argv[64];
	size_t n = 0;
	for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
		argv[n++] = (char *)(uintptr_t)fixed[i];

	static char operands[16][TC_ADDR_STR_MAX + 256];
	size_t nops = 0;

	if (!is_cp) {
		char withuser[320];
		if (user != NULL) {
			(void)snprintf(withuser, sizeof withuser, "%s@%s", user, dest);
			(void)snprintf(operands[nops], sizeof operands[0], "%s",
			               withuser);
		} else {
			(void)snprintf(operands[nops], sizeof operands[0], "%s", dest);
		}
		argv[n++] = (char *)(uintptr_t) "--";
		argv[n++] = operands[nops];
		nops++;
		/* Anything after the address goes to ssh untouched: a remote command,
		 * more flags, whatever the user meant. */
		for (size_t i = 1; i < nargs && n < 60; i++)
			argv[n++] = (char *)(uintptr_t)args[i];
	} else {
		argv[n++] = (char *)(uintptr_t) "--";
		for (size_t i = 0; i < nargs && n < 60 && nops < 16; i++) {
			const char *colon = strchr(args[i], ':');
			if (colon != NULL && strncmp(args[i], "tc", 2) == 0) {
				/* Rewrite <addr>:path into <short-host>:path, so scp gets a
				 * name short enough for its own bookkeeping. */
				(void)snprintf(operands[nops], sizeof operands[0], "%s%s",
				               dest, colon);
				argv[n++] = operands[nops];
				nops++;
			} else {
				argv[n++] = (char *)(uintptr_t)args[i];
			}
		}
	}
	argv[n] = NULL;

	vlogf("exec %s with ProxyCommand=%s", toolpath, proxy);
	execv(toolpath, argv);
	fprintf(stderr, "tailcat-c: could not run %s: %s\n", toolpath,
	        strerror(errno));
	return 1;
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
                     const char *derpmap_url, const char *key_spec,
                     bool full_address, bool exit_node,
                     const tc_allowlist *allow)
{
	/* A saved identity if one exists, otherwise a fresh one. This is the
	 * whole point of `genkey`: without it a server's address changes on
	 * every restart, which makes it useless in a script or a service file.
	 *
	 * The pre-shared key is part of that identity, not generated per run:
	 * it is what stops a relay operator who has watched both public keys go
	 * past from joining the tunnel, and it is embedded in the address, so a
	 * new one would mean a new address. */
	static tc_keyfile saved;
	bool have_saved = false;
	if (load_key(&saved, key_spec, false, &have_saved) != TC_OK)
		return 1;

	tc_wg_identity me;
	uint8_t disco_pub[32];
	static tc_conn_info ci;
	memset(&ci, 0, sizeof ci);

	if (have_saved) {
		if (tc_wg_identity_from_private(&me, saved.private_key) != TC_OK) {
			fprintf(stderr, "tailcat-c: the saved key is not usable\n");
			return 1;
		}
		ci = saved.pub;
	} else {
		if (tc_wg_identity_generate(&me) != TC_OK) {
			fprintf(stderr, "tailcat-c: could not generate keys\n");
			return 1;
		}
		memcpy(ci.server_public, me.public_key, 32);
		if (tc_random_bytes(ci.preshared_key, sizeof ci.preshared_key) !=
		    TC_OK) {
			fprintf(stderr,
			        "tailcat-c: could not generate a pre-shared key\n");
			return 1;
		}
		ci.has_preshared_key = true;
	}
	if (tc_disco_key_for_node(NULL, disco_pub, me.private_key) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not derive the disco key\n");
		return 1;
	}
	memcpy(ci.server_disco_public, disco_pub, 32);
	ci.has_disco_public = true;

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
		if (ci.regions[0].num_nodes > 2)
			ci.regions[0].num_nodes = 2;
		relay_host = ci.regions[0].nodes[0].hostname;
	}

	/* What we advertise is not what we dial. Upstream's default address names
	 * its region by number and lets the client fetch the map, and only
	 * --full-address embeds the relay; advertising the long form always made
	 * our address differ from upstream's for the very same saved key, which
	 * is how this was noticed.
	 *
	 * The embedded form is still worth offering: it saves the client a map
	 * fetch and works with no DNS at all. */
	static tc_conn_info advertised;
	advertised = ci;
	if (!full_address && ci.num_regions > 0 && ci.regions[0].region_id > 0) {
		advertised.region_id = ci.regions[0].region_id;
		advertised.num_regions = 0;
	} else {
		advertised.region_id = 0;
	}

	char addr[TC_ADDR_STR_MAX];
	if (tc_addr_encode(addr, sizeof addr, &advertised, NULL) != TC_OK) {
		fprintf(stderr, "tailcat-c: could not build an address\n");
		return 1;
	}

	/* Declared before the first goto out, so the cleanup there never reads
	 * an indeterminate flag. */
	tc_udp udp;
	tc_path path;
	bool have_udp = false;

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
	/* `serve <ports>` takes as many clients as it can hold, each with its own
	 * session and demultiplexer. The one-shot pipe below stays single-client
	 * on purpose: it writes to one stdout and exits, so a second client would
	 * have nowhere to go. */
	if (ports != NULL) {
		char what[128];
		(void)tc_portset_describe(ports, what, sizeof what);
		fprintf(stderr, "# serving %s to localhost, up to %d clients\n", what,
		        TC_SERVE_MAX_CLIENTS);
		fflush(stderr);

		static serve_state st;
		memset(&st, 0, sizeof st);
		st.derp = &derp;
		st.me = me;
		memcpy(st.psk, ci.preshared_key, sizeof st.psk);
		st.ports = ports;
		st.exit_node = exit_node;
		if (allow != NULL)
			st.allow = *allow;
		if (exit_node)
			fprintf(stderr, "# acting as an exit node: clients may reach "
			                "anything this machine can\n");
		st.proxy = tc_proxy_new(TC_TCP_MAX_CONNS);
		if (st.proxy == NULL) {
			fprintf(stderr, "tailcat-c: out of memory\n");
			goto out;
		}
		tc_derp_set_write_timeout(&derp, 15000);

		/* One socket and one netcheck for every client. The addresses we
		 * advertise are a property of the socket, so working them out once
		 * is not only cheaper, it is the only way each client is told the
		 * same thing. */
		if (tc_disco_key_for_node(st.disco_priv, st.disco_pub,
		                          me.private_key) == TC_OK &&
		    tc_udp_open(&st.udp, 0) == TC_OK) {
			static tc_derp_map one;
			memset(&one, 0, sizeof one);
			if (ci.num_regions > 0) {
				one.regions[0] = ci.regions[0];
				one.num_regions = 1;
			}
			st.num_local = path_local_list(
			    &st.udp, one.num_regions > 0 ? &one : NULL, st.local,
			    TC_PATH_MAX_LOCAL);
			st.have_udp = true;
		} else {
			vlogf("no UDP socket; every client stays on the relay");
		}

		status = run_serve_multi(&st, deadline);
		if (st.have_udp)
			tc_udp_close(&st.udp);
		tc_memzero_explicit(st.disco_priv, sizeof st.disco_priv);

		for (size_t i = 0; i < TC_SERVE_MAX_CLIENTS; i++) {
			if (st.c[i].used)
				drop_client(&st, &st.c[i]);
		}
		tc_proxy_free(st.proxy);
		tc_derp_close(&derp);
		return status;
	}

	uint8_t client_key[32], client_disco[32];
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
			/* Same rule as the multi-client path, and the same silence. */
			if (allow != NULL && !tc_allow_permits(allow, node)) {
				vlogf("refusing client %02x%02x%02x%02x: not in --allow",
				      node[0], node[1], node[2], node[3]);
				continue;
			}
			if (!have_client) {
				memcpy(client_key, node, 32);
				memcpy(client_disco, disco, 32);
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

			/* The client's disco key came in the meow, so a direct path can
			 * be looked for from here. The server probes too rather than
			 * waiting to be found: whichever side is easier to reach, the
			 * probes have to cross for a hole to open. */
			uint8_t sd_priv[32], sd_pub[32];
			if (tc_disco_key_for_node(sd_priv, sd_pub, me.private_key) ==
			    TC_OK) {
				static tc_derp_map one;
				memset(&one, 0, sizeof one);
				if (ci.num_regions > 0) {
					one.regions[0] = ci.regions[0];
					one.num_regions = 1;
				}
				have_udp = path_bring_up(&ctx, &udp, &path, sd_priv, sd_pub,
				                         client_disco,
				                         one.num_regions > 0 ? &one : NULL);
				tc_memzero_explicit(sd_priv, sizeof sd_priv);
			}
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
	tc_tcp_mux_set_accept_filter(mux, accept_any_port, NULL);

	tc_derp_set_write_timeout(&derp, 15000);

	vlogf("listening on any port inside the tunnel");
	/* The connection is accepted inside the loop, so NULL here. The server is
	 * introduced to rather than introducing, so it has nothing to re-send
	 * after a reconnection: the client re-meows and we answer. */
	status = run_pipe(&derp, &peer, mux, NULL, client_key, NULL, 0,
	                  &ctx.relay_stalled, deadline, &ctx);
	if (status != 0 && now_ms() >= deadline)
		fprintf(stderr, "tailcat-c: timed out after %u seconds\n", timeout_s);

out:
	if (have_udp)
		tc_udp_close(&udp);
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
	/* Loopback by default. Listening on the network is a decision with
	 * consequences -- anyone who can reach this machine can then reach the
	 * server through it -- so it has to be asked for. */
	const char *bind_addr = "127.0.0.1";
	/* The server port ssh and cp reach through the tunnel. */
	const char *ssh_port = "22";
	/* An empty --key means "the saved default if there is one", which is how
	 * a first run works with no setup and a later genkey changes nothing
	 * about how commands are invoked. */
	const char *key_spec = "";
	bool gk_client = false, gk_force = false, gk_delete = false;
	bool gk_list = false, gk_psk = true;
	const char *gk_region = "auto";
	/* Upstream's default address names a region by number; --full-address
	 * embeds the relay so a client needs no DERP map at all. */
	bool full_address = false;
	static tc_allowlist allow;
	memset(&allow, 0, sizeof allow);
	/* Room for a subcommand plus several port specs: upstream allows the
	 * list to be spread over arguments, as in `serve 80,443 8000-8999`. */
	const char *args[16];
	size_t nargs = 0;
	memset(args, 0, sizeof args);

	/* Everything after a bare `--` is a command for socks to run, not
	 * arguments for us. Split it off before parsing anything, so a flag
	 * meant for the child is never claimed here. */
	const char *const *child_argv = NULL;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			if (i + 1 < argc)
				child_argv = (const char *const *)&argv[i + 1];
			argc = i;
			break;
		}
	}

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
			g_verbose = true;
		} else if (strcmp(a, "--insecure") == 0) {
			insecure = true;
		} else if (strcmp(a, "--relay") == 0 && i + 1 < argc) {
			relay = argv[++i];
		} else if (strcmp(a, "-p") == 0 && i + 1 < argc) {
			ssh_port = argv[++i];
		} else if (strcmp(a, "--key") == 0 && i + 1 < argc) {
			key_spec = argv[++i];
		} else if (strcmp(a, "--full-address") == 0) {
			full_address = true;
		} else if (strcmp(a, "--allow") == 0 && i + 1 < argc) {
			/* Fatal on a bad list rather than a warning. A typo that left
			 * the list inactive would mean a server that admits everyone
			 * while its operator believes it admits three people, and
			 * nothing about the running server would look wrong. */
			if (tc_allow_parse(&allow, argv[++i]) != TC_OK) {
				fprintf(stderr, "tailcat-c: %s\n", tc_allow_error_string());
				return 2;
			}
		} else if (strcmp(a, "--client") == 0) {
			gk_client = true;
		} else if (strcmp(a, "--force") == 0) {
			gk_force = true;
		} else if (strcmp(a, "--delete") == 0) {
			gk_delete = true;
		} else if (strcmp(a, "--list") == 0) {
			gk_list = true;
		} else if (strcmp(a, "--region") == 0 && i + 1 < argc) {
			gk_region = argv[++i];
		} else if (strcmp(a, "--no-psk") == 0) {
			gk_psk = false;
		} else if (strcmp(a, "--bind") == 0 && i + 1 < argc) {
			bind_addr = argv[++i];
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
	/* These three are meant to stay up, so a deadline of zero means "no
	 * deadline" rather than "expire at once". */
	if (timeout_s == 0 && strcmp(args[0], "serve") != 0 &&
	    strcmp(args[0], "forward") != 0 && strcmp(args[0], "socks") != 0)
		timeout_s = 60;

	/* ssh and cp pass everything after their own arguments straight through,
	 * including things that look like our flags, so they take the tail of
	 * argv rather than the parsed list. Re-scan for them before anything
	 * else claims a flag that was meant for ssh. */
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
	if (strcmp(args[0], "netcheck") == 0)
		return cmd_netcheck(derpmap_url, insecure, timeout_s);
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
			return cmd_serve(relay, NULL, insecure, timeout_s, derpmap_url,
			                 key_spec, full_address, false, &allow);
		}

		static tc_portset ports;
		tc_portset_clear(&ports);
		bool exit_node = false;
		for (size_t i = 1; i < nargs; i++) {
			tc_portset_service svc = TC_PORTSET_SVC_NONE;
			int rc = tc_portset_parse(&ports, args[i], &svc);
			if (rc == TC_ERR_UNSUPPORTED && svc == TC_PORTSET_SVC_EXIT_NODE) {
				/* Implemented, unlike the other named services. It is the
				 * one that has to be asked for by name rather than implied,
				 * because it makes this machine a proxy for everything it
				 * can reach. */
				exit_node = true;
				continue;
			}
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
		                 timeout_given ? timeout_s : 0, derpmap_url,
		                 key_spec, full_address, exit_node, &allow);
	}
	if (strcmp(args[0], "forward") == 0) {
		if (nargs < 3) {
			fprintf(stderr, "tailcat-c: forward needs an address and at "
			                "least one mapping, such as 8080 or 18080:8080\n");
			return 2;
		}
		return cmd_forward_or_socks(args[1], &args[2], nargs - 2, bind_addr,
		                            false, NULL, insecure,
		                            timeout_given ? timeout_s : 0,
		                            derpmap_url, key_spec);
	}
	if (strcmp(args[0], "socks") == 0) {
		if (nargs < 2) {
			fprintf(stderr, "tailcat-c: socks needs an address\n");
			return 2;
		}
		return cmd_forward_or_socks(args[1], nargs >= 3 ? &args[2] : NULL,
		                            nargs >= 3 ? nargs - 2 : 0, bind_addr,
		                            true, child_argv, insecure,
		                            timeout_given ? timeout_s : 0,
		                            derpmap_url, key_spec);
	}
	if (strcmp(args[0], "genkey") == 0) {
		return cmd_genkey(key_spec, gk_client, gk_force, gk_delete, gk_list,
		                  gk_region, gk_psk, insecure, derpmap_url);
	}
	if (strcmp(args[0], "printpub") == 0)
		return cmd_printpub(key_spec);
	if (strcmp(args[0], "ssh") == 0) {
		if (nargs < 2) {
			fprintf(stderr, "tailcat-c: ssh needs an address\n");
			return 2;
		}
		return cmd_ssh_or_cp(false, argv[0], &args[1], nargs - 1, ssh_port,
		                     insecure, derpmap_url);
	}
	if (strcmp(args[0], "cp") == 0) {
		if (nargs < 3) {
			fprintf(stderr, "tailcat-c: cp needs a source and a "
			                "destination\n");
			return 2;
		}
		return cmd_ssh_or_cp(true, argv[0], &args[1], nargs - 1, ssh_port,
		                     insecure, derpmap_url);
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
	return cmd_pipe(args[0], port, insecure, timeout_s, derpmap_url,
	                key_spec);
}
