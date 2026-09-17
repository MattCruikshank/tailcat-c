/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Finding a direct path to a peer, and deciding when to trust it.
 *
 * Everything until now went through the relay. The relay always works, and
 * it is always slower than it needs to be: two machines on the same LAN send
 * every byte to a datacentre and back. This is the layer that notices when
 * they could talk directly, proves it, and moves the traffic -- and, just as
 * importantly, notices when the direct path stops working and moves it back.
 *
 * ---- the one rule ------------------------------------------------------
 *
 * A path is usable only when a Ping we sent along it has been answered.
 *
 * Not when we have an address for it; not when a packet arrived from it; not
 * when it looks plausible. Only a Pong proves the path carries traffic in the
 * direction that matters, which is *inbound*, through whatever NAT is in the
 * way. Every other signal can be produced by an attacker or by a NAT that
 * will drop the next packet, and acting on one means sending a live session
 * into a hole.
 *
 * ---- how two peers behind NAT find each other --------------------------
 *
 * Neither can accept an unsolicited packet, so neither can go first. What
 * breaks the symmetry is that both go at once:
 *
 *   Both send CallMeMaybe over the relay, listing the addresses they might
 *   be reachable at -- local interface addresses, and whatever STUN said the
 *   world sees them as.
 *
 *   Both then send Pings to every address the other listed. Each Ping opens
 *   a hole in its own NAT for replies from that address. The first Pings
 *   arrive at a NAT that has not opened yet and are dropped; by then the
 *   holes exist, and the next ones get through.
 *
 * So the losses are expected, and the retries are the mechanism rather than
 * error handling. A Ping arriving from an address we never heard of is not
 * suspicious either -- it is the other side's hole-punching reaching us
 * first -- so it becomes a candidate and is answered.
 *
 * ---- both sides doing this at once -------------------------------------
 *
 * There is no leader and no agreement. Each side independently decides where
 * to send its own packets, which means the two directions can differ for a
 * while: A reaches B directly while B still uses the relay. That is not a
 * bug and needs no resolution. WireGuard does not care which way a packet
 * arrived, and the asymmetry closes on its own as the second side's probes
 * are answered.
 *
 * ---- switching without dropping the session ----------------------------
 *
 * Switching is only a change to where the *next* packet is addressed; no
 * state moves and nothing is renegotiated, because the WireGuard session is
 * the same session either way. Since the new path is proven before it is
 * used, and the old one keeps working while the new one is probed, the
 * changeover costs nothing. A packet lost at the moment of the switch would
 * be ordinary loss, which WireGuard tolerates and TCP above retransmits --
 * but the ordering here is such that there is no such moment.
 *
 * Coming back is the dangerous direction, and it is the one that gets the
 * conservative treatment: a direct path that goes quiet is abandoned after
 * TC_PATH_TRUST_MS, and the relay -- which never stopped working -- takes
 * over. A NAT can drop a mapping at any time with no notification, so "quiet"
 * has to be treated as "gone" rather than "idle".
 *
 * ---- what this deliberately does not do --------------------------------
 *
 * No relay-to-relay path discovery, no UDP relay allocation (disco's 0x04
 * upward), no path MTU discovery, and no preference for one physical
 * interface over another beyond the round trip it produces. Upstream's
 * magicsock does all of it in about eleven thousand lines; this is the part
 * that makes a direct path happen at all.
 *
 * ---- testing -----------------------------------------------------------
 *
 * The clock and both transmit paths are arguments, so a peer pair can be run
 * against a simulated network with configurable loss, delay and NAT
 * behaviour, and a minute of protocol time takes no wall clock at all. The
 * failure modes here are timing-dependent, which is exactly the kind that
 * cannot be found by running the real thing once and watching it work.
 */
#ifndef TC_PATH_H_
#define TC_PATH_H_

#include "tc/disco.h"
#include "tc/endpoint.h"

/* Candidate addresses held for one peer. A peer offering more than this has
 * more than we would sensibly probe; the excess is dropped. */
#ifndef TC_PATH_MAX_CANDIDATES
#define TC_PATH_MAX_CANDIDATES 16
#endif

/* Our own addresses advertised in one CallMeMaybe. */
#ifndef TC_PATH_MAX_LOCAL
#define TC_PATH_MAX_LOCAL 12
#endif

/* ---- timers ------------------------------------------------------------
 *
 * These follow tailscale.com/wgengine/magicsock, because two implementations
 * probing each other should agree about roughly when things happen.
 */

/* How long a direct path is trusted after the last proof it works. Upstream's
 * trustUDPAddrDuration. A NAT can drop a mapping silently, so this is how
 * long we are willing to keep sending into one that may already be gone. */
#define TC_PATH_TRUST_MS 6500u

/* Gap between probes of a path we are actively using, when nothing has
 * arrived on it. Upstream's heartbeatInterval. */
#define TC_PATH_HEARTBEAT_MS 3000u

/* Gap between probes of a candidate not yet proven. Shorter than the
 * heartbeat: the first probes are expected to be lost to a NAT that has not
 * opened yet, and the retries are how the hole gets punched. */
#define TC_PATH_PROBE_MS 500u

/* After this long with no answer, a candidate is set aside and the next
 * round is pushed out, doubling each time up to TC_PATH_PROBE_MAX_BACKOFF_MS.
 *
 * It is never forgotten, and a packet actually arriving from the address
 * wakes it at once: that is evidence, where being listed in a CallMeMaybe
 * again is only a peer repeating itself. */
#define TC_PATH_PROBE_GIVEUP_MS 5000u
#define TC_PATH_PROBE_MAX_BACKOFF_MS 60000u

/* Gap between CallMeMaybe messages while no direct path exists. */
#define TC_PATH_CMM_MS 5000u

/* Once a direct path is up, keep offering our addresses occasionally: they
 * change when an interface does, and a peer working from a stale list will
 * not find us again after a network change. Upstream's
 * endpointsFreshEnoughDuration is of this order. */
#define TC_PATH_CMM_IDLE_MS 25000u

/* A round trip difference below this is not a reason to move a working
 * session. Upstream's goodEnoughLatency. */
#define TC_PATH_GOOD_ENOUGH_MS 5

typedef enum {
	TC_PATH_RELAY = 0, /* the relay, which always works */
	TC_PATH_DIRECT = 1 /* a proven direct path */
} tc_path_kind;

/* tc_path_udp_fn sends one sealed disco packet to a UDP address.
 *
 * A failure is packet loss: probing is built on retries already, and a
 * candidate we cannot reach is one that will not be answered, which is the
 * same outcome by a different route. */
typedef int (*tc_path_udp_fn)(void *ctx, const tc_endpoint *dst,
                              const uint8_t *pkt, size_t len);

/* tc_path_relay_fn sends one sealed disco packet through the relay, which
 * addresses it by the peer's node key. */
typedef int (*tc_path_relay_fn)(void *ctx, const uint8_t *pkt, size_t len);

typedef struct {
	tc_endpoint ep;

	/* The outstanding probe, if any. The transaction ID is what ties a Pong
	 * to the Ping that earned it; without it a peer could answer a probe we
	 * never sent and set our round trip to whatever it liked. */
	uint8_t txid[TC_DISCO_TXID_LEN];
	bool probe_outstanding;
	uint64_t probe_sent_ms;

	/* Proof. last_pong_ms is the last time this path was shown to work in
	 * both directions; last_recv_ms is the last time anything at all arrived
	 * from the address, which is weaker evidence but still evidence. */
	uint64_t last_pong_ms;
	uint64_t last_recv_ms;
	uint64_t first_probe_ms; /* for giving up on a candidate that never answers */

	int rtt_ms; /* -1 until a Pong arrives */
	bool proven;
	bool sleeping; /* probed for long enough with no answer; set aside */

	/* How many probe rounds this address has swallowed without ever
	 * answering, and when the next round may start. An address that does not
	 * exist is re-advertised in every CallMeMaybe the peer sends, so without
	 * a backoff it would be probed at full rate for the life of the session
	 * -- two packets a second, forever, to nowhere. */
	unsigned dead_rounds;
	uint64_t wake_at_ms;
} tc_path_cand;

typedef struct {
	uint64_t pings_sent;
	uint64_t pings_received;
	uint64_t pongs_sent;
	uint64_t pongs_received;
	uint64_t call_me_maybes_sent;
	uint64_t call_me_maybes_received;
	uint64_t upgrades;   /* relay -> direct */
	uint64_t downgrades; /* direct -> relay */
	uint64_t switches;   /* direct -> a different direct */
	uint64_t discarded;  /* disco packets refused */
} tc_path_stats;

typedef struct {
	uint8_t our_disco_priv[32];
	uint8_t our_disco_pub[32];
	uint8_t peer_disco_pub[32];

	tc_path_cand cands[TC_PATH_MAX_CANDIDATES];
	size_t num_cands;

	tc_endpoint local[TC_PATH_MAX_LOCAL];
	size_t num_local;

	/* Where the peer says our packets appear to come from, learned from the
	 * Src field of a Pong. It is the one address we could not have worked out
	 * by ourselves and the one most likely to be the useful one, so it is
	 * advertised alongside the local ones. */
	tc_endpoint seen_by_peer;
	bool has_seen_by_peer;

	/* The chosen path. -1 means the relay. */
	int best;
	uint64_t best_since_ms;

	uint64_t next_cmm_ms;

	tc_path_udp_fn udp;
	tc_path_relay_fn relay;
	void *ctx;

	tc_path_stats stats;
} tc_path;

/* tc_path_init prepares path discovery for one peer.
 *
 * Both disco keys are required. The peer's arrives in its address or in the
 * meow exchange before any of this runs, and without it nothing here can be
 * sealed or opened. */
int tc_path_init(tc_path *p, const uint8_t our_disco_priv[32],
                 const uint8_t our_disco_pub[32],
                 const uint8_t peer_disco_pub[32], tc_path_udp_fn udp,
                 tc_path_relay_fn relay, void *ctx);

/* tc_path_set_local records the addresses we will offer a peer.
 *
 * Typically tc_udp_local_endpoints plus whatever netcheck learned our public
 * address to be. Addresses tc_endpoint_is_candidate rejects are dropped here
 * rather than sent, since every one of them is a probe the peer would waste
 * on somewhere it could never reach. */
int tc_path_set_local(tc_path *p, const tc_endpoint *eps, size_t n);

/* tc_path_start sends the first CallMeMaybe and begins the schedule. */
int tc_path_start(tc_path *p, uint64_t now_ms);

/* tc_path_input_disco handles a packet that arrived on the UDP socket.
 *
 * Returns TC_OK if it was disco addressed to us and has been dealt with, and
 * TC_ERR_INVAL for anything else -- which the caller should then treat as
 * ordinary traffic. The two share a socket, so telling them apart is this
 * function's job as much as acting on them is.
 *
 * src is where the datagram came from, which is not the same as what it says
 * about itself: a Ping's reply goes to src, so that a peer whose NAT rewrote
 * its address still gets an answer it can receive. */
int tc_path_input_disco(tc_path *p, const tc_endpoint *src, const uint8_t *pkt,
                        size_t len, uint64_t now_ms);

/* tc_path_input_relay handles a disco packet that arrived through the relay,
 * which is how CallMeMaybe travels. There is no source address: the relay is
 * the source, and nothing in a relayed message may be treated as proof that
 * a direct path works. */
int tc_path_input_relay(tc_path *p, const uint8_t *pkt, size_t len,
                        uint64_t now_ms);

/* tc_path_note_recv records that ordinary traffic -- a WireGuard packet --
 * arrived over UDP from src.
 *
 * This is evidence a path is alive, and it is the evidence that matters most
 * once a session is running: a path carrying data needs no probes to prove
 * it. It is not enough to *choose* a path, though. Only a Pong does that,
 * because a datagram from an address proves the address can reach us and
 * says nothing about whether we can reach it. */
void tc_path_note_recv(tc_path *p, const tc_endpoint *src, uint64_t now_ms);

/* tc_path_tick runs the probe, heartbeat, CallMeMaybe and expiry schedules,
 * and re-decides which path to use. */
int tc_path_tick(tc_path *p, uint64_t now_ms);

/* tc_path_next_deadline is when tc_path_tick next has work to do. */
uint64_t tc_path_next_deadline(const tc_path *p, uint64_t now_ms);

/* tc_path_best reports where the next packet should go.
 *
 * TC_PATH_DIRECT fills in *out. TC_PATH_RELAY means send through the relay,
 * which is the answer whenever nothing better has been proven -- and the
 * reason nothing here can break a working session. */
tc_path_kind tc_path_best(const tc_path *p, tc_endpoint *out, uint64_t now_ms);

/* tc_path_knows reports whether ep is one of this peer's candidate addresses.
 *
 * For routing an arriving datagram to the right peer when several share a
 * socket. Deliberately weaker than tc_path_best: the two sides choose their
 * paths independently, so a peer can be sending to us directly some seconds
 * before we have proven the same path in our own direction. Refusing its
 * traffic until we agreed would turn a working direct path into a black hole
 * -- the peer would see an upgrade and we would see silence.
 *
 * It is not an authentication check and must not be used as one. WireGuard
 * decides whether a packet is genuine; this only decides which peer to ask. */
bool tc_path_knows(const tc_path *p, const tc_endpoint *ep);

/* tc_path_rtt_ms is the round trip of the path in use, or -1 when that is
 * the relay -- which has no measurement here, because the probes that produce
 * one only ever go to direct candidates.
 *
 * For `ping`, which reports the number rather than a sentence about it. The
 * alternative was reaching into p->cands[p->best].rtt_ms from the CLI, which
 * the tests were already doing and which makes every field of this struct
 * part of its interface. */
int tc_path_rtt_ms(const tc_path *p, uint64_t now_ms);

/* tc_path_describe writes a one-line summary for a log. */
int tc_path_describe(char *out, size_t cap, const tc_path *p, uint64_t now_ms);

void tc_path_get_stats(const tc_path *p, tc_path_stats *out);

#endif /* TC_PATH_H_ */
