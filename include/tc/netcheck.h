/* SPDX-License-Identifier: BSD-3-Clause
 *
 * What this network can do, and which relay is closest.
 *
 * Phase 1.4 chose a region by timing a DERP connection -- TCP, TLS and the
 * relay's key exchange -- and said at the time that it was the cheap version,
 * to be revisited once STUN arrived. It has. Timing TCP to a relay answers
 * "which relay is quickest to talk to", but every direct path is UDP, and a
 * network where the two agree is an assumption rather than a fact. This
 * measures the UDP path, which is the one that matters.
 *
 * It also answers two questions the old heuristic could not ask at all:
 *
 *   What address does the world see us at?  Needed before we can tell a peer
 *   where to find us. STUN alone gives this.
 *
 *   Does that address depend on who we are talking to?  A NAT that assigns a
 *   different mapping per destination -- "hard" or symmetric NAT -- makes the
 *   address we learn from one server useless for reaching us from anywhere
 *   else. Knowing this early is the difference between failing over to the
 *   relay immediately and spending a minute probing paths that cannot work.
 *
 * Both come from the same probes, which is why netcheck is one operation
 * rather than three.
 *
 * ---- structure ----------------------------------------------------------
 *
 * The scheduling and accounting are separated from the socket. tc_netcheck is
 * a state machine driven by "what should I send now" and "here is a packet
 * that arrived"; tc_netcheck_run is the loop that wires it to a tc_udp.
 *
 * That split is not decoration. A netcheck whose logic only runs against live
 * servers can only be tested against live servers, and this project does not
 * put load on third-party infrastructure to check its own arithmetic. Driven
 * by hand, the core is fully exercised offline: latency ordering, retransmits,
 * timeouts, answers that arrive after the deadline, responses whose
 * transaction ID we never sent.
 *
 * ---- what is measured, and what is not ----------------------------------
 *
 * The mapped address learned here belongs to *the socket the probes went
 * out on*. Running a netcheck on one socket and sending disco from another
 * learns an address for the wrong hole in the NAT, so tc_netcheck_run takes
 * the tc_udp the caller intends to use rather than opening its own.
 *
 * Not implemented, and deliberately: hairpinning (whether we can reach our
 * own mapped address), port mapping protocols (UPnP, PMP, PCP) and captive
 * portal detection. Each is a separate mechanism rather than a reading of
 * these probes.
 */
#ifndef TC_NETCHECK_H_
#define TC_NETCHECK_H_

#include "tc/derpmap.h"
#include "tc/endpoint.h"
#include "tc/stun.h"
#include "tc/udp.h"

/* One probe per family per region. */
#define TC_NETCHECK_MAX_PROBES (TC_DERPMAP_MAX_REGIONS * 2)

/* Sends per probe before it is called unanswered. UDP, so one lost datagram
 * must not be reported as a region that does not exist. */
#ifndef TC_NETCHECK_SENDS
#define TC_NETCHECK_SENDS 3
#endif

#define TC_NETCHECK_DEFAULT_STUN_PORT 3478
#define TC_NETCHECK_DEFAULT_TIMEOUT_MS 3000

typedef struct {
	int64_t region_id;
	/* Round trip in milliseconds, or -1 for no answer. A region can answer
	 * on one family and not the other, which is ordinary and worth keeping
	 * apart: it is how a v6-only path to a relay shows up. */
	int rtt_v4_ms;
	int rtt_v6_ms;
} tc_netcheck_region;

typedef struct {
	/* Any answer at all. False means UDP is blocked, every direct path is
	 * hopeless, and the relay is the only option -- worth knowing in one
	 * boolean rather than after a minute of failed probing. */
	bool udp;
	bool ipv4;
	bool ipv6;

	/* Where the world sees us. ip_len 0 means we never found out. */
	tc_endpoint global_v4;
	tc_endpoint global_v6;

	/* Whether the IPv4 mapping depends on the destination.
	 *
	 * True means a symmetric NAT: the address one server reports is not the
	 * address another would, so telling a peer about it is telling them
	 * somewhere that will not work for them. Two servers must answer before
	 * this is known at all, which is why it is a pair rather than a bool. */
	bool mapping_varies;
	bool mapping_varies_known;

	tc_netcheck_region regions[TC_DERPMAP_MAX_REGIONS];
	size_t num_regions;

	/* The quickest region to answer, by the better of its two families.
	 * Zero when nothing answered; the caller should keep whatever it would
	 * have used otherwise rather than treat that as a failure. */
	int64_t preferred_region;
} tc_netcheck_report;

typedef struct {
	/* Total budget for the whole check, not per probe. All probes are in
	 * flight at once, so the wall clock is the timeout rather than a
	 * multiple of it. Zero means TC_NETCHECK_DEFAULT_TIMEOUT_MS. */
	int timeout_ms;
	/* Regions to probe, in map order. Zero means all of them. */
	size_t max_regions;
	/* Port to use when a node names none. Zero means 3478. */
	uint16_t stun_port;
	/* Resolve a node's hostname when the map carries no literal address.
	 * Off by default: it blocks, and the published map always has both. */
	bool resolve_hostnames;
} tc_netcheck_opts;

/* ---- the state machine -------------------------------------------------
 *
 * The fields are exposed so this can live on a stack; treat them as private.
 */

typedef struct {
	uint8_t txid[TC_STUN_TXID_LEN];
	tc_endpoint dst;
	size_t region_idx;
	bool v6;
	bool answered;
	int sends_left;
	uint64_t due_ms; /* when the next send is due */
	uint64_t sent_ms;
} tc_netcheck_probe;

typedef struct {
	tc_netcheck_probe probes[TC_NETCHECK_MAX_PROBES];
	size_t num_probes;
	uint64_t start_ms;
	uint64_t deadline_ms;
	int timeout_ms;
	tc_netcheck_report report;
} tc_netcheck;

/* tc_netcheck_begin builds the probe set from the map.
 *
 * now_ms is a monotonic clock in milliseconds; the caller supplies it so a
 * test can run a whole check in an instant and a real caller need not care
 * which clock this module would have chosen.
 *
 * Returns TC_ERR_INVAL if the map yields no probe at all. */
int tc_netcheck_begin(tc_netcheck *nc, const tc_derp_map *m,
                      const tc_netcheck_opts *opts, uint64_t now_ms);

/* tc_netcheck_next_send reports the next datagram to send.
 *
 *   TC_OK           *dst and out hold a request to send now.
 *   TC_ERR_TIMEOUT  nothing is due yet; *wait_ms says for how long.
 *   TC_ERR_DONE     the check is over -- every probe answered or spent.
 *
 * Retransmits reuse the probe's transaction ID, so a duplicated answer to an
 * earlier copy still counts. The round trip is measured from the most recent
 * send, which under-reports when an early copy was the one answered; the
 * alternative is reporting a lost datagram as latency. */
int tc_netcheck_next_send(tc_netcheck *nc, uint64_t now_ms, tc_endpoint *dst,
                          uint8_t out[TC_STUN_REQUEST_LEN], int *wait_ms);

/* tc_netcheck_handle feeds in a packet that arrived.
 *
 * Returns TC_OK if it answered an outstanding probe and TC_ERR_INVAL for
 * anything else -- not STUN, a transaction ID we never sent, a duplicate, or
 * an answer to a probe already counted. A caller sharing the socket should
 * treat TC_ERR_INVAL as "not mine" and pass the packet on.
 *
 * src is who sent it, which is checked against where the probe went. An
 * off-path attacker who guesses a transaction ID would still have to source
 * from the relay's address to be believed. */
int tc_netcheck_handle(tc_netcheck *nc, const tc_endpoint *src,
                       const uint8_t *pkt, size_t len, uint64_t now_ms);

/* tc_netcheck_finish fills in the report: preferred region, and the
 * conclusions that need every answer before they can be drawn.
 *
 * Safe to call early; it reports what is known so far. */
void tc_netcheck_finish(tc_netcheck *nc, tc_netcheck_report *out);

/* ---- the loop ---------------------------------------------------------- */

/* Called for a packet that arrived during the check and was not ours.
 *
 * A netcheck on a live socket would otherwise swallow the traffic it is
 * sharing with. Pass NULL when the socket carries nothing else, which is the
 * usual case at startup. */
typedef void (*tc_netcheck_other_fn)(void *ctx, const tc_endpoint *src,
                                     const uint8_t *pkt, size_t len);

/* tc_netcheck_run drives a whole check over u and fills in the report.
 *
 * Returns TC_OK whenever the check ran, including when nothing answered --
 * "UDP is blocked here" is a result, not an error. */
int tc_netcheck_run(tc_netcheck_report *out, const tc_derp_map *m, tc_udp *u,
                    const tc_netcheck_opts *opts, tc_netcheck_other_fn other,
                    void *ctx);

/* tc_netcheck_describe writes a one-line summary for a log, of the form
 *   "region 301 (nyc) 24ms; 203.0.113.7:41641; mapping is stable"
 * The mapped address is not a secret -- a peer is about to be told it -- but
 * nothing else about the local machine goes in. */
int tc_netcheck_describe(char *out, size_t cap, const tc_netcheck_report *r,
                         const tc_derp_map *m);

#endif /* TC_NETCHECK_H_ */
