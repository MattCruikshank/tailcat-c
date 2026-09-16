/* SPDX-License-Identifier: BSD-3-Clause
 *
 * A WireGuard peer over time: rekeying, session lifetime and keepalives.
 *
 * noise.h gives one handshake and one session. That is enough to move bytes
 * and not enough to keep moving them: WireGuard renews a session after two
 * minutes or 2^60 messages and refuses one older than three, so a tunnel
 * built on a single session works during testing and then silently stops.
 * This layer is what makes a session last.
 *
 * It holds three keypairs at once, which is not an optimisation but a
 * correctness requirement. A rekey cannot be atomic across a network, so
 * during the changeover each side may legitimately receive packets under
 * either the old key or the new one:
 *
 *   current   the keypair we send under
 *   previous  the one it replaced, still accepted for arriving packets
 *   next      derived as responder but not yet proven, so not sent under
 *
 * The asymmetry between `current` and `next` is the subtle part. When we
 * initiate, the responder built the reply, so it already holds the keys and
 * the new keypair becomes `current` at once. When we respond, we have no
 * evidence the initiator ever received our response -- it may have been
 * lost -- so the keypair waits in `next` and is promoted only when a data
 * packet actually authenticates under it. Sending under an unproven keypair
 * would black-hole traffic for a whole handshake timeout.
 *
 * A consequence worth knowing: a responder that has never held a session
 * cannot send until the initiator sends first. That is WireGuard's behaviour,
 * not a limitation here.
 *
 * The caller drives the clock and supplies the transmit callback, so all of
 * this is testable against a simulated link with no timers and no network --
 * which matters more here than anywhere else in the project, since the
 * failure mode being tested for takes minutes to appear.
 *
 * Initiation replay protection lives here too, because the thing it needs is
 * the last timestamp seen from this peer, and this is the only object that
 * knows a peer's history.
 */
#ifndef TC_WGPEER_H_
#define TC_WGPEER_H_

#include "tc/noise.h"

/* WireGuard's timers, from the protocol paper section 6.2. */
#define TC_WG_REKEY_AFTER_TIME_MS 120000u
#define TC_WG_REJECT_AFTER_TIME_MS 180000u
#define TC_WG_REKEY_ATTEMPT_TIME_MS 90000u
#define TC_WG_REKEY_TIMEOUT_MS 5000u
#define TC_WG_KEEPALIVE_TIMEOUT_MS 10000u

/* The responder waits longer than the initiator before starting a rekey, so
 * that two peers do not both initiate over the same expiring session. */
#define TC_WG_REKEY_AFTER_TIME_ON_RECV_MS                                     \
	(TC_WG_REJECT_AFTER_TIME_MS - TC_WG_KEEPALIVE_TIMEOUT_MS -                \
	 TC_WG_REKEY_TIMEOUT_MS)

/* Rekey well before the counter could repeat. TC_WG_REJECT_AFTER_MESSAGES in
 * noise.h is the hard stop; this is where renewal begins. */
#define TC_WG_REKEY_AFTER_MESSAGES (1ull << 60)

/* tc_wg_send_fn transmits one WireGuard message. A failure is treated as
 * packet loss, which WireGuard tolerates: handshakes retry and TCP above
 * retransmits. */
typedef int (*tc_wg_send_fn)(void *ctx, const uint8_t *pkt, size_t len);

typedef struct {
	tc_wg_session s;
	uint64_t birth_ms; /* when the keys were derived */
	bool valid;
} tc_wg_keypair;

typedef struct {
	uint64_t handshakes_initiated;
	uint64_t handshakes_responded;
	uint64_t handshakes_completed;
	uint64_t handshakes_retried;
	uint64_t handshakes_abandoned;
	uint64_t rekeys;               /* completions that replaced a session */
	uint64_t keepalives_sent;
	uint64_t promotions;           /* next keypairs proven by a data packet */
	uint64_t recv_on_previous;     /* packets that needed the old keypair */
	uint64_t rejected_expired;
	uint64_t rejected_replay;      /* initiations with a stale timestamp */
	uint64_t rejected_unknown_key; /* transport for no keypair we hold */
} tc_wg_peer_stats;

typedef struct {
	tc_wg_identity id;
	uint8_t remote_static[TC_WG_KEY_LEN];
	uint8_t psk[TC_WG_KEY_LEN];
	bool has_psk;

	tc_wg_keypair current, previous, next;

	/* A handshake we started and are waiting on. Each retry replaces it with
	 * a freshly built initiation, because the peer's replay protection
	 * rejects a repeated timestamp. */
	tc_wg_handshake hs;
	bool hs_active;
	uint8_t hs_msg[TC_WG_INITIATION_SIZE];
	uint64_t hs_first_ms; /* first attempt, for REKEY_ATTEMPT_TIME */
	uint64_t hs_next_ms;  /* when to resend, for REKEY_TIMEOUT */

	/* A data packet arrived and nothing has been sent back since; WireGuard
	 * answers with an empty packet after KEEPALIVE_TIMEOUT so the peer knows
	 * the session is alive. */
	bool keepalive_armed;
	uint64_t keepalive_at;

	/* The last TAI64N seen in an initiation from this peer. Anything not
	 * strictly newer is a replay. */
	uint8_t last_timestamp[TC_WG_TIMESTAMP_LEN];
	bool has_last_timestamp;

	tc_wg_send_fn send;
	void *send_ctx;

	uint64_t rng;

	tc_wg_peer_stats stats;
} tc_wg_peer;

/* tc_wg_peer_init prepares a peer. psk may be NULL for no pre-shared key.
 * remote_static is required: tailcat always learns it from the address or
 * the meow exchange before any handshake. */
int tc_wg_peer_init(tc_wg_peer *p, const tc_wg_identity *id,
                    const uint8_t remote_static[TC_WG_KEY_LEN],
                    const uint8_t psk[TC_WG_KEY_LEN], tc_wg_send_fn send,
                    void *send_ctx);

/* tc_wg_peer_clear wipes every key the peer holds. */
void tc_wg_peer_clear(tc_wg_peer *p);

/* tc_wg_peer_start_handshake begins an initiation now, whatever the timers
 * say. Callers that know they are about to need the tunnel -- a client that
 * has just meowed -- use it so the handshake overlaps with their own setup
 * rather than waiting for the first send to discover there is no session. */
int tc_wg_peer_start_handshake(tc_wg_peer *p, uint64_t now_ms);

/* tc_wg_peer_send encrypts and transmits one payload.
 *
 * Returns TC_ERR_AGAIN when there is no usable session, having started a
 * handshake if one was not already running. That is not an error the caller
 * needs to handle specially: the payload is simply dropped, and TCP above
 * retransmits it once the tunnel is back. Treating a rekey as ordinary packet
 * loss is what keeps this layer out of the reliability business. */
int tc_wg_peer_send(tc_wg_peer *p, const void *pt, size_t len,
                    uint64_t now_ms);

/* tc_wg_peer_input handles one received WireGuard message of any type.
 *
 * A transport packet's payload is written to out and its length to *out_len;
 * everything else -- handshakes, keepalives, cookie replies -- sets *out_len
 * to zero. Messages that are malformed, replayed, forged or addressed to a
 * keypair we no longer hold return TC_OK with nothing written, since on a
 * shared relay anything may arrive. */
int tc_wg_peer_input(tc_wg_peer *p, const uint8_t *msg, size_t len,
                     uint8_t *out, size_t cap, size_t *out_len,
                     uint64_t now_ms);

/* tc_wg_peer_tick runs the handshake retry, keepalive and expiry timers. */
int tc_wg_peer_tick(tc_wg_peer *p, uint64_t now_ms);

/* tc_wg_peer_next_deadline is when tc_wg_peer_tick next has work, or
 * UINT64_MAX if no timer is pending. */
uint64_t tc_wg_peer_next_deadline(const tc_wg_peer *p);

/* tc_wg_peer_is_up reports whether a payload can be sent right now. */
bool tc_wg_peer_is_up(const tc_wg_peer *p, uint64_t now_ms);

/* tc_wg_peer_has_keys reports whether any session exists, including one still
 * waiting in `next` for a data packet to prove it. A responder uses this: it
 * has answered a handshake and should start its event loop, even though it
 * cannot transmit until the initiator sends first. */
bool tc_wg_peer_has_keys(const tc_wg_peer *p, uint64_t now_ms);

/* tc_wg_peer_handshaking reports whether an initiation is outstanding. */
bool tc_wg_peer_handshaking(const tc_wg_peer *p);

void tc_wg_peer_get_stats(const tc_wg_peer *p, tc_wg_peer_stats *out);

/* tc_wg_peer_force_rng seeds the jitter source deterministically.
 *
 * FOR TESTS ONLY. Handshake retries are jittered so two peers that lose each
 * other do not retry in lockstep forever; a test needs that to be
 * reproducible. */
void tc_wg_peer_force_rng(tc_wg_peer *p, uint64_t seed);

#endif /* TC_WGPEER_H_ */
