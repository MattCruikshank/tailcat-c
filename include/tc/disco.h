/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The disco protocol: how two peers agree on a direct path.
 *
 * STUN says what address the world sees us at, and UDP can send a packet to
 * one. Neither tells a peer where to find us, or proves that a path works in
 * both directions. That is what disco does, in three messages:
 *
 *   CallMeMaybe  sent over the relay: "here are my addresses, try them"
 *   Ping         sent over UDP to a candidate: "are you there?"
 *   Pong         the answer, carrying the address the ping came from
 *
 * A path is usable only when a Ping has been answered along it, because only
 * then is it known to work in the direction that matters -- inbound, through
 * whatever NAT is in the way.
 *
 * Wire format, from tailscale.com/disco:
 *
 *   magic           [6]  "TS\xf0\x9f\x92\xac"
 *   senderDiscoPub  [32]
 *   nonce           [24]
 *   box             NaCl box over the payload below
 *
 *   type            u8
 *   version         u8   (0; trailing bytes are always ignored)
 *   payload         ...
 *
 * The box is the same construction DERP's handshake uses, so M3's NaCl code
 * carries it. The disco key is derived from the node key, not the node key
 * itself: a disco key can be published in an address without publishing the
 * identity that owns the tunnel.
 */
#ifndef TC_DISCO_H_
#define TC_DISCO_H_

#include "tc/endpoint.h"

#define TC_DISCO_MAGIC_LEN 6
#define TC_DISCO_KEY_LEN_ 32
#define TC_DISCO_NONCE_LEN 24
#define TC_DISCO_HEADER_LEN (TC_DISCO_MAGIC_LEN + 32 + TC_DISCO_NONCE_LEN)
#define TC_DISCO_TXID_LEN 12

/* Endpoints one CallMeMaybe carries. Upstream sets no limit; this is a bound
 * on how many probes a peer can make us consider from one message. */
#ifndef TC_DISCO_MAX_ENDPOINTS
#define TC_DISCO_MAX_ENDPOINTS 16
#endif

/* The largest payload we will build or accept inside the box. */
#define TC_DISCO_MAX_PAYLOAD (2 + TC_DISCO_MAX_ENDPOINTS * 18 + 512)

typedef enum {
	TC_DISCO_PING = 0x01,
	TC_DISCO_PONG = 0x02,
	TC_DISCO_CALL_ME_MAYBE = 0x03
	/* 0x04 upward are UDP-relay endpoint allocation and CallMeMaybeVia,
	 * which basic traversal does not need. They are parsed as unknown and
	 * ignored, which is what an older peer does too. */
} tc_disco_type;

typedef struct {
	tc_disco_type type;
	union {
		struct {
			uint8_t txid[TC_DISCO_TXID_LEN];
			/* The sender's node key, which a receiver may use to tie a disco
			 * key to a node key -- but only as corroboration. The message is
			 * sealed to a disco key, so this field says nothing on its own. */
			uint8_t node_key[32];
			bool has_node_key;
			/* Trailing zero bytes, used to probe the path MTU. */
			size_t padding;
		} ping;
		struct {
			uint8_t txid[TC_DISCO_TXID_LEN];
			/* Where the ping appeared to come from. This makes a Pong a STUN
			 * response as well as an answer: it is how a peer behind NAT
			 * learns the address its own packets arrive from. */
			tc_endpoint src;
		} pong;
		struct {
			tc_endpoint eps[TC_DISCO_MAX_ENDPOINTS];
			size_t num;
		} call_me_maybe;
	};
} tc_disco_msg;

/* tc_disco_looks_like reports whether a packet begins with the disco magic
 * and is long enough to hold a header. Used to sort disco out of the other
 * traffic on a shared UDP socket. */
bool tc_disco_looks_like(const uint8_t *pkt, size_t len);

/* tc_disco_source reports the disco public key the packet claims to be from,
 * without opening it.
 *
 * It is a claim, not a fact: anyone can write any key there. It is useful only
 * for choosing which peer's key to try opening the box with. */
int tc_disco_source(const uint8_t *pkt, size_t len, uint8_t out_pub[32]);

/* tc_disco_seal builds a complete packet. */
int tc_disco_seal(uint8_t *out, size_t cap, size_t *out_len,
                  const tc_disco_msg *msg, const uint8_t our_pub[32],
                  const uint8_t our_priv[32], const uint8_t peer_pub[32]);

/* tc_disco_open verifies and parses one.
 *
 * peer_pub is the key we *expect*, and the packet's own sender field must
 * match it. Opening with whatever key the packet names would mean anyone
 * could send us a valid disco message, which is the whole thing this is
 * meant to prevent.
 *
 * Returns TC_ERR_UNSUPPORTED for a message type we do not implement, which a
 * caller should ignore rather than treat as an attack: the protocol has more
 * types than basic traversal uses. */
int tc_disco_open(tc_disco_msg *out, const uint8_t *pkt, size_t len,
                  const uint8_t our_priv[32], const uint8_t peer_pub[32]);

#endif /* TC_DISCO_H_ */
