/* SPDX-License-Identifier: BSD-3-Clause
 *
 * WireGuard's Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake and transport.
 *
 * This is the layer that actually protects tailcat traffic. Everything below
 * it -- DERP, TLS -- is untrusted plumbing; the relay only ever sees the
 * ciphertext produced here.
 *
 * Wire formats, all little-endian:
 *
 *   Initiation, 148 bytes
 *     0   u32   type = 1
 *     4   u32   sender index
 *     8   [32]  initiator ephemeral public key
 *     40  [48]  AEAD(initiator static public) + tag
 *     88  [28]  AEAD(TAI64N timestamp) + tag
 *     116 [16]  mac1
 *     132 [16]  mac2
 *
 *   Response, 92 bytes
 *     0   u32   type = 2
 *     4   u32   sender index
 *     8   u32   receiver index
 *     12  [32]  responder ephemeral public key
 *     44  [16]  AEAD(empty) + tag
 *     60  [16]  mac1
 *     76  [16]  mac2
 *
 *   Transport, 16 + n bytes
 *     0   u32   type = 4
 *     4   u32   receiver index
 *     8   u64   counter
 *     16  [n]   AEAD(payload) + tag
 *
 * The pre-shared key is mixed in as the "psk2" of IKpsk2, during the
 * response. tailcat always sets one, which is what stops a DERP operator who
 * has watched both peers' public keys go by from joining the tunnel. A
 * zeroed PSK is accepted for compatibility and reduces this to plain IK.
 */
#ifndef TC_NOISE_H_
#define TC_NOISE_H_

#include "tc/tc.h"

#define TC_WG_KEY_LEN 32
#define TC_WG_TAG_LEN 16
#define TC_WG_MAC_LEN 16
#define TC_WG_TIMESTAMP_LEN 12

#define TC_WG_MSG_INITIATION 1u
#define TC_WG_MSG_RESPONSE 2u
#define TC_WG_MSG_COOKIE_REPLY 3u
#define TC_WG_MSG_TRANSPORT 4u

#define TC_WG_INITIATION_SIZE 148
#define TC_WG_RESPONSE_SIZE 92
#define TC_WG_TRANSPORT_HEADER_SIZE 16

/* WireGuard rejects a packet whose counter is more than this far below the
 * highest one seen, and refuses a counter it has already accepted. */
#define TC_WG_REPLAY_WINDOW_BITS 2048
#define TC_WG_REPLAY_WORDS (TC_WG_REPLAY_WINDOW_BITS / 64)

/* Counters must never wrap or repeat under one key. WireGuard rekeys long
 * before this; we refuse to send past it rather than reuse a nonce. */
#define TC_WG_REJECT_AFTER_MESSAGES (UINT64_MAX - (1ull << 13))

typedef enum {
	TC_WG_HS_ZEROED = 0,
	TC_WG_HS_INITIATION_CREATED,
	TC_WG_HS_INITIATION_CONSUMED,
	TC_WG_HS_RESPONSE_CREATED,
	TC_WG_HS_RESPONSE_CONSUMED
} tc_wg_hs_state;

/* A node's long-term identity. */
typedef struct {
	uint8_t private_key[TC_WG_KEY_LEN];
	uint8_t public_key[TC_WG_KEY_LEN];
} tc_wg_identity;

typedef struct {
	uint8_t remote_static[TC_WG_KEY_LEN];
	bool has_remote_static;

	/* All-zero means no pre-shared key. */
	uint8_t preshared_key[TC_WG_KEY_LEN];

	/* DH(our static, their static), cached because it is needed on every
	 * handshake and never changes. */
	uint8_t precomputed_ss[TC_WG_KEY_LEN];
	bool has_precomputed_ss;

	uint8_t hash[TC_WG_KEY_LEN];
	uint8_t chain_key[TC_WG_KEY_LEN];
	uint8_t local_ephemeral[TC_WG_KEY_LEN];
	uint8_t remote_ephemeral[TC_WG_KEY_LEN];

	uint32_t local_index;
	uint32_t remote_index;

	tc_wg_hs_state state;
} tc_wg_handshake;

/* An established session. Send and receive keys are distinct and the
 * direction depends on who initiated. */
typedef struct {
	uint8_t send_key[TC_WG_KEY_LEN];
	uint8_t recv_key[TC_WG_KEY_LEN];

	/* Index the peer puts in the receiver field of packets to us. */
	uint32_t local_index;
	/* Index we put in the receiver field of packets to them. */
	uint32_t remote_index;

	uint64_t send_counter;

	/* Sliding replay window: recv_max is the highest counter accepted, and
	 * the bitmap records which of the preceding counters have been seen. */
	uint64_t recv_max;
	uint64_t recv_bitmap[TC_WG_REPLAY_WORDS];

	bool is_initiator;
	bool established;
} tc_wg_session;

/* ---- identity -------------------------------------------------------- */

/* tc_wg_identity_from_private clamps the private key and derives the public
 * key from it. */
int tc_wg_identity_from_private(tc_wg_identity *id,
                                const uint8_t private_key[TC_WG_KEY_LEN]);

/* tc_wg_identity_generate makes a fresh keypair. */
int tc_wg_identity_generate(tc_wg_identity *id);

/* ---- handshake ------------------------------------------------------- */

/* tc_wg_handshake_init prepares a handshake against a peer.
 *
 * remote_static may be NULL on the responding side, where the peer's identity
 * is not known until its initiation has been decrypted. psk may be NULL,
 * which means no pre-shared key. */
int tc_wg_handshake_init(tc_wg_handshake *hs, const tc_wg_identity *id,
                         const uint8_t remote_static[TC_WG_KEY_LEN],
                         const uint8_t psk[TC_WG_KEY_LEN]);

/* tc_wg_create_initiation writes a 148-byte initiation, including mac1.
 *
 * local_index is this side's receiver index; the peer echoes it back. Pass 0
 * to have one generated at random, which is what a caller with no index table
 * should do. */
int tc_wg_create_initiation(uint8_t out[TC_WG_INITIATION_SIZE],
                            tc_wg_handshake *hs, const tc_wg_identity *id,
                            uint32_t local_index);

/* tc_wg_consume_initiation verifies and decrypts an initiation.
 *
 * mac1 is checked against our own public key before anything else, which is
 * what makes an unauthenticated peer cheap to reject.
 *
 * If the handshake already has a remote static key, the decrypted key must
 * match it or the message is rejected; otherwise the decrypted key is adopted
 * and reported through out_peer_static. The TAI64N timestamp is reported for
 * the caller to compare against the last one seen from this peer -- that
 * comparison is what prevents initiation replay, and it is the caller's job
 * because only the caller knows the peer's history. */
int tc_wg_consume_initiation(tc_wg_handshake *hs, const tc_wg_identity *id,
                             const uint8_t msg[TC_WG_INITIATION_SIZE],
                             uint8_t out_peer_static[TC_WG_KEY_LEN],
                             uint8_t out_timestamp[TC_WG_TIMESTAMP_LEN]);

/* tc_wg_create_response writes a 92-byte response. Valid only after
 * tc_wg_consume_initiation. */
int tc_wg_create_response(uint8_t out[TC_WG_RESPONSE_SIZE],
                          tc_wg_handshake *hs, const tc_wg_identity *id,
                          uint32_t local_index);

/* tc_wg_consume_response verifies a response. Valid only after
 * tc_wg_create_initiation. */
int tc_wg_consume_response(tc_wg_handshake *hs, const tc_wg_identity *id,
                           const uint8_t msg[TC_WG_RESPONSE_SIZE]);

/* tc_wg_begin_session derives the transport keys and clears the handshake.
 * The key order depends on which side we were, which is why this must be
 * called on a handshake that has reached a response state. */
int tc_wg_begin_session(tc_wg_session *s, tc_wg_handshake *hs);

/* ---- transport ------------------------------------------------------- */

/* tc_wg_encrypt writes a transport packet: the 16-byte header followed by
 * the sealed payload. Needs pt_len + 32 bytes of room. */
int tc_wg_encrypt(uint8_t *out, size_t cap, size_t *out_len, tc_wg_session *s,
                  const void *pt, size_t pt_len);

/* tc_wg_decrypt verifies a transport packet and writes the payload.
 *
 * It enforces the replay window: a counter already seen, or too far behind
 * the highest one accepted, is rejected. The window is only advanced after
 * the tag verifies, so a forged packet cannot poison it. */
int tc_wg_decrypt(uint8_t *out, size_t cap, size_t *out_len, tc_wg_session *s,
                  const uint8_t *msg, size_t msg_len);

/* tc_wg_session_clear wipes the keys. */
void tc_wg_session_clear(tc_wg_session *s);

/* ---- mac1 ------------------------------------------------------------ */

/* tc_wg_mac1_key derives the key used to authenticate handshake messages
 * addressed to the holder of `public_key`: BLAKE2s-256("mac1----" || pk).
 *
 * When sending, use the peer's public key; when verifying, use your own. */
void tc_wg_mac1_key(uint8_t out[TC_WG_KEY_LEN],
                    const uint8_t public_key[TC_WG_KEY_LEN]);

/* tc_wg_timestamp writes the current time as TAI64N.
 *
 * The low 24 bits of the nanosecond field are cleared, exactly as WireGuard
 * does, so the timestamp cannot be used as a high-resolution clock
 * fingerprint. */
void tc_wg_timestamp(uint8_t out[TC_WG_TIMESTAMP_LEN]);

#endif /* TC_NOISE_H_ */
