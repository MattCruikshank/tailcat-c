/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The WireGuard Noise IKpsk2 handshake. See noise.h for the wire formats.
 *
 * Mirrors device/noise-protocol.go in wireguard-go. The ordering of the
 * mixHash and mixKey calls is part of the protocol: both sides must fold the
 * same values into the transcript in the same order or the final AEAD tag
 * will not verify, and the failure gives no hint which step diverged. That is
 * why each one is written out explicitly here rather than being factored into
 * something cleverer.
 */

#include "tc/noise.h"

#include "tc/crypto.h"

#include <string.h>
#include <time.h>

/* The protocol's domain-separation strings. */
static const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char kLabelMac1[] = "mac1----";

/* Message field offsets. */
enum {
	INIT_OFF_TYPE = 0,
	INIT_OFF_SENDER = 4,
	INIT_OFF_EPHEMERAL = 8,
	INIT_OFF_STATIC = 40,      /* 32 + 16 */
	INIT_OFF_TIMESTAMP = 88,   /* 12 + 16 */
	INIT_OFF_MAC1 = 116,
	INIT_OFF_MAC2 = 132,

	RESP_OFF_TYPE = 0,
	RESP_OFF_SENDER = 4,
	RESP_OFF_RECEIVER = 8,
	RESP_OFF_EPHEMERAL = 12,
	RESP_OFF_EMPTY = 44, /* 0 + 16 */
	RESP_OFF_MAC1 = 60,
	RESP_OFF_MAC2 = 76
};

static void put_u32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32le(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static void put_u64le(uint8_t *p, uint64_t v)
{
	for (size_t i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

static uint64_t get_u64le(const uint8_t *p)
{
	uint64_t v = 0;
	for (size_t i = 0; i < 8; i++)
		v |= (uint64_t)p[i] << (8u * i);
	return v;
}

/* mix_hash: h = BLAKE2s(h || data) */
static void mix_hash(uint8_t h[32], const void *data, size_t len)
{
	tc_blake2s_ctx ctx;
	uint8_t out[32];
	tc_blake2s_init(&ctx, 32);
	tc_blake2s_update(&ctx, h, 32);
	tc_blake2s_update(&ctx, data, len);
	tc_blake2s_final(&ctx, out);
	memcpy(h, out, 32);
	tc_memzero_explicit(out, sizeof out);
}

/* mix_key: c = KDF1(c, data) */
static void mix_key(uint8_t c[32], const void *data, size_t len)
{
	uint8_t out[32];
	tc_kdf1(out, c, data, len);
	memcpy(c, out, 32);
	tc_memzero_explicit(out, sizeof out);
}

/* initial_state computes the two constants every handshake starts from:
 *   c = BLAKE2s(CONSTRUCTION)
 *   h = BLAKE2s(c || IDENTIFIER)
 * They are derived rather than hard-coded so a change to the construction
 * string cannot silently disagree with a stale constant. */
static void initial_state(uint8_t c[32], uint8_t h[32])
{
	tc_blake2s(c, 32, kConstruction, sizeof kConstruction - 1, NULL, 0);
	memcpy(h, c, 32);
	mix_hash(h, kIdentifier, sizeof kIdentifier - 1);
}

void tc_wg_mac1_key(uint8_t out[TC_WG_KEY_LEN],
                    const uint8_t public_key[TC_WG_KEY_LEN])
{
	tc_blake2s_ctx ctx;
	tc_blake2s_init(&ctx, 32);
	tc_blake2s_update(&ctx, kLabelMac1, sizeof kLabelMac1 - 1);
	tc_blake2s_update(&ctx, public_key, TC_WG_KEY_LEN);
	tc_blake2s_final(&ctx, out);
}

/* add_macs fills in the mac1 and mac2 fields at the end of a handshake
 * message. mac2 is left zero: it is only non-zero once a peer under load has
 * issued a cookie, and we do not implement the cookie exchange. A peer that
 * is not rate-limiting accepts a zero mac2. */
static void add_macs(uint8_t *msg, size_t len, const uint8_t mac1_key[32])
{
	size_t mac2_off = len - TC_WG_MAC_LEN;
	size_t mac1_off = mac2_off - TC_WG_MAC_LEN;

	tc_blake2s(msg + mac1_off, TC_WG_MAC_LEN, msg, mac1_off, mac1_key, 32);
	memset(msg + mac2_off, 0, TC_WG_MAC_LEN);
}

/* check_mac1 verifies the mac1 of an inbound handshake message.
 *
 * This is the cheap gate in front of the expensive part: it costs one BLAKE2s
 * and proves the sender knows our public key, so a peer that does not cannot
 * make us do a Diffie-Hellman. */
static bool check_mac1(const uint8_t *msg, size_t len,
                       const uint8_t mac1_key[32])
{
	size_t mac2_off = len - TC_WG_MAC_LEN;
	size_t mac1_off = mac2_off - TC_WG_MAC_LEN;
	uint8_t want[TC_WG_MAC_LEN];

	tc_blake2s(want, sizeof want, msg, mac1_off, mac1_key, 32);
	bool ok = tc_ct_equal(want, msg + mac1_off, sizeof want);
	tc_memzero_explicit(want, sizeof want);
	return ok;
}

/* Set by tc_wg_timestamp_force_offset_ms; zero in every real build. */
static uint64_t g_timestamp_offset_ms;

void tc_wg_timestamp_force_offset_ms(uint64_t ms)
{
	g_timestamp_offset_ms = ms;
}

void tc_wg_timestamp(uint8_t out[TC_WG_TIMESTAMP_LEN])
{
	/* TAI64N: 8 bytes of big-endian seconds offset by 2^62 + 10, then 4
	 * bytes of big-endian nanoseconds. */
	static const uint64_t kBase = 0x400000000000000aull;

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		memset(out, 0, TC_WG_TIMESTAMP_LEN);
		return;
	}

	uint64_t nsec = (uint64_t)ts.tv_nsec + (g_timestamp_offset_ms % 1000u) *
	                                           1000000ull;
	uint64_t secs = kBase + (uint64_t)ts.tv_sec + g_timestamp_offset_ms / 1000u +
	                nsec / 1000000000ull;
	ts.tv_nsec = (long)(nsec % 1000000000ull);
	/* WireGuard whitens the low 24 bits of the nanosecond field so the
	 * timestamp cannot serve as a high-resolution clock fingerprint. */
	uint32_t nanos = (uint32_t)ts.tv_nsec & ~(uint32_t)0x00ffffffu;

	for (size_t i = 0; i < 8; i++)
		out[i] = (uint8_t)(secs >> (56u - 8u * i));
	for (size_t i = 0; i < 4; i++)
		out[8 + i] = (uint8_t)(nanos >> (24u - 8u * i));
}

int tc_wg_identity_from_private(tc_wg_identity *id,
                                const uint8_t private_key[TC_WG_KEY_LEN])
{
	if (id == NULL || private_key == NULL)
		return TC_ERR_INVAL;

	memcpy(id->private_key, private_key, TC_WG_KEY_LEN);
	tc_x25519_clamp(id->private_key);
	return tc_x25519_base(id->public_key, id->private_key);
}

int tc_wg_identity_generate(tc_wg_identity *id)
{
	if (id == NULL)
		return TC_ERR_INVAL;
	return tc_x25519_keypair(id->private_key, id->public_key);
}

int tc_wg_handshake_init(tc_wg_handshake *hs, const tc_wg_identity *id,
                         const uint8_t remote_static[TC_WG_KEY_LEN],
                         const uint8_t psk[TC_WG_KEY_LEN])
{
	if (hs == NULL || id == NULL)
		return TC_ERR_INVAL;

	memset(hs, 0, sizeof *hs);

	if (psk != NULL)
		memcpy(hs->preshared_key, psk, TC_WG_KEY_LEN);

	if (remote_static != NULL) {
		memcpy(hs->remote_static, remote_static, TC_WG_KEY_LEN);
		hs->has_remote_static = true;

		int rc = tc_x25519(hs->precomputed_ss, id->private_key,
		                   hs->remote_static);
		if (rc != TC_OK) {
			/* A small-order peer key gives a shared secret an attacker also
			 * knows, so the peer is unusable rather than merely awkward. */
			memset(hs, 0, sizeof *hs);
			return rc;
		}
		hs->has_precomputed_ss = true;
	}
	return TC_OK;
}

int tc_wg_create_initiation(uint8_t out[TC_WG_INITIATION_SIZE],
                            tc_wg_handshake *hs, const tc_wg_identity *id,
                            uint32_t local_index)
{
	if (out == NULL || hs == NULL || id == NULL)
		return TC_ERR_INVAL;
	if (!hs->has_remote_static || !hs->has_precomputed_ss)
		return TC_ERR_INVAL;

	int rc;
	uint8_t eph_pub[32];
	uint8_t ss[32];
	uint8_t key[32];

	initial_state(hs->chain_key, hs->hash);

	/* The responder's identity is folded in first, which is what makes this
	 * IK: the initiator must already know who it is talking to. */
	mix_hash(hs->hash, hs->remote_static, TC_WG_KEY_LEN);

	rc = tc_x25519_keypair(hs->local_ephemeral, eph_pub);
	if (rc != TC_OK)
		return rc;

	if (local_index == 0) {
		rc = tc_random_bytes(&local_index, sizeof local_index);
		if (rc != TC_OK)
			return rc;
	}
	hs->local_index = local_index;

	memset(out, 0, TC_WG_INITIATION_SIZE);
	put_u32le(out + INIT_OFF_TYPE, TC_WG_MSG_INITIATION);
	put_u32le(out + INIT_OFF_SENDER, local_index);
	memcpy(out + INIT_OFF_EPHEMERAL, eph_pub, 32);

	mix_key(hs->chain_key, eph_pub, 32);
	mix_hash(hs->hash, eph_pub, 32);

	/* Encrypt our static public key under a key derived from
	 * DH(our ephemeral, their static). */
	rc = tc_x25519(ss, hs->local_ephemeral, hs->remote_static);
	if (rc != TC_OK)
		goto out;
	tc_kdf2(hs->chain_key, key, hs->chain_key, ss, 32);

	rc = tc_aead_seal(out + INIT_OFF_STATIC, key, 0, hs->hash, 32,
	                  id->public_key, 32);
	if (rc != TC_OK)
		goto out;
	mix_hash(hs->hash, out + INIT_OFF_STATIC, 32 + TC_WG_TAG_LEN);

	/* Encrypt a timestamp under a key derived from the static-static DH.
	 * The responder uses it to reject replayed initiations. */
	tc_kdf2(hs->chain_key, key, hs->chain_key, hs->precomputed_ss, 32);

	uint8_t timestamp[TC_WG_TIMESTAMP_LEN];
	tc_wg_timestamp(timestamp);
	rc = tc_aead_seal(out + INIT_OFF_TIMESTAMP, key, 0, hs->hash, 32,
	                  timestamp, sizeof timestamp);
	tc_memzero_explicit(timestamp, sizeof timestamp);
	if (rc != TC_OK)
		goto out;
	mix_hash(hs->hash, out + INIT_OFF_TIMESTAMP,
	         TC_WG_TIMESTAMP_LEN + TC_WG_TAG_LEN);

	/* mac1 is keyed by the recipient's public key. */
	uint8_t mac1_key[32];
	tc_wg_mac1_key(mac1_key, hs->remote_static);
	add_macs(out, TC_WG_INITIATION_SIZE, mac1_key);
	tc_memzero_explicit(mac1_key, sizeof mac1_key);

	hs->state = TC_WG_HS_INITIATION_CREATED;
	rc = TC_OK;

out:
	tc_memzero_explicit(ss, sizeof ss);
	tc_memzero_explicit(key, sizeof key);
	return rc;
}

int tc_wg_consume_initiation(tc_wg_handshake *hs, const tc_wg_identity *id,
                             const uint8_t msg[TC_WG_INITIATION_SIZE],
                             uint8_t out_peer_static[TC_WG_KEY_LEN],
                             uint8_t out_timestamp[TC_WG_TIMESTAMP_LEN])
{
	if (hs == NULL || id == NULL || msg == NULL)
		return TC_ERR_INVAL;
	if (get_u32le(msg + INIT_OFF_TYPE) != TC_WG_MSG_INITIATION)
		return TC_ERR_INVAL;

	/* Check mac1 before doing any asymmetric work. */
	uint8_t mac1_key[32];
	tc_wg_mac1_key(mac1_key, id->public_key);
	bool mac_ok = check_mac1(msg, TC_WG_INITIATION_SIZE, mac1_key);
	tc_memzero_explicit(mac1_key, sizeof mac1_key);
	if (!mac_ok)
		return TC_ERR_INVAL;

	int rc;
	uint8_t hash[32], chain_key[32], ss[32], key[32];
	uint8_t peer_static[32];

	initial_state(chain_key, hash);
	mix_hash(hash, id->public_key, TC_WG_KEY_LEN);

	const uint8_t *eph = msg + INIT_OFF_EPHEMERAL;
	mix_key(chain_key, eph, 32);
	mix_hash(hash, eph, 32);

	rc = tc_x25519(ss, id->private_key, eph);
	if (rc != TC_OK)
		goto out;
	tc_kdf2(chain_key, key, chain_key, ss, 32);

	rc = tc_aead_open(peer_static, key, 0, hash, 32, msg + INIT_OFF_STATIC,
	                  32 + TC_WG_TAG_LEN);
	if (rc != TC_OK)
		goto out;
	mix_hash(hash, msg + INIT_OFF_STATIC, 32 + TC_WG_TAG_LEN);

	/* If we already know who this peer should be, an initiation claiming a
	 * different identity is a different peer, not this one. */
	if (hs->has_remote_static &&
	    !tc_ct_equal(peer_static, hs->remote_static, TC_WG_KEY_LEN)) {
		rc = TC_ERR_INVAL;
		goto out;
	}

	if (!hs->has_remote_static) {
		memcpy(hs->remote_static, peer_static, TC_WG_KEY_LEN);
		hs->has_remote_static = true;
	}
	if (!hs->has_precomputed_ss) {
		rc = tc_x25519(hs->precomputed_ss, id->private_key, hs->remote_static);
		if (rc != TC_OK)
			goto out;
		hs->has_precomputed_ss = true;
	}

	/* Decrypt the timestamp under the static-static key. Getting here proves
	 * the sender holds the private key for peer_static. */
	tc_kdf2(chain_key, key, chain_key, hs->precomputed_ss, 32);

	uint8_t timestamp[TC_WG_TIMESTAMP_LEN];
	rc = tc_aead_open(timestamp, key, 0, hash, 32, msg + INIT_OFF_TIMESTAMP,
	                  TC_WG_TIMESTAMP_LEN + TC_WG_TAG_LEN);
	if (rc != TC_OK)
		goto out;
	mix_hash(hash, msg + INIT_OFF_TIMESTAMP,
	         TC_WG_TIMESTAMP_LEN + TC_WG_TAG_LEN);

	memcpy(hs->hash, hash, 32);
	memcpy(hs->chain_key, chain_key, 32);
	memcpy(hs->remote_ephemeral, eph, 32);
	hs->remote_index = get_u32le(msg + INIT_OFF_SENDER);
	hs->state = TC_WG_HS_INITIATION_CONSUMED;

	if (out_peer_static != NULL)
		memcpy(out_peer_static, peer_static, TC_WG_KEY_LEN);
	if (out_timestamp != NULL)
		memcpy(out_timestamp, timestamp, TC_WG_TIMESTAMP_LEN);

	tc_memzero_explicit(timestamp, sizeof timestamp);
	rc = TC_OK;

out:
	tc_memzero_explicit(hash, sizeof hash);
	tc_memzero_explicit(chain_key, sizeof chain_key);
	tc_memzero_explicit(ss, sizeof ss);
	tc_memzero_explicit(key, sizeof key);
	tc_memzero_explicit(peer_static, sizeof peer_static);
	return rc;
}

int tc_wg_create_response(uint8_t out[TC_WG_RESPONSE_SIZE],
                          tc_wg_handshake *hs, const tc_wg_identity *id,
                          uint32_t local_index)
{
	if (out == NULL || hs == NULL || id == NULL)
		return TC_ERR_INVAL;
	if (hs->state != TC_WG_HS_INITIATION_CONSUMED)
		return TC_ERR_INVAL;

	int rc;
	uint8_t eph_pub[32], ss[32], tau[32], key[32];

	rc = tc_x25519_keypair(hs->local_ephemeral, eph_pub);
	if (rc != TC_OK)
		return rc;

	if (local_index == 0) {
		rc = tc_random_bytes(&local_index, sizeof local_index);
		if (rc != TC_OK)
			return rc;
	}
	hs->local_index = local_index;

	memset(out, 0, TC_WG_RESPONSE_SIZE);
	put_u32le(out + RESP_OFF_TYPE, TC_WG_MSG_RESPONSE);
	put_u32le(out + RESP_OFF_SENDER, local_index);
	put_u32le(out + RESP_OFF_RECEIVER, hs->remote_index);
	memcpy(out + RESP_OFF_EPHEMERAL, eph_pub, 32);

	mix_hash(hs->hash, eph_pub, 32);
	mix_key(hs->chain_key, eph_pub, 32);

	/* Ephemeral-ephemeral, then ephemeral-static: this is the rest of the
	 * triangle that gives forward secrecy. */
	rc = tc_x25519(ss, hs->local_ephemeral, hs->remote_ephemeral);
	if (rc != TC_OK)
		goto out;
	mix_key(hs->chain_key, ss, 32);

	rc = tc_x25519(ss, hs->local_ephemeral, hs->remote_static);
	if (rc != TC_OK)
		goto out;
	mix_key(hs->chain_key, ss, 32);

	/* The psk2 step: the pre-shared key enters here, contributing to the
	 * chaining key and to the transcript hash via tau. */
	tc_kdf3(hs->chain_key, tau, key, hs->chain_key, hs->preshared_key, 32);
	mix_hash(hs->hash, tau, 32);

	rc = tc_aead_seal(out + RESP_OFF_EMPTY, key, 0, hs->hash, 32, NULL, 0);
	if (rc != TC_OK)
		goto out;
	mix_hash(hs->hash, out + RESP_OFF_EMPTY, TC_WG_TAG_LEN);

	uint8_t mac1_key[32];
	tc_wg_mac1_key(mac1_key, hs->remote_static);
	add_macs(out, TC_WG_RESPONSE_SIZE, mac1_key);
	tc_memzero_explicit(mac1_key, sizeof mac1_key);

	hs->state = TC_WG_HS_RESPONSE_CREATED;
	rc = TC_OK;

out:
	tc_memzero_explicit(ss, sizeof ss);
	tc_memzero_explicit(tau, sizeof tau);
	tc_memzero_explicit(key, sizeof key);
	return rc;
}

int tc_wg_consume_response(tc_wg_handshake *hs, const tc_wg_identity *id,
                           const uint8_t msg[TC_WG_RESPONSE_SIZE])
{
	if (hs == NULL || id == NULL || msg == NULL)
		return TC_ERR_INVAL;
	if (hs->state != TC_WG_HS_INITIATION_CREATED)
		return TC_ERR_INVAL;
	if (get_u32le(msg + RESP_OFF_TYPE) != TC_WG_MSG_RESPONSE)
		return TC_ERR_INVAL;
	if (get_u32le(msg + RESP_OFF_RECEIVER) != hs->local_index)
		return TC_ERR_INVAL;

	uint8_t mac1_key[32];
	tc_wg_mac1_key(mac1_key, id->public_key);
	bool mac_ok = check_mac1(msg, TC_WG_RESPONSE_SIZE, mac1_key);
	tc_memzero_explicit(mac1_key, sizeof mac1_key);
	if (!mac_ok)
		return TC_ERR_INVAL;

	int rc;
	uint8_t hash[32], chain_key[32], ss[32], tau[32], key[32], empty[1];

	/* Work on copies so a failed response leaves the handshake untouched and
	 * a later, valid one can still be consumed. */
	memcpy(hash, hs->hash, 32);
	memcpy(chain_key, hs->chain_key, 32);

	const uint8_t *eph = msg + RESP_OFF_EPHEMERAL;
	mix_hash(hash, eph, 32);
	mix_key(chain_key, eph, 32);

	rc = tc_x25519(ss, hs->local_ephemeral, eph);
	if (rc != TC_OK)
		goto out;
	mix_key(chain_key, ss, 32);

	rc = tc_x25519(ss, id->private_key, eph);
	if (rc != TC_OK)
		goto out;
	mix_key(chain_key, ss, 32);

	tc_kdf3(chain_key, tau, key, chain_key, hs->preshared_key, 32);
	mix_hash(hash, tau, 32);

	/* The empty AEAD is the transcript check: it verifies only if every
	 * mix above matched the responder's, including the pre-shared key. */
	rc = tc_aead_open(empty, key, 0, hash, 32, msg + RESP_OFF_EMPTY,
	                  TC_WG_TAG_LEN);
	if (rc != TC_OK)
		goto out;
	mix_hash(hash, msg + RESP_OFF_EMPTY, TC_WG_TAG_LEN);

	memcpy(hs->hash, hash, 32);
	memcpy(hs->chain_key, chain_key, 32);
	memcpy(hs->remote_ephemeral, eph, 32);
	hs->remote_index = get_u32le(msg + RESP_OFF_SENDER);
	hs->state = TC_WG_HS_RESPONSE_CONSUMED;
	rc = TC_OK;

out:
	tc_memzero_explicit(hash, sizeof hash);
	tc_memzero_explicit(chain_key, sizeof chain_key);
	tc_memzero_explicit(ss, sizeof ss);
	tc_memzero_explicit(tau, sizeof tau);
	tc_memzero_explicit(key, sizeof key);
	return rc;
}

int tc_wg_begin_session(tc_wg_session *s, tc_wg_handshake *hs)
{
	if (s == NULL || hs == NULL)
		return TC_ERR_INVAL;

	memset(s, 0, sizeof *s);

	/* The two sides derive the same pair of keys and assign them to opposite
	 * directions. Getting this backwards yields a session where each side
	 * encrypts with the key the other decrypts with, which fails at the
	 * first transport packet rather than at the handshake. */
	if (hs->state == TC_WG_HS_RESPONSE_CONSUMED) {
		tc_kdf2(s->send_key, s->recv_key, hs->chain_key, NULL, 0);
		s->is_initiator = true;
	} else if (hs->state == TC_WG_HS_RESPONSE_CREATED) {
		tc_kdf2(s->recv_key, s->send_key, hs->chain_key, NULL, 0);
		s->is_initiator = false;
	} else {
		return TC_ERR_INVAL;
	}

	s->local_index = hs->local_index;
	s->remote_index = hs->remote_index;
	s->established = true;

	/* The handshake secrets are no longer needed. */
	tc_memzero_explicit(hs->chain_key, sizeof hs->chain_key);
	tc_memzero_explicit(hs->hash, sizeof hs->hash);
	tc_memzero_explicit(hs->local_ephemeral, sizeof hs->local_ephemeral);
	hs->state = TC_WG_HS_ZEROED;

	return TC_OK;
}

void tc_wg_session_clear(tc_wg_session *s)
{
	if (s == NULL)
		return;
	tc_memzero_explicit(s, sizeof *s);
}

/* ---- transport ------------------------------------------------------- */

int tc_wg_encrypt(uint8_t *out, size_t cap, size_t *out_len, tc_wg_session *s,
                  const void *pt, size_t pt_len)
{
	if (out == NULL || s == NULL || !s->established)
		return TC_ERR_INVAL;
	if (pt == NULL && pt_len != 0)
		return TC_ERR_INVAL;
	if (pt_len > SIZE_MAX - TC_WG_TRANSPORT_HEADER_SIZE - TC_WG_TAG_LEN)
		return TC_ERR_RANGE;

	size_t need = TC_WG_TRANSPORT_HEADER_SIZE + pt_len + TC_WG_TAG_LEN;
	if (cap < need)
		return TC_ERR_NOSPACE;

	/* Reusing a counter under one key would repeat a nonce and break the
	 * AEAD outright, so refuse rather than wrap. A real implementation
	 * rekeys long before this. */
	if (s->send_counter >= TC_WG_REJECT_AFTER_MESSAGES)
		return TC_ERR_RANGE;

	uint64_t counter = s->send_counter;

	put_u32le(out + 0, TC_WG_MSG_TRANSPORT);
	put_u32le(out + 4, s->remote_index);
	put_u64le(out + 8, counter);

	/* No associated data: the header is not authenticated, exactly as in
	 * WireGuard. Tampering with the counter only makes the tag fail. */
	int rc = tc_aead_seal(out + TC_WG_TRANSPORT_HEADER_SIZE, s->send_key,
	                      counter, NULL, 0, pt, pt_len);
	if (rc != TC_OK)
		return rc;

	s->send_counter++;
	if (out_len != NULL)
		*out_len = need;
	return TC_OK;
}

/* replay_check reports whether `counter` is acceptable, without recording
 * it. The window is only advanced once the tag has verified. */
static bool replay_check(const tc_wg_session *s, uint64_t counter)
{
	if (counter >= TC_WG_REJECT_AFTER_MESSAGES)
		return false;

	/* Nothing accepted yet: only counter 0 onwards, all fine. */
	if (counter > s->recv_max)
		return true;

	uint64_t behind = s->recv_max - counter;
	if (behind >= TC_WG_REPLAY_WINDOW_BITS)
		return false; /* too old to judge, so refuse */

	uint64_t idx = counter % TC_WG_REPLAY_WINDOW_BITS;
	uint64_t word = idx / 64u;
	uint64_t bit = idx % 64u;
	return (s->recv_bitmap[word] & (1ull << bit)) == 0;
}

/* replay_record marks a counter as seen, sliding the window forward if it is
 * the highest so far. */
static void replay_record(tc_wg_session *s, uint64_t counter)
{
	if (counter > s->recv_max) {
		uint64_t jump = counter - s->recv_max;
		if (jump >= TC_WG_REPLAY_WINDOW_BITS) {
			memset(s->recv_bitmap, 0, sizeof s->recv_bitmap);
		} else {
			/* Clear the bits the window has just moved past, so they are not
			 * mistaken for recently-seen counters. */
			for (uint64_t i = s->recv_max + 1; i <= counter; i++) {
				uint64_t k = i % TC_WG_REPLAY_WINDOW_BITS;
				s->recv_bitmap[k / 64u] &= ~(1ull << (k % 64u));
			}
		}
		s->recv_max = counter;
	}

	uint64_t idx = counter % TC_WG_REPLAY_WINDOW_BITS;
	s->recv_bitmap[idx / 64u] |= 1ull << (idx % 64u);
}

int tc_wg_decrypt(uint8_t *out, size_t cap, size_t *out_len, tc_wg_session *s,
                  const uint8_t *msg, size_t msg_len)
{
	if (s == NULL || !s->established || msg == NULL)
		return TC_ERR_INVAL;
	if (msg_len < TC_WG_TRANSPORT_HEADER_SIZE + TC_WG_TAG_LEN)
		return TC_ERR_TRUNC;
	if (get_u32le(msg + 0) != TC_WG_MSG_TRANSPORT)
		return TC_ERR_INVAL;
	if (get_u32le(msg + 4) != s->local_index)
		return TC_ERR_INVAL;

	uint64_t counter = get_u64le(msg + 8);
	if (!replay_check(s, counter))
		return TC_ERR_INVAL;

	size_t ct_len = msg_len - TC_WG_TRANSPORT_HEADER_SIZE;
	size_t pt_len = ct_len - TC_WG_TAG_LEN;
	if (cap < pt_len)
		return TC_ERR_NOSPACE;

	int rc = tc_aead_open(out, s->recv_key, counter, NULL, 0,
	                      msg + TC_WG_TRANSPORT_HEADER_SIZE, ct_len);
	if (rc != TC_OK)
		return rc;

	/* Only now, with the packet proven authentic, does the window move.
	 * Recording before verification would let a forged packet with a huge
	 * counter slide the window forward and drop real traffic. */
	replay_record(s, counter);

	if (out_len != NULL)
		*out_len = pt_len;
	return TC_OK;
}
